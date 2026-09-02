+++
title = "Signing"
description = "Build and sign OCMF records in Rust: RFC 6979 deterministic ECDSA, an HSM seam, derived format versions, and a builder that refuses to emit what it cannot read back."
weight = 6
+++

## Text first, always

The builder produces the payload *text*, hashes those exact bytes, and signs the
hash. There is no path from a typed value to a signature that does not go
through the bytes that will be transmitted.

```rust
use ocmf::sign::{ReadingSpec, RecordBuilder, Secp256r1Signer};
use ocmf::{IdentificationLevel, IdentificationType, Pagination, Unit};

let signer = Secp256r1Signer::from_bytes(&secret)?;

let record = RecordBuilder::new()
    .gateway("ACME CS-1", "SN-4711", "1.0.0")
    .pagination(Pagination::transaction(1))
    .meter("ACME", "M-100", "1ABC0000000001", "2.3")
    .identification(
        true,
        IdentificationLevel::Verified,
        vec![],
        IdentificationType::Iso14443,
        "1F2D3A4F5506C7",
    )
    .reading(ReadingSpec::new(begin_time, begin_value, "01-00:B1.08.00*FF", Unit::KWh).begin())
    .reading(ReadingSpec::new(end_time, end_value, "01-00:B1.08.00*FF", Unit::KWh).end())
    .sign(&signer)?;
```

`RecordBuilder::payload_text()` gives you the exact bytes before they are
committed to, which is worth looking at at least once.

## Deterministic by default

ECDSA leaks the private key if a nonce is ever reused across two signatures. On
a charge controller with a weak entropy source that is not a theoretical risk,
and the consequence is not one bad record but a fleet's worth of evidence voided
at once.

The default signers are **RFC 6979 deterministic**: they consult no randomness
at all. And every record this crate signs carries the **low-`s`** form, which
every verifier accepts — the normalisation happens in `sign()`, over the curve's
own order, so it covers `ExternalSigner` too. An HSM is precisely the signer
whose output this crate does not control.

`Secp256r1Signer`, `Secp384r1Signer` and `Secp256k1Signer` are available behind
their curve features. There is deliberately **no secp192r1 signer**: the
underlying crate publishes only the verifying half of ECDSA on that curve, and a
192-bit curve is not something new hardware should be signing with. It is here
so that records from deployed meters can be *checked*.

## Secure elements and HSMs

A certified measuring capsule keeps its private key inside a secure element.
`ExternalSigner` hands that device the prehashed 32 bytes and nothing else:

```rust
use ocmf::sign::ExternalSigner;

let signer = ExternalSigner::new(public_key, |digest: &[u8; 32]| {
    hsm.sign_ecdsa(digest)          // returns (r, s), big-endian
});
let record = builder.sign(&signer)?;
```

## What the builder refuses

**A record this crate writes passes `Profile::Strict`** — and that is checked on
the emitted bytes, not merely intended. Validation runs before anything is
signed, and refuses every input that would become a `Departure::Specification`
deviation on the reading side:

- `|` in any field — the specification forbids it in a section;
- a missing `PG`, a `PG` in a context letter the table does not define, an empty
  `RD`, or a missing `MS`;
- more than one begin or end marker;
- a transaction record with no `IS`, `IF` or `IT`, which the specification marks
  `1..1` wherever there is a transaction reference;
- an `ID` that does not match the format its `IT` states, or a `CI` that does not
  match its `CT`;
- an `ST`, `TX`, `RU`, `RT`, `IL`, `IT`, `CT` or `IF` flag outside its table, or
  an `EF` character other than `E` and `t`;
- an `RI` that is not in the `[Tab. 25]` form — the builder writes the one
  spelling the specification gives, even though no record in the reference
  corpus uses it;
- a `TM` whose fields are not a real date, or that carries no synchronisation
  letter;
- an `RV` with no `RU`;
- `TT` over 250 characters, `CF` over 25, `LN` over 20;
- an `LU` outside `mOhm` and `uOhm`;
- suppressing `SA` while signing on a curve that is not the default — an absent
  `SA` *means* secp256r1, so a record signed on another curve without it
  misstates itself.

Then the record is **re-parsed under `Profile::Strict`** and verified against the
signer's own public key before it is returned. The list above is the promise; the
self-check is the proof.

Reading the field and writing the specification are different jobs, and this
crate does not blur them: `Record::parse` reads `"RI":"1-b:1.8.0"` — the spelling
705 of 705 corpus readings use — and `RecordBuilder` refuses to write it.

## The format version is derived

`FV` comes from the fields the record actually uses:

| Field used | `FV` |
|---|---|
| `CF` charge-controller firmware | 1.3 |
| `LC` cable-loss compensation | 1.2 |
| `TT` tariff text | 1.1 |
| anything else | 1.0 |

Stamping the newest revision on every record is the obvious default and the
wrong one: the legally recognised verifier dispatches on `version <= 1.3` and
answers "not compatible" above it. `FV: "1.4"` on a record using nothing newer
than 1.0 makes a station's own evidence unreadable by the tool a driver runs,
for no benefit at all.

`RecordBuilder::format_version()` overrides the derived value; a record that
claims more than the reference reads is reported as
`FormatVersionAheadOfReference`.

## Cable-loss compensation

```rust
use ocmf::sign::LossCompensationSpec;

let builder = builder.loss_compensation(
    LossCompensationSpec::new(resistance, Unit::MilliOhm).name("cable_A").id(id),
);
```

`LR` and `LU` are mandatory inside the block; `LN` and `LI` are the traceability
fields that let an auditor find the characteristics used.
