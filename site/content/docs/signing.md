+++
title = "Signing"
description = "Build and sign OCMF records in Rust: RFC 6979 deterministic ECDSA, an HSM seam, derived format versions, and a builder that refuses to emit what it cannot read back."
weight = 6
+++

## Build and sign

`RecordBuilder` writes the payload *text*, hashes those exact bytes, and signs
the hash — there is no path from a typed value to a signature that skips the
bytes that will be transmitted.

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

`RecordBuilder::payload_text()` returns the exact payload bytes before signing.

## Signers

| Signer | Feature |
|---|---|
| `Secp256r1Signer` | `curve-p256` (default) |
| `Secp384r1Signer` | `curve-p384` |
| `Secp256k1Signer` | `curve-k256` |
| `BrainpoolP256r1Signer` | `curve-bp256` |
| `BrainpoolP384r1Signer` | `curve-bp384` |

All are pure Rust and **RFC 6979 deterministic**: they use no randomness, so a
weak entropy source on a charge controller cannot cause the nonce reuse that
leaks an ECDSA key. There is **no secp192r1 or secp192k1 signer**; 192-bit
curves are supported for verifying records from deployed meters only.

Every signature this crate emits is in **low-`s`** form, which every verifier
accepts. The normalisation happens in `sign()`, so it applies to
`ExternalSigner` too.

## Secure elements and HSMs

`ExternalSigner` hands a secure element or HSM the 32-byte SHA-256 digest and
nothing else:

```rust
use ocmf::sign::ExternalSigner;

let signer = ExternalSigner::new(public_key, |digest: &[u8; 32]| {
    hsm.sign_ecdsa(digest)          // returns (r, s), big-endian
});
let record = builder.sign(&signer)?;
```

## What the builder refuses

**A record this crate writes passes `Profile::Strict`.** Validation runs before
anything is signed and refuses, with a `BuildError`, every input that would be a
`Departure::Specification` deviation when read:

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
- an `RI` that is not in the `[Tab. 25]` form (`01-00:B1.08.00*FF`);
- a `TM` whose fields are not a real date, or that carries no synchronisation
  letter;
- an `RV` with no `RU`;
- `TT` over 250 characters, `CF` over 25, `LN` over 20;
- an `LU` outside `mOhm` and `uOhm`;
- suppressing `SA` while signing on a curve that is not the default — an absent
  `SA` *means* secp256r1, so a record signed on another curve without it
  misstates itself.

Then the record is **re-parsed under `Profile::Strict`** and verified against the
signer's own public key before it is returned; a failure is
`BuildError::SelfCheck`.

Reading and writing differ on purpose: `Record::parse` accepts field spellings
such as `"RI":"1-b:1.8.0"`, which no reference-corpus reading writes in the
`[Tab. 25]` form, while `RecordBuilder` writes only the specified form.

## The format version is derived

`FV` comes from the fields the record actually uses:

| Field used | `FV` |
|---|---|
| `CF` charge-controller firmware | 1.3 |
| `LC` cable-loss compensation | 1.2 |
| `TT` tariff text | 1.1 |
| anything else | 1.0 |

The lowest sufficient version is used because the S.A.F.E. Transparenzsoftware
refuses any `FV` above 1.3. `RecordBuilder::required_format_version()` shows the
derived value and `RecordBuilder::format_version()` overrides it; a record above
1.3 is reported as `FormatVersionAheadOfReference`.

## Cable-loss compensation

```rust
use ocmf::sign::LossCompensationSpec;

let builder = builder.loss_compensation(
    LossCompensationSpec::new(resistance, Unit::MilliOhm).name("cable_A").id(id),
);
```

`LR` and `LU` are mandatory; `LN` (at most 20 characters) and `LI` are optional
traceability fields identifying the cable characteristics used.
