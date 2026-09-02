# ocmf

[![crates.io](https://img.shields.io/crates/v/ocmf.svg)](https://crates.io/crates/ocmf)
[![docs.rs](https://img.shields.io/docsrs/ocmf)](https://docs.rs/ocmf)
[![license](https://img.shields.io/crates/l/ocmf.svg)](#licence)

**[Documentation](https://hupe1980.github.io/ocmf) · [API reference](https://docs.rs/ocmf) · [Conformance suite](conformance/)**

**The Open Charge Metering Format, read without disturbing the bytes its
signature covers.**

OCMF is the container a certified meter in an EV charging station puts a reading
into and signs, so that a driver can check months later that the kilowatt-hours
on the invoice are the kilowatt-hours the meter measured. It is the working
answer to German calibration law (Mess- und Eichrecht) for e-mobility, and by
now the de-facto European one.

One record is one line of text:

```text
OCMF|{…payload JSON…}|{…signature JSON…}
```

> **Independent and unofficial.** Not affiliated with, endorsed by, or certified
> by S.A.F.E. e.V. or the Open Charge Alliance. This crate implements a public
> format; conformity assessment is a notified body's job.

---

## The rule everything else follows from

The signature is ECDSA over SHA-256 of **the payload section exactly as it was
written**. `[OCMF §JSON based OCMF Format]` says so plainly: "between signing and
validation, the payload section must not be manipulated (removing and adding
white spaces), otherwise positive validation is not possible".

A parser that deserialises into a struct and re-serialises to verify has already
lost — key order, whitespace, number formatting and Unicode escapes are all free
to change, and every one of them changes the hash. So `Record::signed_bytes()`
returns a **slice of the input**, and there is no API anywhere in this crate that
produces signable bytes from a typed value.

```rust
use ocmf::Record;

let text = std::fs::read_to_string("record.ocmf")?;
let record = Record::parse(&text)?;

assert_eq!(record.to_string(), text);          // the identity function
let signed: &[u8] = record.signed_bytes();     // a slice of `text`, never rebuilt
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Written from the data, not only from the document

Every design decision here is anchored in a measurement. The crate ships the
**S.A.F.E. Transparenzsoftware reference corpus** — 256 real records from KEBA,
LEM, Isabellenhütte, Mennekes, eBee, eBZ, DZG, Compleo, Wirelane, ChargePoint and
VW — together with **OpenSSL's verdict on each one**, and the test suite asserts
that this crate agrees with that independent oracle on all 251 records where a
verdict exists.

What the corpus says about the specification:

| Measured | Count | What it means for an implementation |
|---|---:|---|
| Records that omit `MS`, which `[Tab. 3]` marks `1..1` | 229 / 256 | Strict cardinality rejects nine records in ten |
| Readings that omit `TM`, relying on carry-forward | 205 / 705 | Readings cannot be read independently of one another |
| Readings where `RV` is a JSON **string** | 23 | `"00000000.000"`, and one padded to `"       9.038"` |
| Records whose payload is pretty-printed | 9 | Any re-serialisation destroys them |
| Records carrying `SA` at all | 23 | The **defaults** are what verification runs on |
| OBIS codes written the way `[Tab. 25]` specifies | **0** | Not one. `1-b:1.8.0` is the real world |
| Largest payload section | 932 bytes | An OCMF record is small; bounds are cheap |
| Fiscal (`F`) pagination records | **0** | That path is untested by the official test data |

Where the corpus is thin — exactly two brainpoolP256r1 records, two secp192k1,
and not one `base64` signature — [`ocmf/tests/vectors/`](ocmf/tests/vectors/)
fills the gap with one record per algorithm, generated *and verified* with
OpenSSL before being checked in.

And two records that no other implementation can check: **Isabellenhütte** ships
a bare 64-byte `X‖Y` public key with a bare 64-byte `r‖s` signature, in a file
distributed by the reference verifier that cannot read either shape. One of them
is authentic. This crate verifies it — and *says* it did so through two
undocumented encodings, rather than quietly accepting them.

## A conformance suite, published

The specification ships no conformance suite. Every implementation therefore
decides on its own what "reads an OCMF record" means, and the disagreements only
surface years later, in a dispute, when two parties both believe they are right.

[`conformance/suite.json`](conformance/) is an attempt at the missing artefact:
**162 records with a stated expected outcome**, meant to be run by any
implementation in any language.

| Group | Cases | Pins down |
|---|---:|---|
| `table/*` | 94 | One case per value of every closed table — `[Tab. 7, 10, 11, 13–21, 25]`, plus the fiscal pagination context no corpus record exercises, and two `\uXXXX`-escaped table values |
| `deviation/*` | 54 | One per departure real meters make, and one per field a record can render unreadable: a missing `MS`, a quoted `RV`, a carried-forward `TM`, a value outside its table, an `ID` that is not the shape its `IT` states, a bare `r‖s`, non-canonical DER, high-`s`, a pipe inside `TT`, an unreadable `TM`, an `RV` no decimal can hold, an `SA` outside `[Tab. 22]` |
| `curve/*` | 7 | One per algorithm of `[Tab. 22]`, brainpool and secp192k1 included |
| `reject/*` | 7 | Byte sequences that are not records at all, and a valid record with one digit changed |

```console
$ ocmf conformance conformance/suite.json
162 case(s): 162 passed, 0 failed, 0 skipped
```

`ocmf conformance` checks all five stated expectations plus the deviation set —
a reference runner that checked three of them would be publishing a schema it
did not itself honour.

Every signed case is signed and **re-verified before it is written**, so a
generation that produces a record which does not verify fails at generation time
rather than in somebody else's CI. A case an implementation cannot answer — an
unsupported curve — should be reported as *skipped*, not failed; knowing which is
which is most of the point.

## Both transports, as their own tools read them

```console
$ ocmf to-xml start.ocmf end.ocmf --key @key.hex > transparency.xml
$ ocmf to-ocpp record.ocmf --key @key.hex
```

**The S.A.F.E. transparency container** is the file a driver feeds to the
Transparenzsoftware, and producing it is half of what §33 MessEG asks for: the
law does not require a measured value to be *correct*, it requires the affected
party to be able to **check** it.

The tool groups `<value>` elements by `transactionId` and then demands exactly
one `Transaction.Begin` and one `Transaction.End` per group — so a writer that
numbers records `1, 2, 3…` produces a file it refuses, on records it verifies
perfectly one at a time. This crate groups them as S.A.F.E.'s own 257 values are
grouped, and skips a value whose `format` is one of the 13 that are SML or
ISA_EDL rather than reporting a missing OCMF header about it.

**OCPP's `SignedMeterValueType`** puts *the same record* under
`Transaction.End`, where the transparency container gives it no context at all.
Two conventions, both right; neither may borrow the other's answer. The OCA note
also composes `publicKey` as `base64("oca:base16:asn1:…")`, which no other
implementation surveyed here reads or writes.

## Deviations are reported, never swallowed

Two failure modes are equally bad. A strict parser rejects nine real records in
ten and a lawful charging session becomes unbillable for a schema reason. A
lenient parser accepts everything and an operator never learns that their fleet
emits records the official tool will reject.

So parsing runs in a **profile**, and every departure from the specification
becomes a typed `Deviation` carrying the **offending value** and the table it is
measured against — "a value the table does not define" is half a sentence, and
*which* value is the half a manufacturer can act on:

```console
$ ocmf explain keba.xml
keba.xml[0]
  format version   1.0
  gateway          KEBA_KCP30 / 17619300 / 2.8.5
  meter            - - serial (absent) fw -
  pagination       T32
  user             assigned=false level=NONE type=NONE id= [RFID_NONE OCPP_NONE ISO15118_NONE PLMN_NONE]
  algorithm        ECDSA-secp256r1-SHA256  (defaulted; SA absent)
  payload bytes    391
  readings         2
    [0] 2019-08-13T10:03:15,000+0000 I       0.2596 kWh  1-b:1.8.0            billable  (wrote TM,TX,RV,RI,RU,EF,ST)
    [1] 2019-08-13T10:03:36,000+0000 R       0.2597 kWh  1-b:1.8.0            billable  (wrote TM,TX,RV,RI,RU,EF,ST)
    01-0B:01.08.00       Δ 0.0001 kWh
  deviations       3 (3 breach the specification, 0 advisory)
    ! `MS` is absent although it is mandatory at byte 5 [OCMF Tab. 3, S.A.F.E. issue #41]
    ! OBIS code is not in the canonical form: "1-b:1.8.0" at RD[0].RI (byte 265) [OCMF Tab. 25]
    ! OBIS code is not in the canonical form: "1-b:1.8.0" at RD[1].RI (byte 371) [OCMF Tab. 25]
```

**Not every finding is a fault**, and a report that flags everything flags
nothing. Whitespace inside the payload is *explicitly permitted* and still worth
reporting, because re-serialising such a record destroys it; carry-forward is the
rule `[Tab. 7]` states rather than a breach of it. Each deviation says which it
is — `Departure::Specification` or `Departure::Advisory` — and each profile
decides what to do about it:

| Profile | Refuses | Use it when |
|---|---|---|
| `Strict` | breaches of the specification | Checking your own output before a notified body does |
| `Reference` | what S.A.F.E. Transparenzsoftware refuses, bug for bug | Asking "will the official tool accept this?" |
| `Interop` (default) | nothing | Reading a fleet without discarding evidence |

### Structure is fatal; values are not

A record shaped `OCMF|{…}|{…}` **always parses** — whatever its fields say. An
absent `PG`, a `TM` nobody can read, an `RV` no exact decimal can hold, an `SA`
naming an algorithm outside `[Tab. 22]`: each is a `Deviation`, and the typed
view says `None` rather than inventing a value the record never claimed.

A caller who cannot parse cannot *verify* either, so refusing a record over one
bad field throws away the signature over a payload that was never in doubt.
`ParseError` therefore names the header, the delimiters, malformed JSON, a
section that is not an object, a `Limits` bound and the profile in force — and
nothing about a field.

### What nothing else reports

Every closed table in OCMF has values it does not define, and every
implementation surveyed keeps them and says nothing. These 30 findings, spread
over 26 reference-corpus records, parse clean everywhere else:

| Found in the corpus | Records | What it is |
|---|---:|---|
| `"RU":"sec"` | 2 | a unit `[Tab. 20]` does not define, so the reading is not energy and cannot be billed |
| `"CT":""`, `"CT":0`, `"CT":"DC-Test-Charger"` | 7 | a charge-point id type outside `[Tab. 18]` — one of them a JSON *number* |
| `IT`/`ID` mismatches | 13 | ISO14443 UIDs of 2, 8 and 11 bytes where `[Tab. 17]` says 4 or 7; EMAIDs of 12 characters where it says 14 or 15 |
| `"CT":"CBIDC"` with `"CI":"CI"` | 8 | `[Tab. 18]` wants a charge box id, a space, and a connector |

## All seven algorithms

`[OCMF Tab. 22]` defines seven, and **three of them appear in the reference
corpus that a pure-Rust build cannot check** — secp192k1 and brainpoolP256r1
among them. So "recognise and refuse" was not an option:

```console
$ ocmf curves
  yes  ECDSA-secp192k1-SHA256       secp192k1
  yes  ECDSA-secp256k1-SHA256       secp256k1
  yes  ECDSA-secp192r1-SHA256       secp192r1
  yes  ECDSA-secp256r1-SHA256       secp256r1
  yes  ECDSA-brainpool256r1-SHA256  brainpoolP256r1
  yes  ECDSA-secp384r1-SHA256       secp384r1
  yes  ECDSA-brainpool384r1-SHA256  brainpoolP384r1
```

The default backend is pure Rust (RustCrypto) and covers four. The other three
have no audited pure-Rust implementation on a stable release, so
`--features backend-openssl` covers all seven. An algorithm a build cannot check
is reported as `Unsupported`, **never** as "does not verify": a missing curve and
a bad signature are different facts, and only one of them is the station's fault.

## Installing

```toml
[dependencies]
ocmf = "0.1"

# All seven curves, both transports, session rules:
ocmf = { version = "0.1", features = ["full", "backend-openssl"] }
```

The command-line tool ships as a self-contained binary on every
[release](https://github.com/hupe1980/ocmf/releases) — OpenSSL linked
statically, so all seven algorithms work with nothing else installed — or from
source, which needs the OpenSSL development headers:

Every command reads a record, a file of records **one per line** (`#` comments
and blank lines skipped), a transparency XML container, or `-` for stdin.

```console
$ cargo install ocmf-cli
$ ocmf explain record.ocmf                    # fields and deviations, for a human
$ ocmf explain record.ocmf --json             # …and for a pipeline
$ ocmf explain fleet.ocmf --profile reference # will the official tool take these?
$ ocmf verify container.xml                   # signature, key taken from the container
$ ocmf verify record.ocmf --key @k.hex --json # the verdict, and which key gave it
$ ocmf session start.ocmf end.ocmf            # the check-component rules
$ ocmf session start.ocmf end.ocmf --json     # …with every quantity as exact text
$ ocmf sign --key @test.hex --begin 0 --end 29.5   # --curve secp384r1, secp256k1
$ ocmf to-xml record.ocmf --key @key.hex > transparency.xml
$ ocmf to-ocpp record.ocmf --key @key.hex     # and `from-ocpp` reads one back
$ ocmf conformance conformance/suite.json     # run the suite against this build
$ ocmf curves                                 # what this build can check
```

## Documentation

The guide lives at **<https://hupe1980.github.io/ocmf>** — the signed-bytes rule,
reading records, deviations and profiles, verifying, signing, sessions, both
transports, the CLI reference and an FAQ. The API reference is on
[docs.rs](https://docs.rs/ocmf).

## What it does

### Verify

```rust
use ocmf::{PublicKey, Record, verify};

let record = Record::parse(&text)?;

// Keys arrive in five shapes: SPKI, a SEC1 point, a compressed point, a bare
// X‖Y with no prefix at all, and the OCA `oca:base16:asn1:…` composite. All of
// them, hex or Base64, whitespace and all.
let key = PublicKey::from_text(&key_text, record.signature().curve())?;

let verified = verify(&record, &key)?;
println!("{}", verified.algorithm());
for d in verified.deviations() {
    println!("{d}");   // includes NonCanonicalDer, RawSignatureNotDer, HighSSignature
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`Verified` has no public constructor: the only way to hold one is to have run
`verify`. A `-> bool` API invites a caller to check the boolean in one function
and act on the record in another, which is how "verified" quietly becomes
"parsed".

**Exactly one error means the record is not authentic.** The others say whose
fault it is:

| Error | What actually went wrong |
|---|---|
| `Unsupported` | this build has no implementation of the curve |
| `AlgorithmKeyMismatch` | the key names a different curve than `SA` does |
| `KeyNotOnCurve` | the key is the right length and is not a point — a broken registry entry, not a broken record |
| `UnknownAlgorithm` | `SA` names something `[Tab. 22]` does not define — never checked as another algorithm |
| `SignatureEncoding` / `SignatureShape` | `SD` is absent, is not readable as hex/Base64, or is neither DER nor a raw `r‖s` |
| `SignatureScalars` | `r` or `s` is outside `[1, n)` — a signature nothing produced |
| `HighSSignature` | the low form was required by policy; both forms are the same statement, and OCMF permits either |
| **`NotVerified`** | **the signature is well-formed and does not match** |

### Read

```rust
let p = record.payload();

// Carry-forward is already resolved — 29 % of real readings depend on it —
// and readings are grouped per register, because LEM meters interleave an
// import and an export register in one record.
for series in p.by_register() {
    println!("{}: {:?}", series.obis, series.delta());
}

// `2935.600` states three valid decimal places, and keeps them.
let rv = p.readings()[0].value().unwrap();
assert_eq!(rv.as_str(), "2935.600");
assert_eq!(rv.value().scale(), 3);
```

### Sign

```rust
use ocmf::sign::{RecordBuilder, ReadingSpec, Secp256r1Signer};
use ocmf::{IdentificationLevel, IdentificationType, Pagination, Unit};

let signer = Secp256r1Signer::from_bytes(&secret)?;   // RFC 6979, no RNG needed
let record = RecordBuilder::new()
    .gateway("ACME CS-1", "SN-4711", "1.0.0")
    .pagination(Pagination::transaction(1))
    .meter_serial("1ABC0000000001")
    // `[Tab. 4]`: a transaction record states whether a user was assigned,
    // even when the answer is "nobody". The builder will not sign without it.
    .identification(true, IdentificationLevel::Verified, vec![], IdentificationType::Iso14443,
                    "1F2D3A4F5506C7")
    .reading(ReadingSpec::new(begin_time, begin_value, "01-00:B1.08.00*FF", Unit::KWh).begin())
    .reading(ReadingSpec::new(end_time, end_value, "01-00:B1.08.00*FF", Unit::KWh).end())
    .sign(&signer)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Deterministic (RFC 6979 — a reused nonce leaks the private key, and a charge
controller's entropy is not something to bet a fleet's evidence on), and **a
record this crate writes passes `Profile::Strict`**: the builder refuses every
input that would become a breach on the reading side, then re-parses the emitted
text under that profile and re-verifies it against the signer's own public key
before returning it. The cost is the point — it will not write the OBIS spelling
that 705 of 705 corpus readings use.

`FV` is **derived from the fields the record actually uses** — `LC` ⇒ 1.2, `CF` ⇒
1.3, `TT` ⇒ 1.1, otherwise 1.0. Stamping the newest revision on every record is
the obvious default and the wrong one: the legally recognised verifier dispatches
on `version <= 1.3` and answers "not compatible" above it, so `FV: "1.4"` on a
record that uses nothing newer than 1.0 makes a station's own evidence unreadable
by the tool a driver runs, for no benefit at all. `ExternalSigner` hands the
prehashed 32 bytes to a secure element or HSM, which is what a certified
measuring capsule actually contains.

### Report on a record

```rust
// A record's only faithful serialisation is its own text, so there is no
// `Serialize` on `Record` and no `Deserialize` anywhere in this crate. What a
// pipeline actually wants is a report — and every quantity in it is the exact
// decimal *as text*, because JSON numbers go through `f64` in most consumers.
let summary = record.summary();
assert_eq!(summary.record, text);                       // the record, verbatim
assert_eq!(summary.readings[0].value.as_deref(), Some("2935.600"));
println!("{}", serde_json::to_string_pretty(&summary)?); // feature = "serde"
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Check a session

```rust
let report = ocmf::session::validate(&records);
for f in report.findings() {
    println!("{f}");   // "pagination went 1 → 3 at record 1: a record was removed…"
}

// `report.clock()` is the *weakest* clock in the sequence, not the best: one
// synchronised reading says nothing about the twenty around it.
assert!(report.clock().is_some_and(|c| c.duration_is_billable()));
```

Every rule `[OCMF §Signing and Verification Process]` assigns to a check
component — continuous pagination, one begin and one end in their places, one
source, error states and unusable quantities fatal — plus the four the reference
verifier adds in `checkLawIntegrityForTransaction`.

`session::validate_verified(&[Verified])` runs the same rules and says so at the
call site: a clean report over records nobody checked the signatures of answers
"do these hang together", never "is this session real".

### Both transports

```rust
// OCPP 1.6 / 2.0.1 / 2.1, per [OCA Signed Meter Values v1.0, 2025-02-10]
let smv = ocmf::ocpp::SignedMeterValue::from_record(&record, Some(&key));
assert_eq!(smv.encoding_method, "OCMF");
// `publicKey` is Base64 of `oca:base16:asn1:<hex SPKI>` — the composition no
// other open-source implementation appears to read or write.

// The S.A.F.E. transparency container a driver feeds to the official tool
let xml = ocmf::xml::Values::from_records([(&record, Some(&key))]).to_xml()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What it deliberately does not do

| Question | Answered by |
|---|---|
| Did this key sign these bytes? | **this crate** |
| Is this key *this charge point's* key? | out of band — a register, the station's display, a contract |
| Were records removed from the session? | **this crate** (`session`) |
| May these values be billed? | not here: that is law, tariffs and a key registry |

Conflating the four is how a "verified" charging session turns out to be a signed
fragment of a session somebody edited.

## Design notes worth knowing

- **Sections are found by scanning the JSON value, not by `split('|')`.** `TT` is
  250 characters of free text and may contain a pipe; every implementation
  surveyed truncates such a record mid-string and loses the evidence. Where no
  pipe hides in a string, this parser is byte-identical to the naive split.
- **A record's identity is its payload digest, not its text.** ECDSA signatures
  are malleable and DER admits non-canonical encodings, so one payload appears
  under many `SD` values that all verify. Deduplicating on the text stores the
  same reading twice — in a billing pipeline, a double charge.
- **The DER reader is lenient, and says so.** BouncyCastle accepts non-minimal
  lengths, trailing bytes and `INTEGER`s whose top bit is set without a `0x00`
  pad. Real eBZ meters emit the last of those and OpenSSL refuses to parse it;
  this crate reads it and reports `NonCanonicalDer`.
- **`s` is normalised before verification.** `(r, s)` and `(r, n − s)` are the
  same statement; k256 verifies only the low form, and two authentic secp256k1
  records in the corpus are high-`s`.
- **`EF` carries forward.** A record whose first reading is flagged `E` and whose
  second omits the field is a record whose second reading is *still flagged*.
  Reading the omission as "no error" clears a fault the station signed.
- **The specification names no JSON profile** — its normative reference is a web
  page, not RFC 8259 — so duplicate keys, encoding and escapes are undefined.
  Duplicate keys are reported rather than silently resolved.
- **Table values are matched on the decoded string, reproduced from the original
  bytes.** `"\u006bWh"` is a lawful spelling of `"kWh"`; comparing raw text reads
  it as an unknown unit, and an unknown unit is not energy.
- **Ambiguity resolves away from billing, everywhere.** An unknown meter state is
  not `OK`, an unknown unit is not energy, an omitted `EF` is still flagged, and
  a session is judged by its *weakest* clock.

## Runs where the meter is, and where the driver is

`#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`, no I/O, no clock and **no
randomness**. Nothing here opens a socket, reads a file or asks the time — every
instant is an argument — so a fleet's worth of verification is a deterministic
unit test, and a dispute from four years ago replays exactly as it happened.

```console
$ cargo build -p ocmf --no-default-features \
    --features alloc,verify,curve-p256,sign,session,ocpp \
    --target thumbv7em-none-eabihf
$ cargo build -p ocmf --features full --target wasm32-unknown-unknown
```

Both are CI jobs. The browser one works because nothing here asks for
randomness: `std` deliberately leaves `ecdsa/std` off, which would otherwise
drag `getrandom` in and demand a JS backend feature of whoever embeds it.

The library's non-optional dependency surface is **two crates**: `rust_decimal`
and `thiserror`. Hex, Base64, DER, SPKI and JSON are implemented in-crate,
because each has to be lenient in ways a general-purpose crate is right to
refuse.

### Features

| Feature | Gives you |
|---|---|
| `std` *(default)* | `std` integration; required by `xml` |
| `alloc` | the crate itself; `no_std` builds need this |
| `verify` *(default)* | signature checking |
| `sign` *(default)* | `RecordBuilder`, RFC 6979 signers, `ExternalSigner` |
| `session` *(default)* | the check-component rules |
| `curve-p256` *(default)* / `curve-p192` / `curve-p384` / `curve-k256` | one pure-Rust curve each |
| `curves-pure` | all four pure-Rust curves |
| `backend-openssl` | **all seven** `[Tab. 22]` algorithms, against the system OpenSSL |
| `vendored-openssl` | the same, linked statically — what the release binaries are built with |
| `ocpp` | `SignedMeterValueType`, the `oca:` public-key composition |
| `xml` | the S.A.F.E. transparency container, read and write |
| `serde` | `Serialize` on the derived views and the session report, `Serialize`/`Deserialize` on the OCPP container — never on a record, and never a `Decimal` as a JSON number |
| `full` | everything except `backend-openssl` |

## Performance

Measured, not asserted — `cargo bench -p ocmf`, Apple M-series, release profile,
on the 550-byte KEBA record from the corpus:

| | median | note |
|---|---:|---|
| `Record::parse` | **3.8 µs** | sections found, JSON scanned, every field typed, carry-forward resolved, deviations collected and sorted |
| round trip (parse + print) | 3.4 µs | printing is a `&str` copy, and that is the point |
| `payload_digest` | 0.87 µs | SHA-256 over the signed span |
| `PublicKey::from_text` | 0.31 µs | hex → DER → SPKI → point |
| `ObisCode::parse` | 74 ns | once per reading |
| `verify` (secp256r1, pure Rust) | 148 µs | **40× the parse**: the cost is the curve library's, not this crate's |
| `summary()` | 2.2 µs | the serialisable report |

Run to run these move by up to a quarter on a laptop that is doing anything
else, so the ratio is the measurement and the digits are not. A CSMS ingesting a
million records a day spends a few seconds of CPU on reading them and two and a
half minutes on the cryptography. Optimising the
parser further would be optimising the wrong end — which is why the benchmarks
exist: to show *where* the time goes, not to chase a number.

CI runs the benchmarks once per commit as a compile gate. A benchmark that stops
building is a budget nobody is measuring.

## Quality bars, enforced

```console
cargo test --workspace --features full,backend-openssl   # 260 tests
cargo clippy --workspace --all-targets -- -D warnings    # pedantic, clean
cargo deny check             # licences, advisories, and one curve tree only
cargo xtask no-floats        # no f32/f64 in the library: a reading is money
cargo xtask spec-coverage    # every table value in the spec exists in the code
cargo xtask corpus-report    # reproduces the field measurements above
cargo xtask conformance-gen  # regenerates the published suite; CI diffs it
cargo xtask spec-sync        # re-fetches the pinned sources, fails on drift
cargo bench  -p ocmf         # the performance budget
cargo mutants -p ocmf        # where a surviving mutant is a wrong answer about money
```

`spec-coverage` is the unusual one: it reads the vendored specification, harvests
every value from its closed tables, and fails the build if one has no
representation in the source. The specification is the oracle for completeness,
mechanically.

## Comparison

Compared with the **S.A.F.E. Transparenzsoftware**, the legally recognised
reference verifier, whose source was read to build this crate (`def928b`):

| | this crate | Transparenzsoftware |
|---|---|---|
| Byte-exact round trip, tested | **yes** | not applicable (verify-only) |
| Reads a pipe inside `TT` | **yes** | no — splits on every `\|` |
| Bare `r‖s` signature | **yes** | no — `ASN1InputStream` only |
| Bare `X‖Y` public key | **yes** | no — `SubjectPublicKeyInfo` only |
| Unpadded high-bit DER `INTEGER` | **yes** | yes — `getPositiveValue()` |
| Exact decimals for `RV` | **yes** | no — Java `double` |
| Records with `FV: "1.4"` | **yes** | no — the version dispatch stops at 1.3 |
| Escaped table values (`\u006bWh`) | **yes** | no — raw string compare |
| A `String` field written as a JSON number | **yes** — read and reported | no |
| Values outside a closed table | **yes** — reported by name | no |
| `ID`/`CI` checked against the format their type states | **yes** | no |
| Deviation reporting | **yes** | no |
| Signing | **yes** | no |
| A published conformance suite | **yes** | no |
| OCA `oca:` public keys | **yes** | no |
| `no_std` | **yes** | not applicable |

The other implementations in the field — [Chargy](https://github.com/OpenChargingCloud/ChargyDesktopApp)
(TypeScript), [`ocmf-js`](https://github.com/road-labs/ocmf-js) (TypeScript,
signs as well as verifies) and
[`OpenChargeMeteringFormat`](https://github.com/Namoshek/OpenChargeMeteringFormat)
(.NET) — were surveyed but not benchmarked cell by cell, so no claims are made
about them here beyond the observation in the OCA note's own terms: none of them
appears to read or write the `oca:` public-key composition.

## Sources of truth

The specification and the reference implementation are fetched, not vendored:
`cargo xtask spec-sync` clones them into a gitignored `specs/` and fails when a
pin has moved. The OCMF specification is CC BY-ND 4.0 — implementable and
quotable, never redistributable in modified form.

- [OCMF specification](https://github.com/SAFE-eV/OCMF-Open-Charge-Metering-Format),
  revision 1.4.1, pinned at `34c4add`
- [S.A.F.E. Transparenzsoftware](https://github.com/SAFE-eV/transparenzsoftware)
  (Apache-2.0), pinned at `def928b` — the reference verifier and the test corpus
- [OCA, *Signed Meter Values in OCPP* v1.0](https://openchargealliance.org/), 2025-02-10

The test corpus in `ocmf/tests/corpus/` is redistributed under Apache-2.0 with
attribution; see its `NOTICE`.

## Licence

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.
