# ocmf

[![crates.io](https://img.shields.io/crates/v/ocmf.svg)](https://crates.io/crates/ocmf)
[![docs.rs](https://img.shields.io/docsrs/ocmf)](https://docs.rs/ocmf)
[![license](https://img.shields.io/crates/l/ocmf.svg)](#licence)

**[Documentation](https://hupe1980.github.io/ocmf) · [API reference](https://docs.rs/ocmf) · [Conformance suite](conformance/)**

**The Open Charge Metering Format, read without disturbing the bytes its
signature covers.**

OCMF is the signed record a certified meter in an EV charging station emits, so
that a driver can check later that the kilowatt-hours on the invoice are the ones
the meter measured — the working answer to German calibration law (Mess- und
Eichrecht) for e-mobility. One record is one line:

```text
OCMF|{…payload JSON…}|{…signature JSON…}
```

> **Independent and unofficial.** Not affiliated with, endorsed by, or certified
> by S.A.F.E. e.V. or the Open Charge Alliance. Conformity assessment is a
> notified body's job.

## Install

```console
$ cargo add ocmf                                   # secp256r1, verify, sign, sessions
$ cargo add ocmf --features full                   # six curves in pure Rust, both transports
$ cargo add ocmf --features full,backend-openssl   # all seven curves
```

The command-line tool, with OpenSSL linked statically:

```console
$ brew install hupe1980/tap/ocmf
```

Or take a binary from any [release](https://github.com/hupe1980/ocmf/releases),
or `cargo install ocmf-cli` (needs the OpenSSL development headers).

## Quick start

```rust
use ocmf::{PublicKey, Record, verify};

let record = Record::parse(&text)?;
let key = PublicKey::from_text(&key_text, record.signature().curve())?;

let verified = verify(&record, &key)?;            // `Verified` has no public constructor
for reading in verified.payload().readings() {
    println!("{:?} {:?}", reading.time(), reading.value());  // exact decimals, never f64
}
for d in verified.deviations() {
    println!("{d}");                              // every departure from the specification
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

```console
$ ocmf explain record.ocmf                     # fields and deviations
$ ocmf verify container.xml                    # key taken from the container
$ ocmf session start.ocmf end.ocmf --json      # the check-component rules
$ ocmf sign --key @test.hex --begin 0 --end 29.5
$ ocmf to-xml start.ocmf end.ocmf --key @key.hex > transparency.xml
```

## Why this crate

- **The signed bytes are never rebuilt.** The signature covers the payload
  exactly as written, so `Record::signed_bytes()` is a slice of the input and
  `record.to_string() == text`. Sections are found by scanning the JSON, so a `|`
  inside a tariff text cannot truncate a record.
- **It reads what meters actually emit.** 229 of the 256 records in the S.A.F.E.
  reference corpus omit a mandatory field. Every record shaped `OCMF|{…}|{…}`
  parses; each departure from the specification is a typed `Deviation` naming
  the value and the table it breaks, and a `Profile` (`Strict`, `Reference`,
  `Interop`) decides what is refused.
- **All seven `[OCMF Tab. 22]` algorithms.** Six in pure Rust, brainpool
  included; secp192k1 through OpenSSL. A curve the build lacks is
  `Unsupported`, a broken key is `KeyNotOnCurve`, and only `NotVerified` means
  the record is not authentic.
- **Checked against outside oracles.** All 251 corpus records with a verdict
  agree with OpenSSL; the brainpool backends are tested against each other on
  tampered input.
- **Signs records the official tool accepts.** RFC 6979, low-`s`, `FV` derived
  from the fields used, and every record re-parsed under `Profile::Strict` and
  re-verified before it is returned. `ExternalSigner` hands a 32-byte digest to
  an HSM.
- **Both transports.** OCPP `SignedMeterValueType` (including the OCA
  `oca:base16:asn1:` public key) and the S.A.F.E. transparency XML, grouped the
  way the Transparenzsoftware demands.
- **A published conformance suite.** [163 cases](conformance/) with stated
  outcomes, for any implementation in any language.
- **Runs where the meter is, and where the driver is.** `#![no_std]` + `alloc`,
  `#![forbid(unsafe_code)]`, no I/O, no clock, no randomness; builds for
  `thumbv7em-none-eabihf` and `wasm32-unknown-unknown`. Two non-optional
  dependencies. Money is never a float.

## Features

| Feature | Gives you |
|---|---|
| `std`, `verify`, `sign`, `session`, `curve-p256` | the defaults |
| `alloc` | the crate itself; enough for `no_std` |
| `curve-p384`, `curve-k256`, `curve-bp256`, `curve-bp384` | one pure-Rust curve each, verify and sign |
| `curve-p192` | secp192r1, verify only — the one feature that compiles a pre-release crate |
| `curves-pure` | all six pure-Rust curves |
| `backend-openssl` | all seven algorithms against the system OpenSSL — the only way to check secp192k1 |
| `vendored-openssl` | the same, statically linked |
| `ocpp`, `xml` | the two transports |
| `serde` | `Serialize` on reports; quantities as exact text, never JSON numbers |
| `full` | everything except the OpenSSL backend |

MSRV 1.88. Details in the [feature guide](https://hupe1980.github.io/ocmf/docs/feature-flags/).

## Compared with the reference verifier

The S.A.F.E. Transparenzsoftware is the legally recognised verifier; its source
(`def928b`) was read to build this crate.

| | ocmf | Transparenzsoftware |
|---|---|---|
| Pipe inside `TT` | **read** | split mid-string |
| Bare `r‖s` signature, bare `X‖Y` key | **read** | refused |
| `RV` | **exact decimal** | Java `double` |
| `FV: "1.4"` | **read** | refused |
| Escaped table values (`kWh`) | **read** | unknown unit |
| Deviation reporting | **yes** | no |
| Signing, conformance suite, `no_std` | **yes** | no |

## Sources

Fetched at pinned revisions by `cargo xtask spec-sync`, never redistributed:

- [OCMF specification](https://github.com/SAFE-eV/OCMF-Open-Charge-Metering-Format)
  revision 1.4.1 at `e0a26be` (CC BY-ND 4.0)
- [S.A.F.E. Transparenzsoftware](https://github.com/SAFE-eV/transparenzsoftware)
  at `def928b` (Apache-2.0) — its test records ship in `ocmf/tests/corpus/` with
  their `NOTICE`
- [OCA, *Signed Meter Values in OCPP* v1.0](https://openchargealliance.org/), 2025-02-10

## Licence

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.
