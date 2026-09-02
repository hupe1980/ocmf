+++
title = "Feature flags and no_std"
description = "Cargo features for the ocmf crate, the embedded build, the dependency budget, and the supported Rust version."
weight = 11
+++

## Defaults

```toml
default = ["std", "verify", "sign", "session", "curve-p256"]
```

## The features

| Feature | Gives you |
|---|---|
| `alloc` | the crate itself; a `no_std` build needs this and nothing more |
| `std` | `std` integration; required by `xml` |
| `digest` | `Record::payload_digest` — its own feature, because identity is needed without verification |
| `verify` | signature checking |
| `sign` | `RecordBuilder`, the RFC 6979 signers, `ExternalSigner` |
| `session` | the check-component rules |
| `curve-p192` / `curve-p256` / `curve-p384` / `curve-k256` | one pure-Rust curve each |
| `curves-pure` | all four |
| `backend-openssl` | **all seven** algorithms, including brainpool and secp192k1, against the system OpenSSL |
| `vendored-openssl` | the same, built from source and linked statically — what the release binaries use, and not what a library consumer wants |
| `ocpp` | `SignedMeterValueType` and the `oca:` public-key composition |
| `xml` | the S.A.F.E. transparency container, read and write |
| `serde` | `Serialize` on the derived report and the session report, and `Serialize`/`Deserialize` on the OCPP container |
| `full` | everything except `backend-openssl` |

One feature per curve, because an embedded verifier that only ever sees
secp256r1 should not carry four field implementations it cannot use. The matrix
is a **correctness** matrix, not a packaging convenience: CI runs the test suite
under five combinations, because a test that only passes with every feature on is
a test that does not know what it asserts.

## Running where the meter is — and where the driver is

`#![no_std]` with `alloc`, `#![forbid(unsafe_code)]`, no I/O, no clock **and no
randomness**. Nothing here opens a socket, reads a file or asks the time — every
instant is an argument — so a fleet's worth of verification is a deterministic
unit test, and a dispute from four years ago replays exactly as it happened.

```console
$ cargo build -p ocmf --no-default-features \
    --features alloc,verify,curve-p256,sign,session,ocpp \
    --target thumbv7em-none-eabihf
$ cargo build -p ocmf --features full --target wasm32-unknown-unknown
```

Both are CI jobs, not sentences in a README. The same crate signs on the charge
controller, verifies in the CSMS and runs in the browser a driver checks a
receipt in, so the three sides cannot drift.

`alloc` is required: the resolved reading list and the deviation report need it.

### Why the browser one works

**`std` deliberately does not enable `ecdsa/std` or `sha2/std`.** Those pull
`rand_core/std` → `getrandom`, an operating-system randomness source, into a
crate that never asks for randomness: RFC 6979 signing consults none, and
verification is arithmetic over public data. On `wasm32-unknown-unknown`
`getrandom` refuses to build without a JS backend feature, so leaving it out is
the difference between "builds" and "configure this transitive dependency
first". What it costs is `std::error::Error` on two error types this crate never
surfaces.

For the same reason the `serde` feature does **not** enable
`rust_decimal/serde`: that impl writes a `Decimal` as a JSON *number*, which
goes through `f64` in most consumers, and `f64` cannot hold `9.2`. Every
quantity this crate serialises goes out as the decimal's exact text instead, and
leaving the impl unavailable is what keeps that true.

## The dependency budget

The library's non-optional dependencies are **`rust_decimal` and `thiserror`**.
Hex, Base64, DER, `SubjectPublicKeyInfo` and JSON are implemented in-crate — not
out of pride, but because each has to be lenient in a way a general-purpose crate
is right to refuse:

| In-crate | Why not the obvious crate |
|---|---|
| JSON | Every value must keep its source span, duplicate keys must be visible, unknown keys must survive. A deserialise-into-a-struct reader loses all three |
| DER | BouncyCastle accepts non-minimal lengths, trailing bytes and unpadded high-bit integers; a correct DER library is right to refuse them, and a record the legally recognised tool accepts must not be refused here |
| Hex | The reference verifier strips whitespace, and real transparency files write keys as `3059 3013 0607 …` |
| Base64 | Both alphabets, optional padding, embedded whitespace |

Cryptography is not in-crate: `sha2` and the RustCrypto curve crates do that.

## Limits

Parsing is bounded, and every bound is a named error rather than a truncation.
The defaults come from measurement — the largest payload in the reference corpus
is 932 bytes with 6 readings — so they reject nothing real while bounding the
worst case at something a charge controller can hold.

```rust
use ocmf::{Limits, Profile, Record};

let record = Record::parse_with(&text, Profile::Interop, &Limits::DEFAULT)?;

// `Limits` is `#[non_exhaustive]`, so a new bound is not a breaking change —
// adjust one with a setter rather than a struct literal.
let tight = Limits::DEFAULT.payload(4 * 1024).readings(64);
```

`Limits::UNLIMITED` removes the size bounds for a server that has already bounded
its input. It does **not** remove the nesting bound: the reader recurses, and in
a `forbid(unsafe_code)` crate a stack overflow is the one failure that cannot be
returned as a `Result`.

## Supported Rust version

**1.88.** Proved in CI against a 1.88 toolchain rather than asserted. A bump is a
minor version bump of the crate.
