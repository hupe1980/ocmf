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
| `curve-p256` *(default)* | secp256r1, verify and sign |
| `curve-p384` / `curve-k256` / `curve-bp256` / `curve-bp384` | secp384r1 / secp256k1 / brainpoolP256r1 / brainpoolP384r1, verify and sign |
| `curve-p192` | secp192r1, verify only. The one feature that pulls a pre-release crate (`p192`), so nothing else enables it |
| `curves-pure` | all six pure-Rust curves above |
| `backend-openssl` | **all seven** algorithms against the system OpenSSL — the only way to check secp192k1. The pure-Rust backend is still tried first |
| `vendored-openssl` | the same, built from source and linked statically. For distributable binaries; needs a C compiler and perl and takes minutes to build |
| `ocpp` | `SignedMeterValueType` and the `oca:` public-key composition |
| `xml` | the S.A.F.E. transparency container, read and write |
| `serde` | `Serialize` on the derived report and the session report, and `Serialize`/`Deserialize` on the OCPP container |
| `full` | everything except the OpenSSL backends |

Curves are separate features so an embedded verifier that only sees secp256r1
carries one field implementation. CI runs the test suite under five feature
combinations.

```console
$ cargo add ocmf --features curve-bp256,curve-bp384   # add brainpool to the defaults
$ cargo add ocmf --features curves-pure               # all six pure-Rust curves
```

## Embedded and WebAssembly

`#![no_std]` with `alloc`, `#![forbid(unsafe_code)]`, no I/O, no clock **and no
randomness**. Every instant is an argument, so verification is deterministic and
an old dispute replays exactly.

```console
$ cargo build -p ocmf --no-default-features \
    --features alloc,verify,curve-p256,sign,session,ocpp \
    --target thumbv7em-none-eabihf
$ cargo build -p ocmf --features full --target wasm32-unknown-unknown
```

Both builds run in CI. `alloc` is required: the resolved reading list and the
deviation report need it.

`std` does **not** enable `ecdsa/std` or `sha2/std`, which would pull in
`getrandom`. The crate never needs randomness (RFC 6979 signing is
deterministic), and leaving it out is what lets `wasm32-unknown-unknown` build
without configuring a `getrandom` backend.

The `serde` feature does **not** enable `rust_decimal/serde`, which writes a
`Decimal` as a JSON number (and so through `f64` in most consumers). Every
quantity this crate serialises is the decimal's exact text.

## The dependency budget

The library's non-optional dependencies are **`rust_decimal` and `thiserror`**.
Hex, Base64, DER, `SubjectPublicKeyInfo` and JSON are implemented in-crate,
because each has to be lenient in a way a general-purpose crate rightly refuses:

| In-crate | Why not the obvious crate |
|---|---|
| JSON | Every value must keep its source span, duplicate keys must be visible, unknown keys must survive. A deserialise-into-a-struct reader loses all three |
| DER | BouncyCastle accepts non-minimal lengths, trailing bytes and unpadded high-bit integers; a correct DER library is right to refuse them, and a record the legally recognised tool accepts must not be refused here |
| Hex | The reference verifier strips whitespace, and real transparency files write keys as `3059 3013 0607 …` |
| Base64 | Both alphabets, optional padding, embedded whitespace |

Cryptography is not in-crate: `sha2` and the RustCrypto curve crates do that.

## Limits

Parsing is bounded, and every bound is a named error rather than a truncation.
The defaults are sized well above the largest payload in the reference corpus
(932 bytes, 6 readings) and small enough for a charge controller: 128 KiB per
record, 64 KiB per payload, 4096 readings, nesting depth 8, 256 members per
object, 4096 `<value>` elements in a transparency container.

```rust
use ocmf::{Limits, Profile, Record};

let record = Record::parse_with(&text, Profile::Interop, &Limits::DEFAULT)?;

// `Limits` is `#[non_exhaustive]`, so a new bound is not a breaking change —
// adjust one with a setter rather than a struct literal.
let tight = Limits::DEFAULT.payload(4 * 1024).readings(64);
```

`Limits::UNLIMITED` removes the size bounds for a server that has already bounded
its input. Nesting stays capped at `Limits::HARD_DEPTH` (512), because the reader recurses and a stack
overflow cannot be returned as a `Result`.

## Supported Rust version

**1.88**, checked in CI. Raising it is a minor version bump of the crate.
