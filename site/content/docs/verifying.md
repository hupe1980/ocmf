+++
title = "Verifying"
description = "Check an OCMF signature: reading public keys in six shapes, all seven ECDSA algorithms, the pure-Rust and OpenSSL backends, and what each error actually means."
weight = 5
+++

## What a verification proves

That the holder of one private key produced *these bytes*. Nothing else:

| Question | Answered by |
|---|---|
| Did this key sign these bytes? | `ocmf::verify` |
| Is this key *this charge point's* key? | out of band — a register, the station's display, a contract |
| Were records removed from the session? | [`ocmf::session`](@/docs/sessions.md) |
| May these values be billed? | law, tariffs and a key registry — not this crate |

## Reading a public key

OCMF does not carry the key; it arrives out of band in whatever shape the source
uses. `PublicKey` reads six:

| Shape | Where it comes from |
|---|---|
| DER `SubjectPublicKeyInfo` | 247 of the 254 corpus keys; the curve is in the structure |
| The same, Base64 | three more |
| SEC1 uncompressed point `04‖X‖Y` | OCPP deployments, meter labels |
| SEC1 compressed point | rarer, but lawful |
| Bare `X‖Y`, no prefix, no wrapper | Isabellenhütte records in the reference corpus |
| `base64("oca:base16:asn1:…")` | the OCA *Signed Meter Values in OCPP* application note |

```rust
use ocmf::PublicKey;

// Hex or Base64, with whitespace anywhere: real transparency files write
// `3059 3013 0607 2A86 …`.
let key = PublicKey::from_text(&text, record.signature().curve())?;
```

The `hint` is needed only for a bare point, which carries no curve of its own. A
`SubjectPublicKeyInfo` always wins over the hint, and a disagreement between the
two is an error rather than a silent preference.

## Verifying

```rust
use ocmf::{verify, verify_key_text, VerifyOptions, Malleability};

let verified = verify(&record, &key)?;

// Or, when the key material is text in whatever shape it arrived:
let verified = verify_key_text(&record, &key_text)?;

// High-`s` signatures are accepted by default, because the reference verifier
// accepts them. Refuse them if your pipeline would rather not see the twin.
let verified = ocmf::verify_with(
    &record,
    &key,
    VerifyOptions::new().malleability(Malleability::RejectHighS),
)?;
```

## The errors mean different things

Only `NotVerified` means the record is not authentic. The other `VerifyError`
variants say what else went wrong:

| Error | What actually went wrong |
|---|---|
| `Unsupported` | this build has no implementation of the curve |
| `AlgorithmKeyMismatch` | the key names a different curve than `SA` does |
| `KeyNotOnCurve` | the key is the right length and is not a point — a broken registry entry, not a broken record |
| `UnknownAlgorithm` | `SA` names an algorithm the table does not define — the record is never checked as a different one |
| `SignatureEncoding` | `SD` is absent, or is not readable as the encoding `SE` names |
| `SignatureShape` | the bytes are neither DER nor a raw `r‖s` of the right size |
| `SignatureScalars` | `r` or `s` is outside `[1, n)` — a signature nothing produced |
| `HighSSignature` | `Malleability::RejectHighS` is set and `s` is in the high half |
| `Key` | the key text could not be read (a `KeyError`) |
| **`NotVerified`** | **the signature is well-formed and does not match** |

## All seven algorithms

The specification defines seven, all ECDSA over SHA-256 — including on the
384-bit curves.

| `SA` identifier | Curve | Pure Rust | OpenSSL |
|---|---|:--:|:--:|
| `ECDSA-secp192k1-SHA256` | secp192k1 | — | ✓ |
| `ECDSA-secp192r1-SHA256` | secp192r1 (NIST P-192) | ✓ | ✓ |
| `ECDSA-secp256k1-SHA256` | secp256k1 | ✓ | ✓ |
| `ECDSA-secp256r1-SHA256` *(default)* | secp256r1 (P-256) | ✓ | ✓ |
| `ECDSA-brainpool256r1-SHA256` | brainpoolP256r1 | ✓ | ✓ |
| `ECDSA-secp384r1-SHA256` | secp384r1 (P-384) | ✓ | ✓ |
| `ECDSA-brainpool384r1-SHA256` | brainpoolP384r1 | ✓ | ✓ |

Six curves verify in pure Rust, so WebAssembly and embedded builds check them
too; each needs its `curve-*` feature (see
[Feature flags](@/docs/feature-flags.md)). secp192k1 has no pure-Rust
implementation: build with `--features backend-openssl` for all seven. Both
backends are tested to agree on every brainpool input, tampered ones included.
An algorithm a build cannot check is reported as `Unsupported`, never as "does
not verify".

```rust
ocmf::is_supported(ocmf::Curve::Secp192k1);  // a const fn over the features
ocmf::supported_curves();
```

```console
$ ocmf curves
  yes  ECDSA-secp192k1-SHA256       secp192k1
  yes  ECDSA-secp256k1-SHA256       secp256k1
  …
```

## Signature encodings in the wild

`SM` announces a MIME type and defaults to `application/x-der`, but not every
record's signature is DER. `SD` is read in this order:

- **DER** — `SEQUENCE { INTEGER r, INTEGER s }`, read as leniently as the
  S.A.F.E. reference verifier (BouncyCastle) reads it: non-minimal lengths,
  trailing bytes and unpadded high-bit `INTEGER`s, which eBZ meters emit and
  OpenSSL refuses. Reported as `NonCanonicalDer`.
- **Raw `r‖s`** on an exact length match, reported as `RawSignatureNotDer`.
- **Otherwise** an error naming the length.

`s` is normalised to the low form before the backend sees it, because some
pure-Rust curves verify only that form while the reference verifier accepts
either, and authentic high-`s` records exist. The `HighSSignature` deviation is
still reported.
