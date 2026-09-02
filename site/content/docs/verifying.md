+++
title = "Verifying"
description = "Check an OCMF signature: reading public keys in five shapes, all seven ECDSA algorithms, the pure-Rust and OpenSSL backends, and what each error actually means."
weight = 5
+++

## What a verification proves

That the holder of one private key produced *these bytes*. Nothing else. Three
things it does **not** prove, each answered elsewhere:

| Question | Answered by |
|---|---|
| Did this key sign these bytes? | `ocmf::verify` |
| Is this key *this charge point's* key? | out of band — a register, the station's display, a contract |
| Were records removed from the session? | [`ocmf::session`](@/docs/sessions.md) |
| May these values be billed? | law, tariffs and a key registry — not this crate |

Conflating the four is how a "verified" charging session turns out to be a
signed fragment of a session somebody edited.

## Reading a public key

OCMF deliberately does not carry the key: the specification puts that binding
out of band. Keys therefore arrive in whatever shape the source uses, and this
crate reads five of them:

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

Exactly one variant means the record is not authentic. The others say whose
fault it is:

| Error | What actually went wrong |
|---|---|
| `Unsupported` | this build has no implementation of the curve |
| `AlgorithmKeyMismatch` | the key names a different curve than `SA` does |
| `KeyNotOnCurve` | the key is the right length and is not a point — a broken registry entry, not a broken record |
| `UnknownAlgorithm` | `SA` names an algorithm the table does not define — the record is never checked as a different one |
| `SignatureEncoding` | `SD` is absent, or is not readable as the encoding `SE` names |
| `SignatureShape` | the bytes are neither DER nor a raw `r‖s` of the right size |
| `SignatureScalars` | `r` or `s` is outside `[1, n)` — a signature nothing produced |
| `HighSSignature` | the low form was required by policy; both halves of a malleable pair are the same statement |
| **`NotVerified`** | **the signature is well-formed and does not match** |

## All seven algorithms

The specification defines seven, all ECDSA over SHA-256 — including on the
384-bit curves, which rules out the convenient path through a default digest.

| `SA` identifier | Curve | Pure Rust | OpenSSL |
|---|---|:--:|:--:|
| `ECDSA-secp192k1-SHA256` | secp192k1 | — | ✓ |
| `ECDSA-secp192r1-SHA256` | secp192r1 (NIST P-192) | ✓ | ✓ |
| `ECDSA-secp256k1-SHA256` | secp256k1 | ✓ | ✓ |
| `ECDSA-secp256r1-SHA256` *(default)* | secp256r1 (P-256) | ✓ | ✓ |
| `ECDSA-brainpool256r1-SHA256` | brainpoolP256r1 | — | ✓ |
| `ECDSA-secp384r1-SHA256` | secp384r1 (P-384) | ✓ | ✓ |
| `ECDSA-brainpool384r1-SHA256` | brainpoolP384r1 | — | ✓ |

secp192k1 and brainpoolP256r1 **appear in the reference corpus**, so "recognise
and refuse" was not an option. Build with `--features backend-openssl` for all
seven; an algorithm a build cannot check is reported as `Unsupported`, never as
"does not verify".

```rust
ocmf::is_supported(ocmf::Curve::BrainpoolP256r1);  // a const fn over the features
ocmf::supported_curves();
```

```console
$ ocmf curves
  yes  ECDSA-secp192k1-SHA256       secp192k1
  yes  ECDSA-secp256k1-SHA256       secp256k1
  …
```

## Signature encodings in the wild

`SM` announces a MIME type and defaults to `application/x-der`. It is never
present in the reference corpus, and two records are not DER at all.

- **DER first.** Parsed as `SEQUENCE { INTEGER r, INTEGER s }`, leniently:
  BouncyCastle — and therefore the legally recognised verifier — accepts
  non-minimal lengths, trailing bytes and `INTEGER`s whose top bit is set with no
  `0x00` pad. Real eBZ meters emit the last of those and OpenSSL refuses to parse
  it. This crate reads it and reports `NonCanonicalDer`.
- **Raw `r‖s`** on an exact length match, reported as `RawSignatureNotDer`.
- **Otherwise** an error naming the length.

`s` is normalised before the backend sees it. `(r, s)` and `(r, n − s)` are the
same statement; some pure-Rust curves verify only the low form, while
BouncyCastle accepts either — and two authentic secp256k1 records in the corpus
are high-`s`. The deviation is still reported.
