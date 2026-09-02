# Cross-curve vectors

`curves.json` holds one OCMF record per algorithm of `[OCMF Tab. 22]`, plus
three records that repeat the secp256r1 vector in the encodings the field
actually emits:

| Shape | Why it is here |
|---|---|
| `bare-xy-key` | Isabellenhütte writes a 64-byte `X‖Y` with no SEC1 prefix and no `SubjectPublicKeyInfo` |
| `raw-rs-signature` | …and a 64-byte `r‖s` where `SM` says (or defaults to) `application/x-der` |
| `base64-signature` | `SE: "base64"` — one record in the whole reference corpus, and therefore almost untested everywhere |

Unlike `tests/corpus/`, this data is **not** third-party: every key was generated
here and every signature was produced *and verified* by OpenSSL 3.6.3 before
being checked in. That makes it safe to redistribute and, more importantly, it
makes the oracle independent of the crate under test.

The private keys are deliberately not kept. These vectors exist to be verified,
not to be re-signed; regenerating them produces different keys and different
signatures, which is fine — the test asserts properties, not bytes.

## Regenerating

```console
python3 tests/vectors/generate.py
cargo test -p ocmf --features "full,backend-openssl" --test vectors
```

The generator refuses to write a vector that OpenSSL will not verify, so a
regeneration that produces a broken record fails at generation time rather than
in CI.
