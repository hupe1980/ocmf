# Cross-curve vectors

`curves.json` holds one OCMF record per algorithm of `[OCMF Tab. 22]`, plus
three records that repeat the secp256r1 vector in encodings real meters emit:

| Shape | Why it is here |
|---|---|
| `bare-xy-key` | Isabellenhütte writes a 64-byte `X‖Y` with no SEC1 prefix and no `SubjectPublicKeyInfo` |
| `raw-rs-signature` | …and a 64-byte `r‖s` where `SM` says (or defaults to) `application/x-der` |
| `base64-signature` | `SE: "base64"`, which only one reference-corpus record uses |

Unlike `tests/corpus/`, this data is **not** third-party: every key is generated
by the script below and every signature is produced *and verified* by OpenSSL
(3.6.3 for the checked-in file), so the oracle is independent of the crate under
test.

The private keys are not kept. Regenerating produces different keys and
signatures; the test asserts properties, not bytes.

## Regenerating

```console
python3 tests/vectors/generate.py
cargo test -p ocmf --features "full,backend-openssl" --test vectors
```

Run from the `ocmf/` directory. The generator asserts that OpenSSL verifies
each vector before writing it.
