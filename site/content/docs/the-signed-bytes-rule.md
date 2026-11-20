+++
title = "The signed-bytes rule"
description = "Why an OCMF signature covers the payload exactly as written, what that forbids, and how the section scanner finds the span without splitting on the pipe."
weight = 2
+++

## What the specification says

> Between signing and validation, the payload section must not be manipulated
> (removing and adding white spaces), otherwise positive validation is not
> possible.

The signature is ECDSA over SHA-256 of the payload section **exactly as it was
written**. Not of a normalised form, not of a canonical serialisation — of the
bytes on the wire.

## What that forbids

Never verify by deserialising into a struct and re-serialising. Four things
change on that round trip, and each changes the digest:

- **key order** — JSON objects are ordered on the wire and unordered in most
  models;
- **whitespace** — lawful inside the payload, and nine records in the S.A.F.E.
  reference corpus are pretty-printed;
- **number formatting** — `2935.600` and `2935.6` are the same value and
  different bytes;
- **Unicode escapes** — `"kWh"` and `"\u006bWh"` are the same string and
  different bytes.

`Record::signed_bytes()` therefore returns a slice of the input, and no API in
this crate produces signable bytes from a typed value. Writing produces the text
first and signs that.

```rust
let record = Record::parse(&text)?;
assert_eq!(record.to_string(), text);                     // the identity function
assert_eq!(record.signed_bytes(), record.payload_text().as_bytes());
```

## Finding the section boundary

The specification separates the sections with `|` and forbids the character
inside them, but cannot enforce that: the tariff text `TT` is up to 250
characters of free text. Splitting on every pipe truncates such a record.

This parser **scans the payload as a JSON value** to find where it ends, then
requires the next non-space byte to be the delimiter:

```rust
// A tariff name with a pipe in it. Lawful free text; fatal to a naive split.
let src = r#"OCMF|{…,"TT":"Tarif|Nacht",…}|{"SD":"…"}"#;
let record = Record::parse(src)?;
assert_eq!(record.payload().tariff_text(), Some("Tarif|Nacht"));
```

Where no pipe appears inside a string, the result is byte-identical to the
reference verifier's `split("|")[1]`, including any whitespace after the
delimiter. The builder refuses to write a `|` in any field
(`BuildError::PipeInField`).

## A record's identity is its digest, not its text

ECDSA signatures are malleable and DER admits non-canonical encodings, so one
payload can appear under many distinct `SD` values that all verify.
Deduplicate on the payload digest, not the record string, or the same reading
can be billed twice:

```rust
let id: [u8; 32] = record.payload_digest();   // SHA-256 of the signed span (feature `digest`)
```

## Writing

The builder produces the payload text, hashes those exact bytes, and signs the
hash. It then re-parses the record and verifies the signature against the
signer's own public key before returning it. See [Signing](@/docs/signing.md).
