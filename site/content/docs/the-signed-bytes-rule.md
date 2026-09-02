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

A parser that deserialises into a struct and re-serialises to verify has already
lost. Four things change on that round trip, and every one of them changes the
digest:

- **key order** — JSON objects are ordered on the wire and unordered in most
  models;
- **whitespace** — lawful inside the payload, and nine records in the S.A.F.E.
  reference corpus are pretty-printed;
- **number formatting** — `2935.600` and `2935.6` are the same value and
  different bytes;
- **Unicode escapes** — `"kWh"` and `"kWh"` are the same string and
  different bytes.

So `Record::signed_bytes()` returns a slice of the input, and there is no API in
this crate that produces signable bytes from a typed value. Reading gives you a
slice; writing produces the text *first* and signs that. The two directions meet
at the bytes, never at a struct.

```rust
let record = Record::parse(&text)?;
assert_eq!(record.to_string(), text);                     // the identity function
assert_eq!(record.signed_bytes(), record.payload_text().as_bytes());
```

## Finding the section boundary

The specification separates the three sections with `|` and says the character
"is not allowed within the sections" — a rule the format states and cannot
enforce, because the tariff text `TT` is 250 characters of free text.

Every implementation surveyed splits on every pipe and indexes the result. A
record with a pipe inside a tariff name is then truncated mid-string, fails to
parse, and the evidence is lost.

This parser instead **scans the payload as a JSON value** to find where it really
ends, then requires the next non-space byte to be the delimiter:

```rust
// A tariff name with a pipe in it. Lawful free text; fatal to a naive split.
let src = r#"OCMF|{…,"TT":"Tarif|Nacht",…}|{"SD":"…"}"#;
let record = Record::parse(src)?;
assert_eq!(record.payload().tariff_text(), Some("Tarif|Nacht"));
```

Where no pipe hides inside a string the two approaches agree byte for byte —
including keeping any whitespace that follows the delimiter, because that is
what the reference implementation's `split("|")[1]` yields and bit-compatibility
with the legally recognised verifier is not negotiable.

## A record's identity is its digest, not its text

ECDSA signatures are malleable and DER admits non-canonical encodings, so one
payload can appear under many distinct `SD` values that all verify.
Deduplicating on the record string therefore stores the same reading twice, and
in a billing pipeline that is a double charge.

```rust
let id: [u8; 32] = record.payload_digest();   // SHA-256 of the signed span
```

Key on that.

## Writing

The builder produces the payload text, hashes those exact bytes, and signs the
hash. It then re-parses the record it produced and verifies the signature
against the signer's own public key before returning it — a signing path that
can emit an unverifiable record is worse than no signing path at all. See
[Signing](@/docs/signing.md).
