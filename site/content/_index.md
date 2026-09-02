+++
title = "ocmf — Open Charge Metering Format for Rust"
description = "Parse, verify and sign OCMF records in Rust. Byte-exact signed spans, all seven ECDSA algorithms, deviation reporting, OCPP and S.A.F.E. transparency XML, no_std."
template = "index.html"
+++

```rust
use ocmf::{PublicKey, Record, verify};

let record = Record::parse(&text)?;

// Reading a record and writing it back is the identity function.
assert_eq!(record.to_string(), text);

// The bytes the signature covers — a slice of `text`, never rebuilt.
let signed: &[u8] = record.signed_bytes();

let key = PublicKey::from_text(&key_text, record.signature().curve())?;
let verified = verify(&record, &key)?;
```
