+++
title = "Transports"
description = "Move an OCMF record: the OCPP SignedMeterValueType container with its oca: public-key composition, and the S.A.F.E. transparency XML a driver checks a bill with."
weight = 8
+++

OCMF defines a record, not a way to move it. The crate implements the two
transports in use: OCPP (feature `ocpp`) and the S.A.F.E. transparency XML
(feature `xml`).

## OCPP — `SignedMeterValueType`

The Open Charge Alliance's application note *Signed Meter Values in OCPP*
defines how a record travels between a charging station and a CSMS in OCPP 1.6,
2.0.1 and 2.1:

| Field | What it actually holds |
|---|---|
| `signedMeterData` | **Base64 of the OCMF string**, not the string |
| `signingMethod` | empty for OCMF — "if it is already included in the `signedMeterData` block … this SHALL be an empty string", and for OCMF it is, in `SA` |
| `encodingMethod` | `"OCMF"` |
| `publicKey` | Base64 of a **colon-composed string**, below |

```rust
use ocmf::ocpp::SignedMeterValue;

let smv = SignedMeterValue::from_record(&record, Some(&key));
assert_eq!(smv.encoding_method, "OCMF");

// …and back, on the CSMS side
let text = smv.record_text()?;
let record = ocmf::Record::parse(&text)?;
let key = smv.key(record.signature().curve())?;
```

Under the `serde` feature the container serialises to and from OCPP JSON with
camelCase field names. It is the only `Deserialize` type in the crate, which is
safe because the record travels inside it as Base64 of its exact text.

### The `publicKey` composition

```text
base64( "oca:" <encoding> ":" <content-type> ":" <printed-public-key> )
```

`<encoding>` is `base16` or `base64`, `<content-type>` is `asn1`, and the last
part is the key **as printed on the meter**, so base16 is read
case-insensitively and non-hex characters and a `0x` prefix are ignored.

```rust
key.to_oca_base64();                    // what an OCPP `publicKey` should contain
ocmf::PublicKey::from_oca(text, hint)?; // and back
```

A plain Base64 or hex key in that field is also accepted.

### Where a record goes

Start and stop in *separate* records go in two `sampledValue`s with contexts
`Transaction.Begin` and `Transaction.End`; both in *one* record go in a single
`sampledValue` with context `Transaction.End`.

```rust
ocmf::ocpp::MeterValueContext::for_record(&record);   // read off the record's own TX markers
```

The transparency XML treats the same record differently: a record carrying both
markers gets no context and no transaction id there, because nothing needs
pairing. `Payload::marks_transaction_begin()` and `marks_transaction_end()`
answer the underlying question; each transport applies its own rule.

### Configuration worth knowing

`PublicKeyWithSignedMeterValue = Never` (`PublicKeyPolicy::Never`) means the
keys for historical transactions are unretrievable after a meter swap; the
application note calls that "a compliance issue". OCPP 1.6 caps a configuration
value at 500 bytes, which limits the key `MeterPublicKey` can carry.

## S.A.F.E. transparency XML

The file a driver loads into the S.A.F.E. Transparenzsoftware to check a bill,
as §33 <i lang="de">MessEG</i> requires the affected party be able to do.

```xml
<values>
  <value transactionId="1" context="Transaction.Begin">
    <signedData format="OCMF" encoding="plain">OCMF|…|…</signedData>
    <publicKey encoding="hex">3059 3013 …</publicKey>
  </value>
</values>
```

```rust
use ocmf::xml::Values;

let xml = Values::from_records([(&begin, Some(&key)), (&end, Some(&key))]).to_xml()?;

// Read one back, e.g. when a driver disputes a bill:
let values = Values::parse(&xml)?;
let record = values.entries[0].record()?;
let key = values.entries[0].key(None)?;
```

### `transactionId` is what the tool pairs on

The Transparenzsoftware groups `<value>` elements by `transactionId` and
requires **exactly one** `Transaction.Begin` and **exactly one**
`Transaction.End` per group. Numbering the records `1, 2, 3…` produces a file it
refuses with *"no stop value for transaction found"*.

`Values::from_records` groups records the way S.A.F.E.'s own files do:

| The record | `transactionId` | `context` |
|---|---|---|
| marks a begin **and** an end | none | none |
| marks a begin only | a new one | `Transaction.Begin` |
| marks an end only | the open one | `Transaction.End` |
| marks neither | the open one, if any | none |

Set the fields on `ValueEntry` directly to say something else.

### Details

- **The element text is the record, byte for byte.** Re-wrapping, re-indenting
  or re-escaping it invalidates the signature; the writer escapes minimally.
- **Not every value is OCMF.** S.A.F.E.'s files also carry `ISA_EDL_40_P` and
  `SML_EDL40_P` values. `ValueEntry::is_ocmf()` says which, and `ocmf verify`
  skips the others by name.
- **Keys are often grouped** (`3059 3013 0607 …`); the hex reader ignores
  whitespace.
- **`<encodedData>`** (older files) and `<signedData>` are both read.

`Values::parse_with()` takes explicit `Limits` (including the 4096-entry bound)
and `ValueEntry::record_with()` an explicit profile and limits, because a
transparency file is untrusted input.
