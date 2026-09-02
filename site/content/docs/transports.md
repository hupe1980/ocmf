+++
title = "Transports"
description = "Move an OCMF record: the OCPP SignedMeterValueType container with its oca: public-key composition, and the S.A.F.E. transparency XML a driver checks a bill with."
weight = 8
+++

OCMF defines a container, not a way to move it. Two documents define the ways it
actually moves, and both are implemented here.

## OCPP — `SignedMeterValueType`

The Open Charge Alliance's application note *Signed Meter Values in OCPP*
settles how a record travels between a charging station and a CSMS in OCPP 1.6,
2.0.1 and 2.1. Three of the container's four fields are less obvious than they
look:

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

Under the `serde` feature the container serialises straight to and from the JSON
an OCPP message carries, with camelCase field names. It is the one type in the
crate that is `Deserialize`, and the exception proves the rule: the record
travels inside it as Base64 of its own text, so a round trip through JSON
reproduces the signed bytes exactly.

### The `publicKey` composition

```text
base64( "oca:" <encoding> ":" <content-type> ":" <printed-public-key> )
```

`<encoding>` is `base16` or `base64`, `<content-type>` is `asn1`, and the last
part is the key **as printed on the certified meter** — which is why base16 must
be read case-insensitively while non-hexadecimal characters and a `0x` prefix are
ignored. A meter's label may group the hex however its manufacturer likes.

As far as this project's research found, no other open-source implementation
reads or writes that composition.

```rust
key.to_oca_base64();                    // what an OCPP `publicKey` should contain
ocmf::PublicKey::from_oca(text, hint)?; // and back
```

A plain Base64 or hex key in that field is also accepted, because
implementations that predate the note send one.

### Where a record goes

Determined by how the meter packages readings, not by preference: start and stop
in *separate* containers go in two `sampledValue`s with contexts
`Transaction.Begin` and `Transaction.End`; both in *one* container go in a single
`sampledValue` with context `Transaction.End`.

```rust
ocmf::ocpp::MeterValueContext::for_record(&record);   // read off the record's own TX markers
```

**The transparency container disagrees about the same record, and both are
right.** A record carrying both markers goes into an OCPP `sampledValue` under
`Transaction.End`, and into a S.A.F.E. `<value>` with no context and no
transaction id at all — there the attribute is what the verifier *pairs* on, and
a self-contained record has nothing to pair with.
`Payload::marks_transaction_begin()` and `marks_transaction_end()` answer the
underlying question; each transport applies its own rule to it.

### Configuration worth knowing

`PublicKeyWithSignedMeterValue = Never` means that after a meter swap, the keys
for historical transactions are no longer retrievable. The application note calls
that "a compliance issue"; `PublicKeyPolicy::Never` carries the warning in its
documentation. OCPP 1.6 also caps a configuration value at 500 bytes, so
`MeterPublicKey` cannot carry a key longer than that.

## S.A.F.E. transparency XML

This is the file a driver feeds to the Transparenzsoftware, and producing it is
half of what §33 <i lang="de">MessEG</i> actually asks for: the law does not
require a measured value to be *correct*, it requires the affected party to be
able to **check** it. A platform that verifies internally and reports "verified"
has satisfied nobody.

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

// Reading one back matters as much as writing it: the other half of the duty
// arrives when a driver disputes a bill and sends the file back.
let values = Values::parse(&xml)?;
let record = values.entries[0].record()?;
let key = values.entries[0].key(None)?;
```

### `transactionId` is what the tool pairs on

The Transparenzsoftware groups `<value>` elements by `transactionId` and then
demands **exactly one** `Transaction.Begin` and **exactly one**
`Transaction.End` per group. Numbering the records `1, 2, 3…` produces a file it
refuses with *"no stop value for transaction found"*, on records it verifies
perfectly one at a time.

`Values::from_records` groups them as S.A.F.E.'s own 257 values are grouped:

| The record | `transactionId` | `context` | Their files |
|---|---|---|---:|
| marks a begin **and** an end | none | none | 223 |
| marks a begin only | a new one | `Transaction.Begin` | 9 |
| marks an end only | the open one | `Transaction.End` | 9 |
| marks neither | the open one, if any | none | 22 |

Set the fields on `ValueEntry` directly to say something else.

### Four more things that are easy to get wrong

- **The element text is the record, byte for byte.** A transport layer that
  re-wraps, re-indents or re-escapes silently invalidates every record it
  carries. The writer escapes minimally and a round-trip test asserts the bytes
  survive.
- **A container is not an OCMF file.** 234 of S.A.F.E.'s 247 `<signedData>`
  elements are `format="OCMF"`; eleven are `ISA_EDL_40_P` and two are
  `SML_EDL40_P`. `ValueEntry::is_ocmf()` says which, and `ocmf verify` skips the
  others by name rather than reporting a missing OCMF header about a value that
  never claimed to be one.
- **Keys are written in groups of two bytes in the wild** (`3059 3013 0607 …`).
  The hex reader tolerates whitespace, as the reference verifier does.
- **Older files use `<encodedData>`** where newer ones use `<signedData>`. Both
  are read.

`Values::parse_with()` and `ValueEntry::record_with()` read under explicit
limits and profile, because a transparency file arrives from outside — and
everything that arrives from outside is bounded.
