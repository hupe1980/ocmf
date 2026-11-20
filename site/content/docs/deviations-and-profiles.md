+++
title = "Deviations and profiles"
description = "How ocmf reports departures from the OCMF specification: the Departure classes, the full DeviationKind catalogue, and the three parsing profiles."
weight = 4
+++

Parsing runs in a **profile**, and every departure from the specification
becomes a typed `Deviation` carrying the offending value and the table it is
measured against. A profile decides which deviations are fatal; the default
reports them all and refuses none — 89&nbsp;% of the reference corpus omits a
field the specification marks mandatory, so a strict-only parser would reject
most real records.

## Breaches and advisories

Each deviation says whether it breaches the specification:

| `Departure` | Means |
|---|---|
| `Specification` | the record does something the specification does not permit |
| `Advisory` | lawful, and a reader still needs to know — load-bearing, a hazard, or something another implementation will trip over |

```rust
for d in record.deviations() {
    if d.is_breach() {
        // "value is not one the table defines: \"sec\" at RD[0].RU (byte 214)
        //  [OCMF Tab. 10-11, 17-21]"
        eprintln!("{d}");
    }
}
```

Deviations arrive in record order. Each carries the value that caused it,
quoted, escaped and truncated to 48 characters so attacker-controlled text is
safe to log.

Eight kinds are advisory: a pretty-printed payload (lawful, but destroyed by
re-serialising), a duplicate JSON key, carry-forward of a mandatory field, an
absent `FV`, a high-`s` signature, an `FV` newer than the reference verifier
reads, readings dropped by a `Limits` bound, and two `IF` flags from the same
group. Everything else is a breach.

## The profiles

| Profile | Refuses | Use it when |
|---|---|---|
| `Strict` | breaches of the specification | Checking your own output before a notified body does |
| `Reference` | what the S.A.F.E. Transparenzsoftware refuses, bug for bug | Asking "will the official tool accept this?" |
| `Interop` *(default)* | nothing | Reading a fleet without discarding evidence |

```rust
use ocmf::{Limits, Profile, Record};

let record = Record::parse_with(&text, Profile::Strict, &Limits::DEFAULT)?;
```

`Reference` refuses exactly five things, matching the reference verifier's
source: a missing `FV`, an `FV` above 1.3, a bare `r‖s` signature, an
undecodable `SD`, and a missing `SD`. `DeviationKind::rejected_by_reference_verifier()`
answers the same question per kind.

## Rules from the specification's prose

Two checks come from the prose rather than the tables:

- **`IF` holds at most four elements**, one per flag group
  (`IdentificationFlagsCardinality`). Two flags from the same group is advisory
  (`IdentificationFlagsDuplicateGroup`), because the table implies that rule
  rather than stating it.
- **A record must identify its source**:
  `[OCMF §Relation of Serial Numbers, Charge Point and Public Key]` requires the
  meter serial, the gateway serial, or `CT` with `CI`. With none of them no key
  can be bound to the record (`SourceUnidentifiable`).

## Undefined table values

A value outside a closed table is kept verbatim, reported as
`UndefinedTableValue` (or a format mismatch), and never treated as billable.
Examples from the S.A.F.E. reference corpus — 30 findings in 26 records:

| Found in the corpus | Records | What it is |
|---|---:|---|
| `"RU":"sec"` | 2 | a unit no table defines, so the reading is not energy and cannot be billed |
| `"CT":""`, `"CT":0`, `"CT":"DC-Test-Charger"` | 7 | a charge-point id type outside the table — one of them a JSON *number* |
| `IT`/`ID` mismatches | 13 | ISO 14443 UIDs of 2, 8 and 11 bytes where the table says 4 or 7; EMAIDs of 12 characters where it says 14 or 15 |
| `"CT":"CBIDC"` with `"CI":"CI"` | 8 | the table wants a charge box id, a space, and a connector |

## The catalogue

`DeviationKind` is `#[non_exhaustive]`; every variant carries a citation, a
stable machine-readable name and a one-sentence message.

Grouped by where they occur:

**Structure.** `PrettyPrintedPayload`, `FourthSectionPublicKey`,
`DuplicateKey`, `ControlCharacterInString`, `NonCanonicalNumber`,
`InvalidStringEscape`.

**Payload fields.** `FormatVersionMissing`, `FormatVersionMalformed`,
`FormatVersionAheadOfReference`, `MeterSerialMissing`,
`IdentificationStatusMissing`, `IdentificationFlagsMissing`,
`IdentificationTypeMissing`, `IdentificationDataFormat`, `ChargePointIdFormat`,
`IdentificationFlagsCardinality`, `IdentificationFlagsDuplicateGroup`,
`SourceUnidentifiable`, `PaginationMissing`, `PaginationMalformed`,
`PaginationLeadingZero`, `ReadingsMissing`, `ReadingsTruncated`,
`LossCompensationIncomplete`, `FieldTooLong`, `FieldTypeMismatch`,
`UnknownKey`, `UndefinedTableValue`, `ScalarFieldNotAString`,
`ExtensionInsideReading`.

**Readings.** `RvIsString`, `NumberUnrepresentable`,
`MandatoryReadingFieldMissing`, `CarriedForwardMandatoryField`,
`TimeOffsetWithColon`, `TimeDotMilliseconds`, `TimeStatusMissing`,
`TimeSubSecondDigits`, `TimeMalformed`, `ObisNonCanonical`, `ObisMalformed`.

**Signature section.** `RawSignatureNotDer`, `NonCanonicalDer`,
`AlgorithmIdentifierSpelling`, `SignatureDataUndecodable`,
`SignatureDataMissing`, `HighSSignature`.

Every kind has a case in the [conformance suite](@/docs/conformance.md).

## What is fatal

Only structure. A byte sequence that is not `OCMF|<JSON object>|<JSON object>`
is not a record and is a `ParseError`; everything inside those objects is
reported, so a record with a bad field can still be parsed and verified:

| Fatal — `ParseError` | Reported — `Deviation` |
|---|---|
| the header or a delimiter is missing | any field's value, absence or JSON type |
| a section is not a JSON object | `PG`, `RD` or `SD` absent |
| the JSON is malformed | `SA` or `SE` outside its table |
| a `Limits` bound was reached | `TM`, `RI` or `RV` unreadable |
| the profile in force refuses a deviation | a scalar field holding an object |

An undecodable `SD` costs the signature, not the payload. A string field that
arrives as a JSON number is read as its literal text. An unreadable `TM` costs
the reading its clock. The one non-fatal loss is a `Limits` bound on `RD`: the
surplus readings are dropped and reported as `ReadingsTruncated`.
