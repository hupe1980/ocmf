+++
title = "Deviations and profiles"
description = "How ocmf reports departures from the OCMF specification: the Departure classes, the full DeviationKind catalogue, and the three parsing profiles."
weight = 4
+++

## Two ways to be wrong

A strict parser rejects nine real records in ten — 89&nbsp;% of the reference
corpus omits a field the specification marks mandatory — and a lawful charging
session becomes unbillable for a schema reason.

A lenient parser accepts everything, and an operator never learns that their
fleet emits records the official tool will reject.

So parsing runs in a **profile**, and every departure becomes a typed
`Deviation` carrying the offending value and the table it is measured against.
Nobody has to choose between working and knowing.

## Not every finding is a fault

A report that flags everything flags nothing. Whitespace inside the payload is
*explicitly permitted* and still worth reporting, because re-serialising such a
record destroys it. Carry-forward is the rule the specification states, not a
breach of it. Each deviation says which it is:

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

Deviations arrive in the order they appear in the record, and each carries the
value that caused it — quoted, escaped and bounded to 48 characters, because
every field in a record is attacker-influenced text that ends up in somebody's
log.

Eight kinds are advisory: a pretty-printed payload, a duplicate JSON key,
carry-forward of a mandatory field, an absent `FV`, a high-`s` signature, a
format version newer than the reference verifier dispatches on, readings dropped
by a `Limits` bound, and two `IF` flags from the same group — which the table
implies and does not state, so reporting it as a breach would be reporting a
deviation from a rule nobody wrote. Everything else is a breach.

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

`Reference` refuses exactly five things, read out of the Java rather than
guessed: a missing `FV`, an `FV` above 1.3, a bare `r‖s` signature, an
undecodable `SD`, and an `SD` that is not there at all.

## Where the specification's *prose* states a rule

Most of what a reader checks comes out of the tables. Two rules live in the
prose instead, and nothing surveyed checks them:

- **`IF` is `0..4`** because there are four flag groups. More than four elements
  breaches the cardinality; two flags from *one* group state two things about
  the same assignment, which the table implies rather than says — so that one
  is advisory.
- **The serial numbers are *conditionally* mandatory**, and
  `[OCMF §Relation of Serial Numbers, Charge Point and Public Key]` gives the
  condition: the meter's serial, or the gateway's, or — "alternatively, a direct
  identification of the charge point" — `CT` with `CI`. With none of the three,
  no route the specification describes can bind a key to the record.
  `SourceUnidentifiable`.

Both hold across the whole reference corpus (measured: 0, 0 and 0).

## What nothing else reports

Every closed table in OCMF has values it does not define. Keeping such a value
and refusing it a billing decision is half the job; saying so is the other half.
These 30 findings, spread over 26 records of the S.A.F.E. reference corpus,
parse clean everywhere else:

| Found in the corpus | Records | What it is |
|---|---:|---|
| `"RU":"sec"` | 2 | a unit no table defines, so the reading is not energy and cannot be billed |
| `"CT":""`, `"CT":0`, `"CT":"DC-Test-Charger"` | 7 | a charge-point id type outside the table — one of them a JSON *number* |
| `IT`/`ID` mismatches | 13 | ISO 14443 UIDs of 2, 8 and 11 bytes where the table says 4 or 7; EMAIDs of 12 characters where it says 14 or 15 |
| `"CT":"CBIDC"` with `"CI":"CI"` | 8 | the table wants a charge box id, a space, and a connector |

## The catalogue

`DeviationKind` is `#[non_exhaustive]`; every variant carries a citation, a
stable machine-readable name and a one-sentence message.

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

Every one of them has a case in the [conformance suite](@/docs/conformance.md);
a kind with no case fails the build.

## Losing the payload is the bug

A junk signature, an unknown meter state, a unit nobody defined: each is a reason
to refuse *something*, and the temptation is to refuse the record. The record is
the evidence a dispute turns on — and a caller who cannot parse it cannot
**verify** it either, so refusing it throws away the one thing that was never in
doubt.

So the line is drawn at structure. A byte sequence that is not
`OCMF|<JSON object>|<JSON object>` is not a record and is an error. Everything
inside those objects is data:

| Fatal — `ParseError` | Reported — `Deviation` |
|---|---|
| the header or a delimiter is missing | any field's value, absence or JSON type |
| a section is not a JSON object | `PG`, `RD` or `SD` absent |
| the JSON is malformed | `SA` or `SE` outside its table |
| a `Limits` bound was reached | `TM`, `RI` or `RV` unreadable |
| the profile in force refuses a deviation | a scalar field holding an object |

An undecodable `SD` costs the signature and not the payload. A string field that
arrives as a JSON number is read as the literal text it was written with. A `TM`
nobody can read costs the reading its clock. Values outside a closed table are
kept verbatim, reported, and refused every predicate that could authorise money.

The one exception is a `Limits` bound on `RD`, because the point of a bound is
to bound the work: the surplus readings are dropped and `ReadingsTruncated` says
so.
