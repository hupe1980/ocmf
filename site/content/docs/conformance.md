+++
title = "Conformance suite"
description = "A published OCMF conformance suite: 162 records with stated expected outcomes, meant to be run by any implementation in any language."
weight = 10
+++

The OCMF specification ships no conformance suite. Every implementation
therefore decides on its own what "reads an OCMF record" means, and the
disagreements only surface years later, in a dispute, when two parties both
believe they are right.

[`conformance/suite.json`](https://github.com/hupe1980/ocmf/tree/main/conformance)
is an attempt at the missing artefact: **162 records with a stated expected
outcome**, meant to be run by *any* implementation. Nothing in it depends on
Rust, and the records in it are ordinary OCMF text.

| Group | Cases | What it pins down |
|---|---:|---|
| `table/*` | 94 | One case per value of every closed table, plus the fiscal pagination context and two `\uXXXX`-escaped table values |
| `deviation/*` | 54 | One per departure real meters make, and one per field a record can render unreadable |
| `curve/*` | 7 | One per algorithm, brainpool and secp192k1 included |
| `reject/*` | 7 | Byte sequences that are not records at all, and a valid record with one digit changed |

## The schema

```jsonc
{
  "version": 1,
  "cases": [
    {
      "id": "table/meter-state-M",
      "group": "table",
      "description": "ST = M (MANIPULATED) [OCMF Tab. 10]",
      "record": "OCMF|{…}|{…}",              // the record, verbatim
      "key": "3059…",                         // hex SPKI, or absent
      "expect": {
        "parses": true,                       // can it be read at all?
        "round_trips": true,                  // does printing it reproduce the input?
        "verifies": true,                     // does the signature check out?
        "deviations": ["MeterSerialMissing"], // exactly these, in any order
        "readings": 2,                        // after carry-forward
        "billable_readings": 0                // meter OK, no error flag, energy unit
      }
    }
  ]
}
```

Two properties of that schema are load-bearing:

- **`deviations` is the post-verification set.** A bare `r‖s`, a non-canonical
  DER encoding and a high-`s` signature are only discoverable while checking a
  signature. An implementation that does not verify, or that cannot check a
  case's curve, should require the set it observes to be a *subset*.
- **A case an implementation cannot answer is *skipped*, not failed.** Knowing
  which is which is most of the point.
- **`parses` is asked under the most permissive reading.** A record with an
  absent `PG`, an unreadable `TM` or an `SA` nobody defines **parses**, reports,
  and is refused by a strict profile — a different question, asked by the
  `deviations` field. Only a byte sequence that is not
  `OCMF|<JSON object>|<JSON object>` fails `parses`.

An implementation that models no deviations at all can ignore that field and
still run the other five expectations, which is most of the value.

## Running it

```console
$ ocmf conformance conformance/suite.json
162 case(s): 162 passed, 0 failed, 0 skipped
```

Against your own implementation: read `suite.json`, run each case, compare.

## It cannot drift

The suite is generated, and every signed case is re-verified before it is
written — a generation that produces a record which does not verify fails there
rather than in somebody else's CI. CI then regenerates and diffs the result, so a
hand-edited suite is impossible. A deviation kind with no case fails the build.

Every record says `"FV":"1.3"` unless the case is about `FV` itself: 1.3 is the
newest version the S.A.F.E. Transparenzsoftware's own dispatch reads, so the
suite can be run against the reference implementation as well as against yours.

## The data behind it

Three independent bodies of test data, doing different jobs:

**The reference corpus.** Every OCMF record inside the S.A.F.E.
Transparenzsoftware test resources — 256 records, 705 readings, from eleven
vendors — each carrying **OpenSSL's verdict on it**. The oracle is deliberately
not this crate: a bug shared between an implementation and its test data is
invisible. The tests assert agreement on all 251 records where a verdict exists.

**Cross-curve vectors.** One record per algorithm, plus three that repeat the
secp256r1 record in the encodings the field emits — a bare `X‖Y` key, a raw
`r‖s` signature, and a Base64 `SD`. Generated *and verified* with OpenSSL before
being checked in.

**The published suite**, above.

On top of those: property tests (round trip is the identity; one changed byte
always breaks the signature; parsing is total), five fuzz targets, and unit tests
beside the rule each one checks.
