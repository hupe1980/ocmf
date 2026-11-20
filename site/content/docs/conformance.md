+++
title = "Conformance suite"
description = "A published OCMF conformance suite: 163 records with stated expected outcomes, meant to be run by any implementation in any language."
weight = 10
+++

[`conformance/suite.json`](https://github.com/hupe1980/ocmf/tree/main/conformance)
holds **163 OCMF records, each with a stated expected outcome**, for *any*
implementation to run. Nothing in it depends on Rust; the records are ordinary
OCMF text. Table citations refer to OCMF revision 1.4.1 (specification commit
`e0a26be`), which ships no conformance suite of its own.

| Group | Cases | What it pins down |
|---|---:|---|
| `table/*` | 94 | One case per value of every closed table, plus the fiscal pagination context and two `\uXXXX`-escaped table values |
| `deviation/*` | 55 | One per departure real meters make, and one per field a record can render unreadable |
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

Three rules for reading it:

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

An implementation that models no deviations can ignore that field and still
run the other five expectations.

## Running it

```console
$ ocmf conformance conformance/suite.json
163 case(s): 163 passed, 0 failed, 0 skipped
```

Against your own implementation: read `suite.json`, run each case, compare.
Deviation names are `DeviationKind::name()` strings, a stable mapping rather
than a `Debug` rendering.

## How it is kept correct

The suite is generated (`cargo xtask conformance-gen`), and every signed case is
re-verified before it is written. CI regenerates and diffs it, so a hand edit
fails the build, as does a deviation kind with no case.

Every record says `"FV":"1.3"` unless the case is about `FV` itself: 1.3 is the
newest version the S.A.F.E. Transparenzsoftware reads, so the suite can be run
against the reference implementation too.

## The data behind it

Besides the suite, the crate is tested against:

- **The reference corpus** — every OCMF record in the S.A.F.E.
  Transparenzsoftware test resources: 256 records, 705 readings, eleven vendors,
  each with **OpenSSL's verdict** as the oracle rather than this crate's. The
  tests assert agreement on all 251 records that have a verdict.
- **Cross-curve vectors** — one record per algorithm, plus the secp256r1 record
  with a bare `X‖Y` key, a raw `r‖s` signature and a Base64 `SD`, all generated
  and verified with OpenSSL.
- **Property tests** (round trip is the identity; one changed byte breaks the
  signature; parsing is total), five fuzz targets, and unit tests.
