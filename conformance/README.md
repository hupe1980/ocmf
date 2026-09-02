# The OCMF conformance suite

`suite.json` is a set of OCMF records with a stated expected outcome for each
one. It is meant to be run by **any** OCMF implementation, in any language —
that is the point of publishing it. Nothing in it depends on Rust, and the
records in it are ordinary OCMF text.

The specification has no conformance suite. Every implementation therefore
decides on its own what "reads an OCMF record" means, and the disagreements only
surface years later, in a dispute, when two parties both believe they are right.
This is an attempt at the missing artefact.

## What is in it

| Group | Cases | What it pins down |
|---|---|---|
| `table/*` | one per value of every closed table | `[Tab. 7, 10, 11, 13–21, 25]`. An implementation that maps an unknown value onto a known one fails here, and so does one that reads `"\u006bWh"` as anything but `kWh` |
| `deviation/*` | one per departure real meters make, **and one per field a record can render unreadable** | A missing `MS`, a quoted `RV`, a carried-forward `TM`, a bare `r‖s`, a non-canonical DER encoding, a high-`s` signature, a raw control character in a string, a value outside its table, an `ID` that is not the shape its `IT` states, a pipe inside `TT` — plus a `TM` nobody can read, an `RV` no exact decimal can hold, an `SA` outside `[Tab. 22]`, and an absent `PG`, `RD` or `SD` |
| `curve/*` | one per algorithm of `[Tab. 22]` | Including brainpool and secp192k1, which most implementations cannot check |
| `reject/*` | byte sequences that must **not** be accepted | Truncated sections, a payload that is not an object, a signature that does not verify. The parser refuses *structure* only, so anything about a field's value is a `deviation/*` case with `"parses": true` instead |

## The schema

```jsonc
{
  "version": 1,
  "cases": [
    {
      "id": "table/meter-state-M",
      "group": "table",
      "description": "ST = M (MANIPULATED) [OCMF Tab. 10]",
      "record": "OCMF|{…}|{…}",          // the record, verbatim
      "key": "3059…",                     // hex SPKI, or absent
      "expect": {
        "parses": true,                   // can it be read at all?
        "round_trips": true,              // does printing it reproduce the input byte for byte?
        "verifies": true,                 // does the signature check out against `key`?
        "deviations": ["MeterSerialMissing"],  // exactly these, in any order
        "readings": 2,                    // how many readings after carry-forward
        "billable_readings": 0            // readings where meter=OK, no error flag, energy unit
      }
    }
  ]
}
```

`parses` is asked under the most permissive reading: a record with an absent
`PG`, an unreadable `TM` or an `SA` nobody defines **parses**, reports, and is
refused by a strict profile — a different question, which the `deviations` field
asks. Only a byte sequence that is not `OCMF|<JSON object>|<JSON object>` fails
`parses`.

`deviations` uses the names in this crate's `DeviationKind` — a written-down
mapping (`DeviationKind::name`), not a `Debug` rendering, because other
implementations match on these strings — and it is the set
observed **after verification** where a case verifies: a bare `r‖s`, a
non-canonical DER encoding and a high-`s` signature are only discoverable while
checking a signature, not while reading a record. An implementation that does
not verify — or that cannot check a case's curve — should require the set it
observes to be a *subset* of this one, rather than equal to it. One that does
not model deviations at all can ignore the field and still run the other four
expectations, which is most of the value.

## Running it

Against this crate:

```console
$ cargo run -p ocmf-cli -- conformance conformance/suite.json
162 case(s): 162 passed, 0 failed, 0 skipped
```

It checks all five expectations plus the deviation set; a runner that checks
fewer is publishing a schema it does not honour.

Against your own implementation: read `suite.json`, run each case, compare. A
case that your implementation *cannot* answer (an unsupported curve, say) should
be reported as skipped rather than failed — knowing which is which is the point.

## Regenerating

```console
cargo xtask conformance-gen
```

Every signed case is signed with the test key below and **re-verified before it
is written**, so a generation that produces a record that does not verify fails
at generation time.

## A note on `FV`

Every record in the suite says `"FV":"1.3"` unless the case is about `FV` itself.
1.3 is the newest version the S.A.F.E. Transparenzsoftware's own dispatch reads
(`version <= 1.3`, checked against `def928b`), so a suite pinned there can be run
against the reference implementation as well as against yours. The case
`deviation/format-version-ahead-of-reference` covers the other side.

## Attribution

Exactly one case — `deviation/high-s-signature` — carries a record from the
S.A.F.E. Transparenzsoftware test resources (Apache-2.0, © S.A.F.E. e.V.; see
`ocmf/tests/corpus/NOTICE`). It is here because this crate's own signer emits
the low-`s` form, so the only honest way to cover a high-`s` signature is with
one a real meter produced.

Everything else was generated by this repository, including the `curve/*`
records and their keys.

The test private key is deliberately published — these records exist to be
checked, not to be trusted:

```text
secp256r1 private scalar: 2a2a2a…2a (32 bytes of 0x2a)
```
