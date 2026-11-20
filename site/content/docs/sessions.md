+++
title = "Sessions"
description = "Check a whole charging transaction: continuous pagination, one begin and one end, one source, error states fatal — every rule OCMF assigns to a check component."
weight = 7
+++

## Check a sequence

A valid signature on each record says nothing about the sequence. The
specification assigns that check to a *check component*:

> The cohesion between several individual data records is ensured by continuous
> pagination. […] The first record must be marked as the start of a charging
> process, the last as the end. In between, no data records may have been
> removed or added. Likewise, intermediate error conditions […] must lead to an
> error during the test. Furthermore, all data records must come from the same
> source.

`ocmf::session::validate` checks each of those, plus the reference verifier's
additions: exactly one start and one stop reading, `RV(start) ≤ RV(stop)`,
`t(start) ≤ t(stop)`, `ST == "G"` on both, and an identification level outside
the error states.

```rust
let report = ocmf::session::validate(&records);

for f in report.findings() {
    println!("{f}");
    // "pagination went 1 → 3 at record 1: a record was removed, duplicated or reordered"
}

for t in report.totals() {
    println!("{}: {} → {} (Δ {} {})", t.obis, t.begin, t.end, t.delta, t.unit);
}
```

Pass the records in the order the station produced them; `validate` checks the
pagination, it does not sort.

## Which rules a sequence is subject to

`[OCMF Tab. 2]` defines the `F` pagination context as "fiscal readings,
independent of transactions", so a fiscal record must not carry begin or end
markers. `SessionReport::kind()` says which rule set ran:

| `SequenceKind` | Marker rules | `RegisterTotal` ends are |
|---|---|---|
| `Transaction` | one begin in the first record, one end in the last | the readings marked `TX = B` and `TX = E` |
| `Fiscal` | skipped | the **first and last** readings of each register |

Everything else applies to both: continuous pagination, one source, no repeats,
meter state, error flags, identification, the clock, and a register that does
not run backwards.

## Where signatures fit

`validate` answers "do these records hang together", not "are they authentic".
When you hold verified records, pass them to `validate_verified` so both
questions are answered:

```rust
let verified: Vec<_> = records.iter()
    .map(|r| ocmf::verify(r, &key))
    .collect::<Result<_, _>>()?;

let report = ocmf::session::validate_verified(&verified);
```

## The findings

`Finding` is `#[non_exhaustive]`; each variant carries the record index and the
values involved.

- `Empty`
- `PaginationBroken`, `PaginationContextChanged`, `PaginationUnreadable`
- `NoBegin`, `NoEnd`, `MultipleBegins`, `MultipleEnds`, `MarkerOutOfPlace`
  — a transaction sequence only
- `SourceChanged` — the records do not all come from one meter or gateway
- `MeterNotOk`, `ErrorFlagged`, `TransactionFaulted`
- `IdentificationError`
- `MeterWentBackwards`, `RegisterEndWithoutBegin`, `TimeWentBackwards`
- `ClockNotSynchronised`
- `DuplicateRecord` — the same payload twice, caught on the digest even when the
  pagination is valid

Start and stop are compared **per register**, with exact decimals. The
reference verifier compares across all registers at once, which pairs an import
start with an export stop on interleaved records; a register with an end but no
begin is reported as `RegisterEndWithoutBegin`.

## A report a pipeline can read

Under the `serde` feature the report serialises, with every quantity as the
decimal's **exact text** rather than a JSON number:

```console
$ ocmf session start.ocmf end.ocmf --json
{
  "kind": "Transaction",
  "findings": [],
  "totals": [
    { "obis": "01-00:B1.08.00*FF", "begin": "100.000", "end": "129.500",
      "delta": "29.500", "unit": "kWh" }
  ],
  "worst_clock": "S",
  "best_clock": "S"
}
```

A finding serialises with its name — `{"finding": "PaginationBroken", "from": 1,
"to": 3, "index": 1}` — so tools can match on the name rather than the message.

## The weakest clock decides

`SessionReport::clock()` is the **lowest** clock status anywhere in the
sequence: one synchronised reading does not vouch for unsynchronised ones.

```rust
report.clock();       // the weakest — what a decision should use
report.best_clock();  // reported for completeness; authorise nothing on it
```

## Scope

The module reports findings; it does not decide whether a session may be
invoiced, which depends on tariffs, a key registry and law. A clean report means
every rule above held.
