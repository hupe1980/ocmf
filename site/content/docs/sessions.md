+++
title = "Sessions"
description = "Check a whole charging transaction: continuous pagination, one begin and one end, one source, error states fatal — every rule OCMF assigns to a check component."
weight = 7
+++

## Beyond one signature

A valid signature on each record says nothing about the sequence. The
specification assigns that to a *check component*:

> The cohesion between several individual data records is ensured by continuous
> pagination. […] The first record must be marked as the start of a charging
> process, the last as the end. In between, no data records may have been
> removed or added. Likewise, intermediate error conditions […] must lead to an
> error during the test. Furthermore, all data records must come from the same
> source.

Every sentence of that is a check here, plus the four the reference verifier
adds: exactly one start and one stop reading, `RV(start) ≤ RV(stop)`,
`t(start) ≤ t(stop)`, `ST == "G"` on both, and an identification level outside
the four error states.

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

The records must be in the order the station produced them; the function checks
that the pagination agrees, it does not sort.

## Which rules a sequence is subject to

`[OCMF Tab. 2]` defines the `F` pagination context as "fiscal readings,
**independent of transactions**", and `[OCMF Tab. 7]` makes an absent `TX` mean
the same thing. A fiscal record is therefore *forbidden* to carry a begin or an
end marker — so asking one for a marker reports a fault against a record for
obeying the specification.

`SessionReport::kind()` says which rule set ran:

| `SequenceKind` | Marker rules | `RegisterTotal` ends are |
|---|---|---|
| `Transaction` | one begin in the first record, one end in the last | the readings marked `TX = B` and `TX = E` |
| `Fiscal` | skipped | the **first and last** readings of each register |

Everything else applies to both: continuous pagination, one source, no repeats,
meter state, error flags, identification, the clock, and a register that does
not run backwards.

No record in the reference corpus is fiscal — measured, 0 of 256 — which makes
this the path most worth being explicit about, not the least.

## Where signatures fit

`validate` answers "do these records hang together", never "is this session
real". When you hold verified records, thread them through instead — the two
questions then stay visibly answered rather than visibly conflated:

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

`RegisterEndWithoutBegin` is where this parts company with the reference
verifier deliberately. `Meter.validateListStartStop` compares the **largest**
start against the **smallest** stop across every law-relevant register at once,
as Java `double`s — which on the interleaved records LEM meters write pairs an
import start with an export stop. Asked per register, with exact decimals, the
question either has an answer or it does not, and "it does not" is a finding.

## A report a pipeline can read

Under the `serde` feature the whole report serialises, with every quantity as
the decimal's **exact text** — a JSON number goes through `f64` in most
consumers, and these are kilowatt-hours somebody is invoiced for.

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

A finding names itself — `{"finding": "PaginationBroken", "from": 1, "to": 3,
"index": 1}` — so another tool can match on the name rather than on prose.

## The weakest clock decides

`SessionReport::clock()` is the **lowest** clock status anywhere in the
sequence, not the best. One synchronised reading does not vouch for twenty
unsynchronised ones, and the error of taking the best one always runs towards
billing.

```rust
report.clock();       // the weakest — what a decision should use
report.best_clock();  // reported for completeness; authorise nothing on it
```

That matches every other rule in the crate: an unknown meter state is not `OK`,
an unknown unit is not energy, an omitted error flag is still set.

## This module does not decide money

It reports findings. Whether a session may be invoiced depends on tariffs, on a
key registry binding each record to *this* charge point, and on law — none of
which is in scope. What it does guarantee is that no finding is silently absent:
a clean report means every rule above held.
