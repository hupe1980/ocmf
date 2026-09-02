+++
title = "Reading records"
description = "The payload: fields, readings, carry-forward resolution, OBIS codes, exact decimals and the welded timestamp field."
weight = 3
+++

## The shape of a payload

A payload is one JSON object. The crate types every field of the
specification's tables and keeps the raw JSON alongside, so vendor extensions
and exact text are never lost.

```rust
let p = record.payload();

p.format_version();      // FV
p.gateway_id();          // GI, GS, GV — the signing component
p.meter_serial();        // MS
p.pagination();          // PG — Option: absent or unreadable is a deviation
p.identification_type(); // IT, plus IS / IL / IF / ID
p.tariff_text();         // TT
p.loss_compensation();   // LC — cable-loss compensation
p.readings();            // RD, carry-forward resolved
p.object();              // the raw JSON, for vendor extensions
```

## Carry-forward

The specification states, in one sentence in a table preamble:

> For the readings, fields that have an identical value to the previous reading
> are omitted. However, this only applies within a signed record.

The rule is written over *fields*, with `RI` and `TX` as examples rather than as
the list, so `TM`, `RU`, `RT`, `EF` and `ST` carry on exactly the same footing.
This is not a corner case: **205 of 705 readings** in the reference corpus have
no `TM` at all.

`Reading` accessors answer what the reading *means* — after resolution.
`Reading::explicit()` says what it *wrote*:

```rust
use ocmf::Explicit;

let r = &record.payload().readings()[1];
r.time();                              // resolved: inherited if omitted
r.explicit().has(Explicit::TIME);      // false — this reading did not write TM
```

Three details decide money:

**`EF` carries forward.** A record whose first reading is flagged `E` and whose
second omits the field is a record whose second reading is *still flagged*.
Reading the omission as "no error" clears a fault the station signed.

**`RV` and `CL` never carry.** The specification gives a second meaning to their
absence — a reading may report only that an error occurred — so an omitted `RV`
is ambiguous, and only one of the two readings can invent money. They stay
`None`.

**`RI` and `RU` are a group**, carried together or not at all, as the table says.

Carry-forward never crosses a record boundary: the specification scopes it to one
signature, and carrying a unit across one would be inventing data.

## Registers

A record can hold several registers interleaved — LEM's DCBM writes one
fully-specified import reading, then an export reading carrying only what
changed. Pairing the first and last readings would match an import begin with an
export end, so grouping happens **after** carry-forward:

```rust
for series in record.payload().by_register() {
    println!("{}", series.obis);          // canonical OBIS form
    series.begin();                        // the reading marked TX = B
    series.end();                          // …or any of the five endings
    series.delta();                        // end − begin, exact, same unit only
}
```

## OBIS codes

The specification defines billing-relevant codes in the form `01-00:B1.08.00*FF`.
**Not one OBIS code in the reference corpus is written that way.** What 705 real
readings contain:

| Form | Readings |
|---|---:|
| `1-b:1.8.0` | 462 |
| `1-b:1.9.0` | 200 |
| `1-b:1.8.e` | 14 |
| `01-00:01.08.00.FF` | 6 |
| `1-0:1.8.0`, `1-0:1.8.0*198`, `1-0:1.8.1` | 4 each |
| five more spellings | 2–3 each |

Lower-case medium letters, one- and two-digit groups, and three different
spellings of the tariff separator. `ObisCode` therefore parses a loose grammar,
keeps the original text, and offers a normal form for comparison:

```rust
let code = reading.obis().unwrap();
code.as_str();          // "1-b:1.8.0", as the station wrote it
code.canonical();       // "01-0B:01.08.00"
code.register();        // Register::ActiveEnergyImport
code.register().is_import();             // Some(true)
code.register().is_device_side();        // mains or after cable-loss compensation
code.register().is_transaction_scoped(); // this transaction, or a lifetime total
```

The radix the specification leaves open is not invented here: `B1` can only be
hexadecimal, `1-0:98.8.0.FF` is a decimal-flavoured IEC code, and `*198` cannot
be a hex byte at all. Groups are compared case-insensitively without leading
zeros, and semantic questions are answered from the code sets that are actually
defined.

## Numbers are never floats

A reading states its own precision. `2935.600` says three valid decimal places,
and the specification is explicit that the representation "must not be
transformed … since this would change the representation of the physical
quantity and thus potentially the number of valid digits".

`f64` cannot hold `9.2`. Every number in this crate is an exact decimal parsed
from the token's own text, with that text kept alongside:

```rust
let rv = reading.value().unwrap();
rv.value();       // rust_decimal::Decimal — exact arithmetic
rv.as_str();      // "2935.600" — what the meter wrote
rv.value().scale();  // 3
rv.was_quoted();  // true for the 23 corpus readings that write RV as a string
```

A build guard fails on an `f32` or `f64` anywhere in the library.

## Time

`TM` welds a timestamp and a clock-synchronisation letter into one field:

```text
2018-07-24T13:22:04,000+0200 S
```

The letter is not decoration. It is the difference between a duration that may be
billed and one that may not:

```rust
let t = reading.time().unwrap();
t.unix_millis();                    // computed in-crate: no calendar dependency
t.status;                           // Option<TimeStatus>: U, I, S or R
t.status.unwrap().instant_is_billable();    // only S
t.status.unwrap().duration_is_billable();   // S or R
```

`R` states precisely that the wall-clock start was untrustworthy while the
elapsed duration was recorded to calibration-law requirements. The crate parses
the deviant spellings real stations emit — `±hh:mm` offsets, a `.` millisecond
separator — and reports each one.

## JSON that survives

The specification names no JSON profile: its references cite a web page rather
than RFC 8259. Three consequences shape the reader:

- **Every value keeps its source span**, so nothing is normalised.
- **Duplicate keys are visible.** `{"RV":1,…,"RV":2}` is well-formed under the
  reference the specification actually cites, and different parsers resolve it
  differently — one signed record, two lawful readings of what was measured. The
  crate reports the ambiguity rather than silently choosing.
- **Unknown keys survive at every level**, in order, with their exact text —
  including inside `RD` reading objects, where the specification granted no
  namespace and vendors put extensions anyway.
