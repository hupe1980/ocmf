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
p.gateway_id();          // GI; also gateway_serial(), gateway_version()
p.meter_serial();        // MS
p.pagination();          // PG — Option: absent or unreadable is a deviation
p.identification_type(); // IT; also identification_status/level/flags/data()
p.tariff_text();         // TT
p.loss_compensation();   // LC — cable-loss compensation
p.readings();            // RD, carry-forward resolved
p.object();              // the raw JSON, for vendor extensions
```

## Carry-forward

> For the readings, fields that have an identical value to the previous reading
> are omitted. However, this only applies within a signed record.

The rule applies to every field, so `TM`, `RU`, `RT`, `EF` and `ST` carry
forward as `RI` and `TX` do; 205 of 705 readings in the reference corpus have no
`TM` of their own. `Reading` accessors return the resolved value;
`Reading::explicit()` says what the reading actually wrote:

```rust
use ocmf::Explicit;

let r = &record.payload().readings()[1];
r.time();                              // resolved: inherited if omitted
r.explicit().has(Explicit::TIME);      // false — this reading did not write TM
```

Rules that affect billing:

- **`EF` carries forward.** If the first reading is flagged `E` and the second
  omits `EF`, the second reading is still flagged.
- **`RV` and `CL` never carry.** An absent `RV` can mean the reading reports
  only an error, so it stays `None`.
- **`RI` and `RU` carry as a group**, together or not at all.
- **Carry-forward never crosses a record boundary.**

## Registers

A record can interleave several registers (LEM's DCBM writes an import reading,
then an export reading carrying only what changed). `by_register()` groups
readings **after** carry-forward, so an import begin is never paired with an
export end:

```rust
for series in record.payload().by_register() {
    println!("{}", series.obis);          // canonical OBIS form
    series.begin();                        // the reading marked TX = B
    series.end();                          // …or any of the five endings
    series.delta();                        // end − begin, exact, same unit only
}
```

## OBIS codes

The specification writes billing-relevant codes as `01-00:B1.08.00*FF`. No OBIS
code in the reference corpus uses that form. Its 705 readings contain:

| Form | Readings |
|---|---:|
| `1-b:1.8.0` | 462 |
| `1-b:1.9.0` | 200 |
| `1-b:1.8.e` | 14 |
| `01-00:01.08.00.FF` | 6 |
| `1-0:1.8.0`, `1-0:1.8.0*198`, `1-0:1.8.1` | 4 each |
| five more spellings | 2–3 each |

`ObisCode` parses this loose grammar, keeps the original text, and offers a
normal form for comparison:

```rust
let code = reading.obis().unwrap();
code.as_str();          // "1-b:1.8.0", as the station wrote it
code.canonical();       // "01-0B:01.08.00"
code.register();        // Register::ActiveEnergyImport
code.register().is_import();             // Some(true)
code.register().is_device_side();        // mains or after cable-loss compensation
code.register().is_transaction_scoped(); // this transaction, or a lifetime total
```

Groups are compared case-insensitively without leading zeros; no radix is
assumed, since the field mixes hexadecimal (`B1`) and decimal (`*198`) groups.

## Numbers are never floats

A reading states its own precision: `2935.600` has three valid decimal places,
and the specification forbids transforming the representation. Every number is
an exact decimal parsed from the token's text, with that text kept alongside:

```rust
let rv = reading.value().unwrap();
rv.value();       // rust_decimal::Decimal — exact arithmetic
rv.as_str();      // "2935.600" — what the meter wrote
rv.value().scale();  // 3
rv.was_quoted();  // true for the 23 corpus readings that write RV as a string
```

The library contains no `f32` or `f64`; a build check enforces that.

## Time

`TM` welds a timestamp and a clock-synchronisation letter into one field:

```text
2018-07-24T13:22:04,000+0200 S
```

The letter decides what may be billed:

```rust
let t = reading.time().unwrap();
t.unix_millis();                    // computed in-crate: no calendar dependency
t.status;                           // Option<TimeStatus>: U, I, S or R
t.status.unwrap().instant_is_billable();    // only S
t.status.unwrap().duration_is_billable();   // S or R
```

`R` means the wall-clock time is not trustworthy but the elapsed duration is.
The deviant spellings stations emit — `±hh:mm` offsets, a `.` millisecond
separator — are parsed and reported.

## JSON that survives

The specification names no strict JSON profile, so the reader:

- **keeps every value's source span** — nothing is normalised;
- **reports duplicate keys** (`DuplicateKey`) rather than silently choosing one,
  since parsers disagree on `{"RV":1,…,"RV":2}`;
- **keeps unknown keys at every level**, in order and verbatim — including
  vendor extensions inside `RD` reading objects.
