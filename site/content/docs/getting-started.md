+++
title = "Getting started"
description = "Install the ocmf crate or the command-line tool, parse your first record, and check a signature."
weight = 1
+++

## Install

```toml
[dependencies]
ocmf = "0.1"

# All seven curves, both transports, the session rules:
ocmf = { version = "0.1", features = ["full", "backend-openssl"] }
```

The command-line tool is a separate crate, and ships as a self-contained binary
on every [release](https://github.com/hupe1980/ocmf/releases):

```console
$ cargo install ocmf-cli
```

The library needs Rust 1.88 or newer. It is `#![no_std]` with `alloc`,
`#![forbid(unsafe_code)]`, and has two non-optional dependencies.

## Parse a record

```rust
use ocmf::Record;

let text = std::fs::read_to_string("record.ocmf")?;
let record = Record::parse(&text)?;

// Printing a record reproduces its input, byte for byte.
assert_eq!(record.to_string(), text);

let payload = record.payload();
println!("meter {:?}", payload.meter_serial());
println!("{} reading(s)", payload.readings().len());
```

`Record<'a>` borrows the text it was parsed from; nothing is copied.
`RecordBuf` owns a `String` and re-borrows on demand when you need an owned
value.

## Read the meter values

Readings are grouped per register *after* carry-forward is resolved, because a
record may interleave an import and an export register:

```rust
for series in record.payload().by_register() {
    println!("{}: {:?} {}", series.obis, series.delta(), series.readings.len());
}
```

Every quantity is an exact decimal that remembers how it was written.
`2935.600` states three valid decimal places and keeps all three — see
[Reading records](@/docs/reading-records.md).

## Check a signature

OCMF deliberately does not carry the public key: it reaches a verifier out of
band, from a register, a transparency file or a label on the station. Give the
crate the key and it will tell you whether that key signed those bytes.

```rust
use ocmf::{PublicKey, verify};

let key = PublicKey::from_text(&key_text, record.signature().curve())?;
let verified = verify(&record, &key)?;

println!("{}", verified.algorithm());
for d in verified.deviations() {
    println!("{d}");
}
```

`Verified` has no public constructor. The only way to hold one is to have run
`verify`, which stops a `-> bool` from being checked in one function and ignored
in another.

> [!NOTE]
> A successful verification proves that the holder of one private key produced
> these bytes. It does not prove the key belongs to the charge point the record
> names, that no record was removed from the session, or that the values may be
> billed. [Verifying](@/docs/verifying.md) keeps the four apart.

## From the command line

```console
$ ocmf explain record.ocmf      # fields and deviations, for a human
$ ocmf explain record.ocmf --json
$ ocmf verify container.xml     # key taken from the transparency container
$ ocmf session start.ocmf end.ocmf
$ ocmf curves                   # what this build can check
```

Every command accepts a single record, a file with one record per line, a
S.A.F.E. transparency XML container, or `-` for standard input. The full list is
in the [CLI reference](@/docs/cli.md).
