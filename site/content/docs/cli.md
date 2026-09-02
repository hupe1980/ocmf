+++
title = "CLI reference"
description = "The ocmf command: explain, verify, session, sign, to-xml, to-ocpp, from-ocpp, conformance and curves."
weight = 9
+++

Download a self-contained binary from the
[releases](https://github.com/hupe1980/ocmf/releases) — OpenSSL is linked
statically, so all seven `[Tab. 22]` algorithms work with nothing else
installed, and the conformance suite travels in the archive beside it. Or build
it, which needs the OpenSSL development headers:

```console
$ cargo install ocmf-cli
```

The binary is called `ocmf`. Every command that takes records accepts a single
record, a file with **one record per line** (blank lines and `#` comments
skipped), a S.A.F.E. transparency XML container, or `-` for standard input.

## `explain`

Prints a record's fields and every departure it makes from the specification,
with the table each one is measured against. This is the check a meter
manufacturer wants before a notified body runs it.

```console
$ ocmf explain record.ocmf
$ ocmf explain fleet.ocmf --profile reference   # will the official tool take these?
$ ocmf explain record.ocmf --json               # the machine-readable report
```

`--profile` is `interop` (default), `reference` or `strict`. Under `strict` the
command exits non-zero when the record breaches the specification.

The JSON report carries the record verbatim plus everything derived from it, with
**every quantity as exact text** — JSON numbers go through `f64` in most
consumers, which is the whole reason the crate has its own number type.

## `verify`

```console
$ ocmf verify record.ocmf --key 3059301306072A8648CE3D02…
$ ocmf verify record.ocmf --key @key.hex
$ ocmf verify container.xml                # the key travels with the record
$ ocmf verify record.ocmf --key @key.hex --json
```

`--key` accepts hex, Base64, an `oca:` composite, or `@path` to read from a file.
Exits non-zero if any record does not verify.

`--json` emits one report per record. It carries the verdict, the record and
everything derived from it, **and the key that gave the verdict** — a report
that says "verified" without saying which key has answered half the question.
It also carries the three deviations only a signature check can find:
`RawSignatureNotDer`, `NonCanonicalDer` and `HighSSignature`.

A container holding another format is **skipped by name** rather than failing
the file: 13 of the 247 values S.A.F.E. ships are SML or ISA_EDL, and "this
value is not this format" is a different answer from "this record has no
header".

## `session`

Runs the check-component rules over a transaction's records, in the order given.

```console
$ ocmf session start.ocmf end.ocmf
$ ocmf session transaction.ocmf --profile reference
$ ocmf session start.ocmf end.ocmf --json     # every quantity as exact text
```

Prints which rule set the sequence is subject to — a fiscal one is not asked for
transaction markers it is forbidden to carry — then the per-register totals, the
weakest clock in the sequence, and every finding. Exits non-zero when the
sequence does not hold together.

## `sign`

Builds and signs a record, for testing a pipeline end to end.

```console
$ ocmf sign --key @test.hex --begin 0.000 --end 29.500
$ ocmf sign --key @test.hex --curve secp384r1
```

`--curve` is `secp256r1` (default), `secp384r1` or `secp256k1`. The record goes
to standard output and the public key to standard error, so a shell pipeline gets
the record and a human gets the key.

> [!WARNING]
> This takes a private scalar on the command line. It is for test keys.

## `to-xml`, `to-ocpp`, `from-ocpp`

```console
$ ocmf to-xml record.ocmf --key @key.hex > transparency.xml
$ ocmf to-ocpp record.ocmf --key @key.hex > smv.json
$ ocmf from-ocpp smv.json
```

`from-ocpp` prints the record and verifies it against the key that travelled with
it, if one did.

## `conformance`

Runs a published conformance suite against this build.

```console
$ ocmf conformance conformance/suite.json
162 case(s): 162 passed, 0 failed, 0 skipped
```

It checks all five stated expectations plus the deviation set. A case this build
cannot answer — an unsupported curve — is reported as *skipped*, never as failed.
See [Conformance](@/docs/conformance.md).

## `curves`

```console
$ ocmf curves
Signature algorithms [OCMF Tab. 22] this build can check:

  yes  ECDSA-secp192k1-SHA256       secp192k1
  yes  ECDSA-secp256k1-SHA256       secp256k1
  yes  ECDSA-secp192r1-SHA256       secp192r1
  yes  ECDSA-secp256r1-SHA256       secp256r1
  yes  ECDSA-brainpool256r1-SHA256  brainpoolP256r1
  yes  ECDSA-secp384r1-SHA256       secp384r1
  yes  ECDSA-brainpool384r1-SHA256  brainpoolP384r1
```
