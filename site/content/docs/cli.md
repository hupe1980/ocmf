+++
title = "CLI reference"
description = "The ocmf command: explain, verify, session, sign, to-xml, to-ocpp, from-ocpp, conformance and curves."
weight = 9
+++

## Install

```console
$ brew install hupe1980/tap/ocmf     # macOS or Linux; `brew info ocmf` shows where the conformance suite is
$ cargo install ocmf-cli             # needs the OpenSSL development headers
```

Or download a self-contained binary from the
[releases](https://github.com/hupe1980/ocmf/releases). OpenSSL is linked
statically, so all seven `[Tab. 22]` algorithms work with nothing else
installed, and the conformance suite ships in the archive.

The binary is called `ocmf`. Every command that takes records accepts a single
record, a file with **one record per line** (blank lines and `#` comments
skipped), a S.A.F.E. transparency XML container, or `-` for standard input.

## `explain`

Prints a record's fields and every departure it makes from the specification,
with the table each one is measured against.

```console
$ ocmf explain record.ocmf
$ ocmf explain fleet.ocmf --profile reference   # would the official tool accept these?
$ ocmf explain record.ocmf --json               # the machine-readable report
```

`--profile` is `interop` (default), `reference` or `strict`. Under `strict` the
command exits non-zero when the record breaches the specification.

The JSON report carries the record verbatim plus everything derived from it,
with **every quantity as exact text**, never a JSON number.

## `verify`

```console
$ ocmf verify record.ocmf --key 3059301306072A8648CE3D02…
$ ocmf verify record.ocmf --key @key.hex
$ ocmf verify container.xml                # the key travels with the record
$ ocmf verify record.ocmf --key @key.hex --json
```

`--key` accepts hex, Base64, an `oca:` composite, or `@path` to read from a
file. `--profile` works as for `explain`. Exits non-zero if any record does not
verify.

`--json` emits one report per record: the verdict, the record and everything
derived from it, **the key that gave the verdict**, and the three deviations
only a signature check can find — `RawSignatureNotDer`, `NonCanonicalDer` and
`HighSSignature`.

A container value in another format (SML, ISA_EDL) is **skipped by name**
rather than reported as a record with no header.

## `session`

Runs the check-component rules over a transaction's records, in the order given.

```console
$ ocmf session start.ocmf end.ocmf
$ ocmf session transaction.ocmf --profile reference
$ ocmf session start.ocmf end.ocmf --json     # every quantity as exact text
```

Prints which rule set applies (transaction or fiscal), the per-register totals,
the weakest clock in the sequence, and every finding. Exits non-zero when the
sequence does not hold together. See [Sessions](@/docs/sessions.md).

## `sign`

Builds and signs a record, for testing a pipeline end to end.

```console
$ ocmf sign --key @test.hex --begin 0.000 --end 29.500
$ ocmf sign --key @test.hex --curve secp384r1 --pagination 7
```

| Flag | Default |
|---|---|
| `--key` | required: the private scalar, hex or `@path` |
| `--curve` | `secp256r1`; also `secp384r1`, `secp256k1`, `brainpool-p256r1`, `brainpool-p384r1` |
| `--pagination` | `1` (`PG` = `T1`) |
| `--meter-serial` | `1TEST00000001` |
| `--obis` | `01-00:B1.08.00*FF` |
| `--begin` / `--end` | `0.000` / `1.000`, exact decimals in kWh |

The record goes to standard output and the public key to standard error. The
192-bit curves are verify-only, so `sign` does not offer them.

> [!WARNING]
> This takes a private scalar on the command line. Use it with test keys only.

## `to-xml`, `to-ocpp`, `from-ocpp`

```console
$ ocmf to-xml record.ocmf --key @key.hex > transparency.xml
$ ocmf to-ocpp record.ocmf --key @key.hex > smv.json
$ ocmf from-ocpp smv.json
```

`to-xml` takes one or more record inputs. `from-ocpp` prints the record and
verifies it against the key that travelled with it, if there is one.

## `conformance`

Runs a conformance suite against this build.

```console
$ ocmf conformance conformance/suite.json
163 case(s): 163 passed, 0 failed, 0 skipped
$ ocmf conformance conformance/suite.json --verbose   # every case, not only failures
```

It checks all five stated expectations plus the deviation set. A case this build
cannot answer (an unsupported curve) is reported as *skipped*, not failed. See
[Conformance](@/docs/conformance.md).

## `curves`

Lists the signature algorithms this build can check.

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
