+++
title = "FAQ"
description = "Common questions about OCMF and the ocmf Rust crate: what the format is, what a signature proves, why records must not be re-serialised, and how it relates to OCPP and Eichrecht."
weight = 12

[extra]
faq = [
  { q = "What is OCMF?", a = "The Open Charge Metering Format is a text container that a certified meter in an EV charging station puts a reading into and signs. One record is one line: the literal header OCMF, a payload JSON object, and a signature JSON object, separated by pipes. It is specified by S.A.F.E. e.V. and is the working answer to German calibration law (Mess- und Eichrecht) for e-mobility." },
  { q = "What does a valid OCMF signature prove?", a = "That the holder of one private key produced those exact bytes. It does not prove that the key belongs to the charge point the record names, that no record was removed from the session, or that the values may be billed. Those are three separate questions with three separate answers." },
  { q = "Why must an OCMF payload never be re-serialised?", a = "The signature is ECDSA over SHA-256 of the payload section exactly as it was written. Key order, whitespace, number formatting and Unicode escapes all change on a round trip through a typed value, and every one of them changes the digest. Nine records in the S.A.F.E. reference corpus are pretty-printed, so this is not hypothetical." },
  { q = "Which signature algorithms does OCMF define?", a = "Seven, all ECDSA over SHA-256: secp192k1, secp192r1, secp256k1, secp256r1 (the default when the SA field is absent), brainpoolP256r1, secp384r1 and brainpoolP384r1. The ocmf crate verifies four in pure Rust and all seven through an OpenSSL backend." },
  { q = "Does OCMF carry the public key?", a = "No. The specification puts key distribution out of band by design: a key reaches a verifier from a register, a transparency file, an OCPP message or a label on the station. A withdrawn fourth section once carried one, and the crate still reads it while reporting that it is withdrawn." },
  { q = "How does an OCMF record travel over OCPP?", a = "Inside SignedMeterValueType. The signedMeterData field holds Base64 of the OCMF string, signingMethod is empty because SA is already inside the record, encodingMethod is OCMF, and publicKey holds Base64 of a colon-composed oca:base16:asn1: string." },
  { q = "Can I use the ocmf crate on an embedded charge controller?", a = "Yes. It is no_std with alloc, forbids unsafe code, performs no I/O and never asks for the time. CI builds it for thumbv7em-none-eabihf, and the same crate signs on the controller and verifies in the CSMS." },
  { q = "Why not use serde_json to parse the payload?", a = "Because a deserialise-into-a-struct reader loses the three things OCMF needs: the exact source span of every value, the visibility of duplicate keys, and unknown keys at every level. All three are load-bearing for a format whose signature covers the bytes." }
]
+++

## About the format

### What is OCMF?

The **Open Charge Metering Format** is a text container that a certified meter in
an EV charging station puts a reading into and signs, so that a driver can check
months later that the kilowatt-hours on the invoice are the kilowatt-hours the
meter measured. One record is one line:

```text
OCMF|{…payload JSON…}|{…signature JSON…}
```

It is specified by S.A.F.E.&nbsp;e.V. and is the working answer to German
calibration law (<i lang="de">Mess- und Eichrecht</i>) for e-mobility — by now
the de-facto European one.

### What does a valid signature prove?

That the holder of one private key produced *those exact bytes*. It does not
prove that the key belongs to the charge point the record names, that no record
was removed from the session, or that the values may be billed. See
[Verifying](@/docs/verifying.md).

### Why must a payload never be re-serialised?

Because the signature covers the payload section exactly as written. Key order,
whitespace, number formatting and Unicode escapes are all free to change on a
round trip through a typed value, and every one of them changes the digest. Nine
records in the reference corpus are pretty-printed, so this is not hypothetical —
see [the signed-bytes rule](@/docs/the-signed-bytes-rule.md).

### Which signature algorithms does OCMF define?

Seven, all ECDSA over SHA-256: secp192k1, secp192r1, secp256k1, secp256r1
(the default when `SA` is absent), brainpoolP256r1, secp384r1 and
brainpoolP384r1. The [full table](@/docs/verifying.md) says which build covers
which.

### Does OCMF carry the public key?

No — the specification puts key distribution out of band by design. A key reaches
a verifier from a register, a transparency file, an OCPP message or a label on
the station. A withdrawn fourth section once carried one; the crate still reads
it, and reports that it is withdrawn.

### How does a record travel over OCPP?

Inside `SignedMeterValueType`, per the Open Charge Alliance's application note.
The details, including the `oca:base16:asn1:` public-key composition, are in
[Transports](@/docs/transports.md).

## About this crate

### Can I use it on an embedded charge controller? In a browser?

Both. `#![no_std]` with `alloc`, `#![forbid(unsafe_code)]`, no I/O, no clock and
**no randomness** — RFC 6979 signing consults none and verification is
arithmetic over public data. CI builds it for `thumbv7em-none-eabihf` and for
`wasm32-unknown-unknown`, and the same crate signs on the controller, verifies
in the CSMS and runs in the page a driver checks a receipt in. See
[Feature flags](@/docs/feature-flags.md).

### Why not use `serde_json`?

A deserialise-into-a-struct reader loses the three things this format needs: the
exact source span of every value, the visibility of duplicate keys, and unknown
keys at every level. All three are load-bearing when the signature covers the
bytes.

### Why is there no `Deserialize` for `Record`?

A record's only faithful serialisation is its own text. Deriving
`Serialize`/`Deserialize` on `Record` invites exactly the bug this crate exists
to prevent: a struct goes into a database, comes back out, is re-serialised, and
the bytes the signature covers are no longer the bytes that were signed. Store
`Record::as_str()`; for a report about a record, use `Record::summary()`, which is
`Serialize` and carries every quantity as exact text.

### Why does my record report deviations when it is valid?

Because most of them are. 89&nbsp;% of real records omit a field the
specification marks mandatory, and not one OBIS code in the reference corpus is
written the way the table specifies. A `Deviation` is a fact, not a verdict —
and each one says whether it *breaches* the specification or is merely worth
knowing. See [Deviations and profiles](@/docs/deviations-and-profiles.md).

### Will the official Transparenzsoftware accept my record?

Parse it under `Profile::Reference`, or run `ocmf explain --profile reference`.
That profile is bug-for-bug with the reference verifier, including its version
dispatch: a record with `FV` above 1.3 is refused there even though it is
perfectly lawful.

### Will it accept my transparency *file*?

A different question, and the one that is easier to get silently wrong. The tool
groups `<value>` elements by `transactionId` and then demands exactly one
`Transaction.Begin` and one `Transaction.End` per group — so a file that numbers
its records `1, 2, 3…` is refused on records it verifies perfectly one at a
time. `ocmf to-xml` groups them the way S.A.F.E.'s own files are grouped. See
[Transports](@/docs/transports.md).

### Why does `session` say nothing about begin and end markers for my records?

Because they are fiscal. `[OCMF Tab. 2]` defines the `F` pagination context as
"fiscal readings, independent of transactions", so those records are *forbidden*
to carry a marker and asking for one would report a fault against a record for
obeying the specification. `SessionReport::kind()` says which rule set ran, and
the per-register totals become first-to-last rather than begin-to-end. See
[Sessions](@/docs/sessions.md).

### Is this crate certified?

No. It is independent and unofficial: not affiliated with, endorsed by or
certified by S.A.F.E.&nbsp;e.V. or the Open Charge Alliance. It implements a
public format; conformity assessment is a notified body's job.

### What is out of scope?

OCMF's withdrawn binary format, other metering formats (SML, EDL, PCDF, Alfen),
RSA — the specification is ECDSA only — key distribution, and any judgement about
whether a reading may be invoiced. That last one is law, tariffs and a key
registry.
