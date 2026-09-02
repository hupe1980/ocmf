+++
title = "Documentation"
description = "How to read, verify, sign and transport OCMF records with the ocmf crate — from a first parse to a full transparency container."
sort_by = "weight"
template = "section.html"
page_template = "page.html"
weight = 1
+++

OCMF — the **Open Charge Metering Format** — is the container a certified meter
in an EV charging station puts a reading into and signs, so that a driver can
check months later that the kilowatt-hours on the invoice are the kilowatt-hours
the meter measured. One record is one line of text:

```text
OCMF|{…payload JSON…}|{…signature JSON…}
```

`ocmf` is an independent Rust implementation of that format. It reads records
deployed meters actually emit, says exactly how they depart from the
specification, verifies them against every algorithm the specification defines,
and builds and signs new ones the same way.

If you are new here, read [Getting started](@/docs/getting-started.md) and then
[The signed-bytes rule](@/docs/the-signed-bytes-rule.md) — the second one
explains a constraint that every other page assumes.
