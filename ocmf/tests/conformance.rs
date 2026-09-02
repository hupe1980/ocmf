//! Runs the published conformance suite against this crate.
//!
//! `conformance/suite.json` is meant to be run by *any* OCMF implementation —
//! see `conformance/README.md`. Running it here is the least this crate can do:
//! a suite its own author cannot pass is not a suite.
//!
//! It is also the regression test with the widest reach. Every value of every
//! closed table, every departure real meters make, every algorithm, and every
//! record that must be refused, in one file that a human can read.

use std::collections::BTreeSet;

#[cfg(feature = "verify")]
use ocmf::PublicKey;
use ocmf::{Limits, Record, json};

#[cfg_attr(
    not(feature = "verify"),
    allow(
        dead_code,
        reason = "a case's key and expected verdict are read only where signatures can be checked; \
                  the other four expectations still run"
    )
)]
struct Case {
    id: String,
    group: String,
    record: String,
    key: Option<String>,
    parses: bool,
    round_trips: bool,
    verifies: Option<bool>,
    deviations: BTreeSet<String>,
    readings: Option<usize>,
    billable: Option<usize>,
}

/// The suite lives at the **workspace** root, not inside this package: it is a
/// deliverable other implementations run, not a crate asset. So it is read at
/// run time rather than `include_str!`d — a published `ocmf` crate has no
/// `conformance/` beside it, and a test that will not compile there is a defect
/// in the artefact.
fn suite_text() -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("conformance/suite.json");
    std::fs::read_to_string(path).ok()
}

/// Every test here is a no-op outside the workspace. In it, the file is always
/// present — `cargo xtask conformance-gen` writes it and CI diffs the result —
/// so a skip means "this is a packaged crate", never "the suite went missing".
macro_rules! suite_or_skip {
    () => {
        match suite_text() {
            Some(raw) => raw,
            None => {
                println!("no conformance/suite.json beside this package: skipping");
                return;
            }
        }
    };
}

fn parse_suite(raw: &str) -> Vec<Case> {
    let mut dev = Vec::new();
    let doc = json::parse(raw, &Limits::UNLIMITED, &mut dev).expect("the suite is JSON");
    let obj = doc.as_object().expect("an object");
    assert_eq!(
        obj.get("version")
            .and_then(json::Value::as_number)
            .map(json::RawNumber::as_str),
        Some("1"),
        "the suite schema is versioned; a bump needs a look at this runner"
    );
    obj.get("cases")
        .unwrap()
        .as_array()
        .unwrap()
        .items
        .iter()
        .map(|c| {
            let o = c.as_object().unwrap();
            let text = |k: &str| {
                o.get(k)
                    .and_then(json::Value::as_str)
                    .map(|s| s.decode().into_owned())
            };
            let e = o.get("expect").unwrap().as_object().unwrap();
            let flag = |k: &str| e.get(k).and_then(json::Value::as_bool);
            let count = |k: &str| {
                e.get(k)
                    .and_then(json::Value::as_number)
                    .and_then(|n| n.as_str().parse::<usize>().ok())
            };
            Case {
                id: text("id").unwrap(),
                group: text("group").unwrap(),
                record: text("record").unwrap(),
                key: text("key"),
                parses: flag("parses").unwrap(),
                round_trips: flag("round_trips").unwrap(),
                verifies: flag("verifies"),
                deviations: e
                    .get("deviations")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .items
                    .iter()
                    .map(|d| d.as_str().unwrap().decode().into_owned())
                    .collect(),
                readings: count("readings"),
                billable: count("billable_readings"),
            }
        })
        .collect()
}

#[test]
fn the_suite_covers_what_it_claims_to_cover() {
    let cases = parse_suite(&suite_or_skip!());
    let ids: BTreeSet<&str> = cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), cases.len(), "case ids must be unique");

    let count = |g: &str| cases.iter().filter(|c| c.group == g).count();
    // One case per value of every closed table, and the tables are big.
    assert!(count("table") >= 90, "table cases: {}", count("table"));
    assert!(
        count("deviation") >= 25,
        "deviation cases: {}",
        count("deviation")
    );
    assert_eq!(count("curve"), 7, "one per algorithm of [OCMF Tab. 22]");
    assert!(count("reject") >= 6, "reject cases: {}", count("reject"));

    // Every meter state, every transaction marker, every identification type.
    for letter in "NGTDRMXIOSEF".chars() {
        assert!(ids.contains(format!("table/meter-state-{letter}").as_str()));
    }
    for letter in "BCXELRAPST".chars() {
        assert!(ids.contains(format!("table/transaction-{letter}").as_str()));
    }
    // And the path the reference corpus never exercises.
    assert!(ids.contains("table/pagination-fiscal"));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one block per expectation the suite states"
)]
fn every_case_holds() {
    #[cfg_attr(not(feature = "verify"), allow(unused_mut))]
    let mut skipped: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for c in parse_suite(&suite_or_skip!()) {
        let parsed = Record::parse(&c.record);
        if parsed.is_ok() != c.parses {
            failures.push(format!(
                "{}: expected parses={}, got {}",
                c.id,
                c.parses,
                parsed.is_ok()
            ));
            continue;
        }
        let Ok(record) = parsed else { continue };

        if (record.to_string() == c.record) != c.round_trips {
            failures.push(format!("{}: round trip is not the identity", c.id));
        }
        if let Some(n) = c.readings
            && record.payload().readings().len() != n
        {
            failures.push(format!(
                "{}: expected {n} readings, got {}",
                c.id,
                record.payload().readings().len()
            ));
        }
        if let Some(n) = c.billable {
            let got = record
                .payload()
                .readings()
                .iter()
                .filter(|r| r.is_billable())
                .count();
            if got != n {
                failures.push(format!(
                    "{}: expected {n} billable readings, got {got}",
                    c.id
                ));
            }
        }
        // Deviations are compared against the *verified* set where a case
        // verifies, because a bare `r||s` and a non-canonical DER encoding are
        // only discoverable while checking the signature. Where verification
        // did not run — no `verify` feature, an unsupported curve — the
        // observed set can only be a subset, and that is what is required.
        // The three bindings below are only ever *reassigned* by the block
        // behind `verify`, so a build without it needs no `mut`.
        #[cfg_attr(
            not(feature = "verify"),
            allow(unused_mut, reason = "reassigned only where signatures are checked")
        )]
        let mut verified_deviations = false;
        #[cfg_attr(not(feature = "verify"), allow(unused_mut))]
        let mut got: BTreeSet<String> = record
            .deviations()
            .iter()
            .map(|d| d.kind.name().to_string())
            .collect();
        #[cfg_attr(not(feature = "verify"), allow(unused_mut))]
        let mut compare_deviations = true;

        #[cfg(feature = "verify")]
        if let (Some(expected), Some(key_text)) = (c.verifies, c.key.as_deref()) {
            let hint = record.signature().curve();
            match PublicKey::from_text(key_text, hint) {
                Ok(key) => match ocmf::verify(&record, &key) {
                    Err(ocmf::VerifyError::Unsupported { algorithm, .. }) => {
                        skipped.push(format!("{}: {algorithm} unavailable in this build", c.id));
                        compare_deviations = false;
                    }
                    Ok(v) => {
                        verified_deviations = true;
                        got = v
                            .deviations()
                            .iter()
                            .map(|d| d.kind.name().to_string())
                            .collect();
                        if !expected {
                            failures.push(format!("{}: expected not to verify, and it did", c.id));
                        }
                    }
                    Err(e) => {
                        if expected {
                            failures.push(format!("{}: expected verifies=true, got {e}", c.id));
                        }
                    }
                },
                Err(e) => failures.push(format!("{}: the case's key does not read: {e}", c.id)),
            }
        }

        if compare_deviations {
            let ok = if verified_deviations {
                got == c.deviations
            } else {
                got.is_subset(&c.deviations)
            };
            if !ok {
                failures.push(format!(
                    "{}: deviations differ\n     expected {:?}\n     got      {got:?}",
                    c.id, c.deviations
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} conformance failure(s):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );

    // A skip is only ever allowed for a curve this build genuinely cannot
    // check. Asserting a *count* would bake one feature combination into the
    // test; asserting the reason holds for every one of them.
    #[cfg(feature = "verify")]
    {
        let supported: BTreeSet<&str> = ocmf::verify::supported_curves()
            .into_iter()
            .map(|c| c.algorithm().as_str())
            .collect();
        for s in &skipped {
            assert!(
                !supported.iter().any(|a| s.contains(a)),
                "skipped a case whose algorithm this build does support: {s}"
            );
        }
        assert_eq!(
            skipped.len(),
            7 - supported.len(),
            "one curve case per algorithm, and only the unavailable ones skip"
        );
    }
    #[cfg(not(feature = "verify"))]
    assert!(
        skipped.is_empty(),
        "nothing verifies in this build, so nothing can be skipped"
    );
}

#[test]
fn the_suite_exercises_every_deviation_this_crate_can_report() {
    // Driven by `DeviationKind::ALL` rather than a list kept by hand: a kind
    // with no case is a rule nobody checks, and a hand-kept list is a list that
    // silently stops covering the newest kind.
    // The one exemption, and it is about the *runner* rather than the record:
    // `ReadingsTruncated` fires when a record holds more readings than the
    // caller's `Limits` allows, so a case for it would pin one implementation's
    // configuration rather than the format. The default bound is 4096 and the
    // largest record ever measured carries six.
    const CONFIGURATION_DEPENDENT: [&str; 1] = ["ReadingsTruncated"];

    let seen: BTreeSet<String> = parse_suite(&suite_or_skip!())
        .into_iter()
        .flat_map(|c| c.deviations)
        .collect();
    let missing: Vec<&str> = ocmf::DeviationKind::ALL
        .iter()
        .map(|k| k.name())
        .filter(|n| !seen.contains(*n))
        .filter(|n| !CONFIGURATION_DEPENDENT.contains(n))
        .collect();
    assert!(
        missing.is_empty(),
        "no conformance case reports {missing:?}"
    );

    // And nothing in the suite names a kind this crate does not have.
    let known: BTreeSet<&str> = ocmf::DeviationKind::ALL.iter().map(|k| k.name()).collect();
    for name in &seen {
        assert!(
            known.contains(name.as_str()),
            "{name} is not a DeviationKind"
        );
    }
}
