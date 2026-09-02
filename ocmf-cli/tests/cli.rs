//! The command line, exercised end to end.
//!
//! The library's tests answer "does this crate read OCMF correctly". These
//! answer the other half: that the tool a manufacturer actually runs before a
//! notified body does says the right thing and **exits with the right status**,
//! because a check that reports a failure and returns 0 is a check nobody's CI
//! notices.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// A real KEBA KCP30 record from the S.A.F.E. reference corpus, and its key.
const KEBA: &str = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
const KEBA_KEY: &str = "3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE";

/// Runs the binary with `stdin`, so no test writes to the user's filesystem.
fn run(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ocmf"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary was built");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("writing stdin");
    child.wait_with_output().expect("the binary ran")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn explain_reports_the_fields_and_the_departures() {
    let out = run(&["explain", "-"], KEBA);
    assert!(out.status.success(), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("KEBA_KCP30"));
    assert!(
        text.contains("serial (absent)"),
        "89 % of records omit `MS`"
    );
    assert!(text.contains("(defaulted; SA absent)"));
    assert!(text.contains("MeterSerialMissing") || text.contains("`MS` is absent"));
    // The value that caused each finding travels with it: "not one the table
    // defines" is half a sentence.
    assert!(text.contains(r#""1-b:1.8.0""#));
}

#[test]
fn explain_under_strict_refuses_and_says_why() {
    let out = run(&["explain", "-", "--profile", "strict"], KEBA);
    assert!(!out.status.success(), "nine records in ten fail Strict");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Strict"), "{err}");
    // …and it says which rule, on stdout, before it gives up.
    assert!(stdout(&out).contains("NOT READ"), "{}", stdout(&out));
}

#[test]
fn explain_json_is_machine_readable_and_keeps_quantities_exact() {
    let out = run(&["explain", "-", "--json"], KEBA);
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let record = &json[0];
    assert_eq!(record["record"], KEBA);
    // A JSON number goes through `f64` in most consumers, and `0.2596` is money.
    assert_eq!(record["readings"][0]["value"], "0.2596");
    assert_eq!(record["readings"][0]["value_scale"], 4);
    assert_eq!(record["pagination"], "T32");
}

#[test]
fn verify_checks_a_real_signature_and_a_tampered_one() {
    let out = run(&["verify", "-", "--key", KEBA_KEY], KEBA);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("VERIFIED"));

    // One tenth of a watt-hour.
    let out = run(
        &["verify", "-", "--key", KEBA_KEY],
        &KEBA.replace("0.2596", "0.2597"),
    );
    assert!(!out.status.success());
    assert!(stdout(&out).contains("NOT VERIFIED"));
}

#[test]
fn verify_json_says_which_key_verified_it_and_what_only_verifying_can_see() {
    let out = run(&["verify", "-", "--key", KEBA_KEY, "--json"], KEBA);
    assert!(out.status.success(), "{}", stdout(&out));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let one = &json[0];
    assert_eq!(one["verified"], true);
    assert_eq!(one["summary"]["verification"]["key_curve"], "secp256r1");
    assert_eq!(
        one["summary"]["verification"]["key"],
        KEBA_KEY.to_lowercase(),
        "a report that says `verified` without saying which key has answered half"
    );
    // The three kinds only a signature check can find are in the list.
    let kinds: Vec<&str> = one["summary"]["deviations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"HighSSignature"), "{kinds:?}");

    // A record that does not verify still produces a report, and still exits
    // non-zero: a check that reports a failure and returns 0 is not a check.
    let out = run(
        &["verify", "-", "--key", KEBA_KEY, "--json"],
        &KEBA.replace("0.2596", "0.2597"),
    );
    assert!(!out.status.success());
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json[0]["verified"], false);
    assert!(
        json[0]["error"]
            .as_str()
            .unwrap()
            .contains("does not verify")
    );
}

#[test]
fn a_record_that_is_not_ocmf_fails_rather_than_reporting_nothing() {
    let out = run(&["explain", "-"], "not a record\n");
    assert!(!out.status.success());
}

#[test]
fn sign_then_verify_is_a_round_trip_through_the_tool() {
    let key = "2a".repeat(32);
    let signed = run(&["sign", "--key", &key], "");
    assert!(
        signed.status.success(),
        "{:?}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let record = stdout(&signed);
    assert!(record.starts_with("OCMF|"));

    // The public key the signer printed on stderr is the one that checks it.
    let stderr = String::from_utf8_lossy(&signed.stderr).into_owned();
    let public = stderr
        .lines()
        .find_map(|l| l.strip_prefix("public key (hex SPKI): "))
        .expect("the signer prints its public key");
    let out = run(&["verify", "-", "--key", public], &record);
    assert!(out.status.success(), "{}", stdout(&out));

    // …and a record this crate signs has nothing to report about itself.
    let out = run(&["explain", "-", "--profile", "strict"], &record);
    assert!(out.status.success(), "{}", stdout(&out));
}

#[test]
fn a_session_is_judged_as_a_sequence_and_not_a_pile_of_records() {
    let one = |page: u32, marker: &str, value: &str, hour: u32| {
        format!(
            r#"OCMF|{{"FV":"1.3","PG":"T{page}","MS":"M-1","IS":true,"IL":"VERIFIED","IF":[],"IT":"NONE","RD":[{{"TM":"2024-03-01T0{hour}:00:00,000+0100 S","TX":"{marker}","RV":{value},"RI":"01-00:B1.08.00*FF","RU":"kWh","EF":"","ST":"G"}}]}}|{{"SD":"00"}}"#
        )
    };
    let clean = format!(
        "{}\n{}\n",
        one(1, "B", "100.000", 8),
        one(2, "E", "129.500", 9)
    );
    let out = run(&["session", "-"], &clean);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("Every check-component rule holds"));
    assert!(stdout(&out).contains("29.500"));

    // Remove the middle record and the pagination says so.
    let gap = format!(
        "{}\n{}\n",
        one(1, "B", "100.000", 8),
        one(3, "E", "129.500", 9)
    );
    let out = run(&["session", "-"], &gap);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("pagination went 1"));
}

#[test]
fn a_fiscal_sequence_is_not_asked_for_markers_it_cannot_carry() {
    // `[OCMF Tab. 2]`: `F` is "fiscal readings, independent of transactions",
    // so these records are forbidden to carry a begin or an end marker. No
    // corpus record exercises this path, so nothing else pins it.
    let one = |pg: u32, rv: &str| {
        format!(
            r#"OCMF|{{"FV":"1.3","PG":"F{pg}","MS":"M-1","RD":[{{"TM":"2024-03-01T0{pg}:00:00,000+0100 S","RV":{rv},"RI":"01-00:B1.08.00*FF","RU":"kWh","EF":"","ST":"G"}}]}}|{{"SD":"00"}}"#
        )
    };
    let out = run(
        &["session", "-"],
        &format!("{}\n{}\n", one(1, "100.000"), one(2, "129.500")),
    );
    assert!(out.status.success(), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("fiscal readings"), "{text}");
    assert!(text.contains("29.500"), "{text}");
    assert!(text.contains("Every check-component rule holds"), "{text}");
}

#[test]
fn session_json_is_machine_readable_and_keeps_quantities_exact() {
    let one = |page: u32, marker: &str, value: &str, hour: u32| {
        format!(
            r#"OCMF|{{"FV":"1.3","PG":"T{page}","MS":"M-1","IS":true,"IL":"VERIFIED","IF":[],"IT":"NONE","RD":[{{"TM":"2024-03-01T0{hour}:00:00,000+0100 S","TX":"{marker}","RV":{value},"RI":"01-00:B1.08.00*FF","RU":"kWh","EF":"","ST":"G"}}]}}|{{"SD":"00"}}"#
        )
    };
    let clean = format!(
        "{}\n{}\n",
        one(1, "B", "100.000", 8),
        one(2, "E", "129.500", 9)
    );
    let out = run(&["session", "-", "--json"], &clean);
    assert!(out.status.success(), "{}", stdout(&out));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json["kind"], "Transaction");
    assert_eq!(
        json["totals"][0]["delta"], "29.500",
        "a string, never an f64"
    );
    assert_eq!(json["worst_clock"], "S");
    assert!(json["findings"].as_array().unwrap().is_empty());

    // A broken sequence still emits the report, and still exits non-zero.
    let gap = format!(
        "{}\n{}\n",
        one(1, "B", "100.000", 8),
        one(3, "E", "129.500", 9)
    );
    let out = run(&["session", "-", "--json"], &gap);
    assert!(!out.status.success());
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json["findings"][0]["finding"], "PaginationBroken");
}

#[test]
fn a_byte_order_mark_is_a_property_of_the_file_and_not_of_the_record() {
    let out = run(&["explain", "-"], &format!("\u{feff}{KEBA}"));
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("KEBA_KCP30"));
}

#[test]
fn the_two_transports_round_trip_through_the_tool() {
    let xml = run(&["to-xml", "-", "--key", KEBA_KEY], KEBA);
    assert!(xml.status.success());
    let container = stdout(&xml);
    assert!(container.contains("<signedData"));

    // The container carries its own key, so `verify` needs no `--key`.
    let out = run(&["verify", "-"], &container);
    assert!(out.status.success(), "{}", stdout(&out));

    let ocpp = run(&["to-ocpp", "-", "--key", KEBA_KEY], KEBA);
    assert!(ocpp.status.success());
    let back = run(&["from-ocpp", "-"], &stdout(&ocpp));
    assert!(
        back.status.success(),
        "{}",
        String::from_utf8_lossy(&back.stderr)
    );
    assert_eq!(stdout(&back).trim_end(), KEBA, "the signed bytes survive");
}

#[test]
fn a_split_session_is_written_as_one_transaction_the_official_tool_can_verify() {
    // The Transparenzsoftware groups `<value>` elements by `transactionId` and
    // then demands exactly one `Transaction.Begin` and one `Transaction.End`.
    // One id per record makes it refuse a pair of perfectly good records.
    let begin = KEBA.replace(r#""TX":"E""#, r#""TX":"C""#);
    let end = KEBA.replace(r#""TX":"B""#, r#""TX":"C""#);
    let out = run(
        &["to-xml", "-", "--key", KEBA_KEY],
        &format!("{begin}\n{end}\n"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let xml = stdout(&out);
    assert_eq!(xml.matches(r#"transactionId="1""#).count(), 2, "{xml}");
    assert!(xml.contains(r#"context="Transaction.Begin""#), "{xml}");
    assert!(xml.contains(r#"context="Transaction.End""#), "{xml}");

    // The records themselves are edited, so they no longer verify — but their
    // bytes must survive the container untouched, which is the other half of
    // what a transparency file is for.
    let back = run(&["explain", "-"], &xml);
    assert!(back.status.success(), "{}", stdout(&back));
    assert!(xml.contains(r#""TX":"C""#), "the record text is verbatim");
}

#[test]
fn a_container_holding_another_format_is_skipped_by_name() {
    // Real transparency files are mixed: 13 of the 247 values S.A.F.E. ships
    // are SML or ISA_EDL. One of them must not take the whole file down.
    let mixed = format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?><values>"#,
            r#"<value><signedData format="SML_EDL40_P" encoding="base64">TEST1</signedData></value>"#,
            r#"<value><signedData format="OCMF" encoding="plain">{}</signedData>"#,
            r#"<publicKey encoding="hex">{}</publicKey></value>"#,
            "</values>"
        ),
        KEBA.replace('&', "&amp;").replace('<', "&lt;"),
        KEBA_KEY,
    );
    let out = run(&["verify", "-"], &mixed);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("VERIFIED"));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("SML_EDL40_P"),
        "and it says which one it skipped: {err}"
    );
}

#[test]
fn curves_names_what_this_build_can_and_cannot_check() {
    let out = run(&["curves"], "");
    assert!(out.status.success());
    let text = stdout(&out);
    for name in [
        "secp192k1",
        "secp192r1",
        "secp256k1",
        "secp256r1",
        "brainpoolP256r1",
        "secp384r1",
        "brainpoolP384r1",
    ] {
        assert!(text.contains(name), "{name} is not listed");
    }
}

#[test]
fn the_published_conformance_suite_passes() {
    let suite = concat!(env!("CARGO_MANIFEST_DIR"), "/../conformance/suite.json");
    let out = run(&["conformance", suite], "");
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("0 failed"));
}
