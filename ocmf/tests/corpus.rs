//! The reference corpus, checked record by record against an independent
//! oracle.
//!
//! `tests/corpus/records.json` holds every OCMF record in the S.A.F.E.
//! Transparenzsoftware test data (Apache-2.0, see `NOTICE`), each with the
//! public key it ships with and **OpenSSL's verdict on it**. OpenSSL is the
//! oracle precisely because it is not this crate: a bug shared between the
//! implementation and its test data would be invisible.
//!
//! What these tests assert is not "the code does what it does". It is:
//!
//! - every real record parses, and reproduces itself byte for byte;
//! - this crate agrees with OpenSSL on all 251 records where a verdict exists
//!   (247 authentic, 4 not);
//! - the field statistics that shaped the design are still true of the data.

use std::collections::BTreeMap;

use ocmf::{Curve, Limits, PublicKey, Record, json};

#[cfg_attr(
    not(feature = "verify"),
    allow(
        dead_code,
        reason = "OpenSSL's verdict is the oracle for verification, and this build does none"
    )
)]
struct Entry {
    source: String,
    record: String,
    key: Option<String>,
    openssl_verified: Option<bool>,
}

fn corpus() -> Vec<Entry> {
    let raw = include_str!("corpus/records.json");
    let mut dev = Vec::new();
    let value = json::parse(raw, &Limits::UNLIMITED, &mut dev).expect("fixture is JSON");
    let obj = value.as_object().expect("fixture is an object");
    let entries = obj.get("entries").unwrap().as_array().unwrap();
    entries
        .items
        .iter()
        .map(|e| {
            let o = e.as_object().unwrap();
            let text = |k: &str| {
                o.get(k)
                    .and_then(json::Value::as_str)
                    .map(|s| s.decode().into_owned())
            };
            Entry {
                source: text("source").unwrap(),
                record: text("record").unwrap(),
                key: text("key"),
                openssl_verified: o.get("openssl_verified").and_then(json::Value::as_bool),
            }
        })
        .collect()
}

#[test]
fn every_real_record_parses() {
    let corpus = corpus();
    assert!(
        corpus.len() > 250,
        "the fixture should hold the whole corpus"
    );
    for e in &corpus {
        Record::parse(&e.record).unwrap_or_else(|err| panic!("{}: {err}", e.source));
    }
}

#[test]
fn every_real_record_reproduces_itself_byte_for_byte() {
    for e in corpus() {
        let r = Record::parse(&e.record).unwrap();
        assert_eq!(r.to_string(), e.record, "{}", e.source);
        assert_eq!(
            r.signed_bytes(),
            e.record.split('|').nth(1).unwrap().as_bytes(),
            "{}: the signed span must match what the reference implementation splits out",
            e.source
        );
    }
}

#[test]
#[cfg(feature = "verify")]
fn this_crate_and_openssl_agree_on_every_record() {
    let mut agreed = 0usize;
    let mut skipped_unsupported = 0usize;
    let mut disagreements = Vec::new();

    for e in corpus() {
        let (Some(key_text), Some(expected)) = (&e.key, e.openssl_verified) else {
            continue;
        };
        let record = Record::parse(&e.record).unwrap();
        let hint = record.signature().curve();
        let Ok(key) = PublicKey::from_text(key_text, hint) else {
            panic!("{}: OpenSSL read this key and we could not", e.source);
        };
        // "Authentic" is `Ok`; every other outcome is "not authentic, and
        // here is why" — a key on the wrong curve and a bad signature are
        // different facts, and both mean the record does not stand. Only
        // `Unsupported` is neither: it means this build cannot tell.
        match ocmf::verify(&record, &key) {
            Err(ocmf::VerifyError::Unsupported { .. }) => skipped_unsupported += 1,
            Ok(_) if expected => agreed += 1,
            Err(_) if !expected => agreed += 1,
            other => disagreements.push(format!(
                "{}: openssl said {expected}, we said {}",
                e.source,
                match other {
                    Ok(_) => "verified".to_string(),
                    Err(err) => err.to_string(),
                }
            )),
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} disagreement(s) with OpenSSL:\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );

    // Without the OpenSSL backend, brainpool and secp192k1 records are named
    // as unsupported rather than failed — and there are exactly five of them.
    #[cfg(feature = "backend-openssl")]
    {
        assert_eq!(skipped_unsupported, 0, "every curve is available");
        assert_eq!(agreed, 251, "247 authentic records and 4 that are not");
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        assert!(
            skipped_unsupported >= 4,
            "brainpool and secp192k1 need the OpenSSL backend"
        );
        assert_eq!(agreed + skipped_unsupported, 251);
    }
}

#[test]
#[cfg(all(feature = "verify", feature = "backend-openssl"))]
fn the_isabellenhuette_record_only_this_crate_can_check() {
    // A bare 64-byte X||Y public key and a bare 64-byte r||s signature, with
    // `SM` absent so the record claims DER. The reference verifier that ships
    // this file cannot read either shape.
    let e = corpus()
        .into_iter()
        .find(|e| e.source.contains("OCMF-receipt-with_publickey_and_data"))
        .expect("the ISA record is in the corpus");

    let key_text = e.key.expect("it ships with a key");
    assert_eq!(key_text.len(), 128, "64 bytes of hex, no SEC1 prefix");

    let record = Record::parse(&e.record).unwrap();
    let hint = record.signature().curve();
    let key = PublicKey::from_text(&key_text, hint).unwrap();
    let verified = ocmf::verify(&record, &key).expect("it is authentic");

    assert!(
        verified
            .deviations()
            .iter()
            .any(|d| d.kind == ocmf::DeviationKind::RawSignatureNotDer),
        "and the crate says so rather than hiding it"
    );
}

/// How often each optional signature-section field is written at all — which
/// is the measurement that decides how much the defaults carry.
#[derive(Default)]
struct SignatureFieldsWritten {
    algorithm: usize,
    encoding: usize,
    mime: usize,
}

#[test]
fn the_measurements_that_shaped_the_design_still_hold() {
    let corpus = corpus();
    let mut records = 0usize;
    let mut readings = 0usize;
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    let mut no_meter_serial = 0usize;
    let mut no_time = 0usize;
    let mut quoted_rv = 0usize;
    let mut pretty = 0usize;
    let mut max_payload = 0usize;
    let mut max_readings = 0usize;
    let mut fiscal = 0usize;
    let mut written = SignatureFieldsWritten::default();
    let mut identification_flags_absent = 0usize;

    for e in &corpus {
        let r = Record::parse(&e.record).unwrap();
        records += 1;
        readings += r.payload().readings().len();
        max_payload = max_payload.max(r.payload_text().len());
        max_readings = max_readings.max(r.payload().readings().len());
        if r.payload().meter_serial().is_none() {
            no_meter_serial += 1;
        }
        if r.payload().pagination().map(|p| p.context()) == Some(ocmf::PaginationContext::Fiscal) {
            fiscal += 1;
        }
        written.algorithm += usize::from(r.signature().algorithm_was_written());
        written.encoding += usize::from(r.signature().encoding_was_written());
        written.mime += usize::from(r.signature().mime_was_written());
        if r.payload().identification_flags().is_none() {
            identification_flags_absent += 1;
        }
        for reading in r.payload().readings() {
            if !reading.explicit().has(ocmf::Explicit::TIME) {
                no_time += 1;
            }
            if reading.value().is_some_and(ocmf::Number::was_quoted) {
                quoted_rv += 1;
            }
        }
        for d in r.deviations() {
            *kinds.entry(d.kind.name()).or_default() += 1;
            if d.kind == ocmf::DeviationKind::PrettyPrintedPayload {
                pretty += 1;
            }
        }
    }

    // The numbers the design was built from. If a future spec revision or a
    // corpus refresh moves one, that is a design input changing, and this test
    // is where it should be noticed.
    assert_eq!(records, 256);
    assert_eq!(readings, 705);
    assert_eq!(no_meter_serial, 229, "89 % of records omit a mandatory MS");
    assert_eq!(
        no_time, 205,
        "29 % of readings rely on carry-forward for TM"
    );
    assert_eq!(quoted_rv, 23, "RV arrives as a JSON string this often");
    assert_eq!(
        pretty, 9,
        "records whose payload must never be re-serialised"
    );
    assert_eq!(
        fiscal, 0,
        "the fiscal pagination context is untested by the corpus"
    );
    // The defaults are what verification actually runs on: 233 of 256 records
    // carry no `SA` at all, and only one record in the world exercises `SE`.
    assert_eq!(
        written.algorithm, 23,
        "records that name their own algorithm"
    );
    assert_eq!(
        written.encoding, 1,
        "records that name their own SD encoding"
    );
    assert_eq!(written.mime, 0, "the field that would announce a raw r||s");
    assert_eq!(
        identification_flags_absent, 12,
        "records with no `IF` at all"
    );
    assert!(max_payload <= 932, "the largest real payload, in bytes");
    assert!(max_readings <= 6, "the largest real reading count");

    // Not one OBIS code in the corpus is written the way [OCMF Tab. 25] says.
    assert!(
        kinds.contains_key("ObisNonCanonical"),
        "kinds seen: {kinds:?}"
    );
}

#[test]
fn not_one_obis_code_in_the_corpus_is_written_the_way_the_table_says() {
    let mut obis: BTreeMap<String, usize> = BTreeMap::new();
    let mut readings = 0usize;
    for e in &corpus() {
        let r = Record::parse(&e.record).unwrap();
        for reading in r.payload().readings() {
            readings += 1;
            if reading.explicit().has(ocmf::Explicit::OBIS)
                && let Some(code) = reading.obis()
            {
                *obis.entry(code.as_str().to_string()).or_default() += 1;
                assert!(
                    !code.is_canonical(),
                    "{}: {code} is written the way [OCMF Tab. 25] specifies, \
                     which no record in the corpus was thought to do",
                    e.source
                );
            }
        }
    }
    assert_eq!(obis.get("1-b:1.8.0"), Some(&462), "obis seen: {obis:?}");
    assert_eq!(obis.get("1-b:1.9.0"), Some(&200));
    assert_eq!(obis.get("1-b:1.8.e"), Some(&14));
    assert_eq!(obis.get("01-00:01.08.00.FF"), Some(&6));
    assert_eq!(
        obis.values().sum::<usize>(),
        readings,
        "every reading names a register, one way or another"
    );
    assert_eq!(
        obis.len(),
        12,
        "distinct spellings, none of them the table's: {obis:?}"
    );
}

#[test]
fn the_corpus_writes_values_the_tables_do_not_define_and_they_are_reported() {
    // Measured, not supposed: `"RU":"sec"` and four spellings of `CT` outside
    // [OCMF Tab. 18]. Each is kept verbatim, is never billable, and is said.
    let mut undefined: BTreeMap<String, usize> = BTreeMap::new();
    let mut id_format = 0usize;
    let mut cp_format = 0usize;
    let mut records_affected = 0usize;
    for e in &corpus() {
        let r = Record::parse(&e.record).unwrap();
        records_affected += usize::from(r.deviations().iter().any(|d| {
            matches!(
                d.kind,
                ocmf::DeviationKind::UndefinedTableValue
                    | ocmf::DeviationKind::IdentificationDataFormat
                    | ocmf::DeviationKind::ChargePointIdFormat
            )
        }));
        for d in r.deviations() {
            let field = d.at.path.clone().unwrap_or_default();
            match d.kind {
                ocmf::DeviationKind::UndefinedTableValue => {
                    // `RD[0].RU` and `RD[1].RU` are the same field.
                    let field = field.rsplit('.').next().unwrap_or(&field).to_string();
                    *undefined.entry(field).or_default() += 1;
                }
                ocmf::DeviationKind::IdentificationDataFormat => id_format += 1,
                ocmf::DeviationKind::ChargePointIdFormat => cp_format += 1,
                _ => {}
            }
        }
    }
    assert_eq!(
        undefined.get("RU"),
        Some(&2),
        "two readings say `sec`: {undefined:?}"
    );
    assert_eq!(
        undefined.get("CT"),
        Some(&7),
        "seven records name a charge-point id type Tab. 18 does not define"
    );
    assert_eq!(
        undefined.len(),
        2,
        "and nothing else in the corpus is outside its table: {undefined:?}"
    );

    // `[OCMF Tab. 17]` states a format for five of its eighteen types, and real
    // records miss it thirteen times: six ISO14443 UIDs of 2 bytes, two of 8,
    // one of 11, two ISO15693 UIDs of 7 bytes where the table says 8, and two
    // EMAIDs of 12 characters where it says 14 or 15. None of them is a reason
    // to refuse the record; all of them are reasons to tell the manufacturer.
    assert_eq!(id_format, 13, "records whose ID does not match its IT");

    // `[OCMF Tab. 18]`: CBIDC is "charge box ID and connector ID …, a space is
    // used as field separator". Eight records declare `CBIDC` and then write
    // `"CI":"CI"` or `"CI":"HTB"` — a charge box with no connector. Nothing
    // read this before, because nothing checked it.
    assert_eq!(cp_format, 8, "CBIDC records with no connector id");

    // 30 findings, spread over 26 records: some carry more than one.
    assert_eq!(
        undefined.values().sum::<usize>() + id_format + cp_format,
        30
    );
    assert_eq!(
        records_affected, 26,
        "records carrying at least one of them"
    );

    // And two rules the corpus does *not* break — asserted so that a corpus
    // refresh that does break them is noticed rather than absorbed.
    for e in &corpus() {
        for d in Record::parse(&e.record).unwrap().deviations() {
            assert_ne!(
                d.kind,
                ocmf::DeviationKind::MandatoryReadingFieldMissing,
                "{}: {d}",
                e.source
            );
            assert_ne!(
                d.kind,
                ocmf::DeviationKind::IdentificationStatusMissing,
                "{}: {d}",
                e.source
            );
        }
    }
}

/// The three rules added after the specification's prose was read again rather
/// than its tables: `IF`'s cardinality, one flag per group, and the
/// conditionally-mandatory serial numbers. Counted here so that a corpus
/// refresh that moves one fails the build rather than the document.
#[test]
fn the_rules_the_specifications_prose_states_are_checked_against_real_records() {
    let mut cardinality = 0usize;
    let mut duplicate_group = 0usize;
    let mut unidentifiable = 0usize;
    for e in &corpus() {
        let r = Record::parse(&e.record).unwrap();
        for d in r.deviations() {
            match d.kind {
                ocmf::DeviationKind::IdentificationFlagsCardinality => cardinality += 1,
                ocmf::DeviationKind::IdentificationFlagsDuplicateGroup => duplicate_group += 1,
                ocmf::DeviationKind::SourceUnidentifiable => unidentifiable += 1,
                _ => {}
            }
        }
    }
    assert_eq!(
        cardinality, 0,
        "`[OCMF Tab. 4]` says 0..4 and the field obeys"
    );
    assert_eq!(
        duplicate_group, 0,
        "no record states two things about one group"
    );
    // `[OCMF §Relation of Serial Numbers, Charge Point and Public Key]`: the
    // meter's serial, or the gateway's, or `CT`/`CI`. A record with none of
    // the three cannot be bound to a key by any route the specification
    // describes — which is the question a signature does not answer.
    assert_eq!(
        unidentifiable, 0,
        "every real record names a serial number or a charge point — the rule \
         holds in the field, which is worth knowing before it is enforced"
    );
}

#[test]
fn every_curve_in_the_corpus_is_one_this_crate_names() {
    let mut seen = BTreeMap::new();
    for e in corpus() {
        let r = Record::parse(&e.record).unwrap();
        let Some(c) = r.signature().curve() else {
            continue;
        };
        *seen.entry(c.name()).or_insert(0usize) += 1;
        if let Some(k) = &e.key
            && let Ok(key) = PublicKey::from_text(k, Some(c))
            && key.curve() != c
        {
            // `second_key_fail_ocmf.xml` exists to demonstrate exactly this:
            // a key on another curve than the record claims. It must be a
            // named mismatch, never a verification failure.
            assert!(
                e.source.contains("fail"),
                "{}: unexpected key/SA mismatch",
                e.source
            );
        }
    }
    // secp192k1 and brainpoolP256r1 are in there — which is why "recognise and
    // refuse" was not an option for this crate.
    assert!(seen.contains_key(Curve::Secp256r1.name()));
    assert!(seen.len() >= 2, "curves seen: {seen:?}");
}
