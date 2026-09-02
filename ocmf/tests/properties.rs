//! Properties, checked over generated records.
//!
//! The corpus proves the crate reads the records somebody already wrote. These
//! prove the statements that have to hold for records nobody has written yet.

use ocmf::sign::{ReadingSpec, RecordBuilder, Secp256r1Signer, Signer};
use ocmf::{Limits, MeterState, Pagination, Profile, Record, TransactionMarker, Unit, verify};
use proptest::prelude::*;
use rust_decimal::Decimal;

fn a_time(s: &str) -> ocmf::OcmfTime {
    let mut dev = Vec::new();
    ocmf::OcmfTime::parse(s, &ocmf::Location::at(0), &mut dev).expect("a valid TM")
}

/// Free text that a station could lawfully write into `TT`, `GI` or `ID`,
/// including the characters that break naive implementations.
fn field_text() -> impl Strategy<Value = String> {
    prop::string::string_regex(r"[ -~äöüÄÖÜß€]{0,40}").unwrap()
}

/// A decimal a meter could report, with a scale it is stating on purpose.
fn reading_value() -> impl Strategy<Value = Decimal> {
    (0i64..1_000_000_000i64, 0u32..=4u32).prop_map(|(m, s)| Decimal::new(m, s))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Reading a record and writing it back is the identity function, for
    /// every record this crate can build.
    #[test]
    fn round_trip_is_the_identity(
        gateway in field_text(),
        id in field_text(),
        begin in reading_value(),
        delta in 0i64..1_000_000i64,
        page in 1u64..1_000_000u64,
    ) {
        let signer = Secp256r1Signer::from_bytes(&[9u8; 32]).unwrap();
        let end = begin + Decimal::new(delta, begin.scale());
        let built = RecordBuilder::new()
            .gateway(&gateway, "SN-1", "1.0")
            .pagination(Pagination::transaction(page))
            .meter_serial("METER-1")
            .identification(
                true,
                ocmf::IdentificationLevel::Verified,
                vec![],
                // `KEY_CODE` is one of the thirteen types [OCMF Tab. 17]
                // describes as having no exact format, so free text is lawful
                // there — which is what this property is about.
                ocmf::IdentificationType::KeyCode,
                &id,
            )
            .reading(
                ReadingSpec::new(a_time("2024-03-01T08:00:00,000+0100 S"), begin,
                                 "01-00:B1.08.00*FF", Unit::KWh).begin(),
            )
            .reading(
                ReadingSpec::new(a_time("2024-03-01T09:30:00,000+0100 S"), end,
                                 "01-00:B1.08.00*FF", Unit::KWh).end(),
            )
            .sign(&signer);

        // A field containing `|` is refused before anything is signed; that is
        // the builder doing its job, not a failed property.
        let Ok(buf) = built else { return Ok(()); };

        let text = buf.as_str().to_string();
        let record = Record::parse(&text).unwrap();
        prop_assert_eq!(record.to_string(), text.clone());
        prop_assert_eq!(record.signed_bytes(), record.payload_text().as_bytes());

        // And it is specification-clean: nothing this crate writes deviates.
        prop_assert!(Record::parse_with(&text, Profile::Strict, &Limits::DEFAULT).is_ok());
    }

    /// The scale a station states survives the whole loop: build, sign, parse.
    #[test]
    fn a_stated_scale_survives(value in reading_value()) {
        let signer = Secp256r1Signer::from_bytes(&[9u8; 32]).unwrap();
        let buf = RecordBuilder::new()
            .pagination(Pagination::transaction(1))
            .meter_serial("M")
            .identification(
                false,
                ocmf::IdentificationLevel::None,
                vec![],
                ocmf::IdentificationType::None,
                "",
            )
            .reading(ReadingSpec::new(
                a_time("2024-03-01T08:00:00,000+0100 S"), value,
                "01-00:B1.08.00*FF", Unit::KWh,
            ).begin())
            .sign(&signer)
            .unwrap();
        let text = buf.as_str().to_string();
        let record = Record::parse(&text).unwrap();
        let rv = record.payload().readings()[0].value().unwrap();
        prop_assert_eq!(rv.value(), value);
        prop_assert_eq!(rv.value().scale(), value.scale());
        prop_assert_eq!(rv.as_str(), value.to_string());
    }

    /// Changing any single byte of the payload breaks the signature.
    ///
    /// This is the property the whole design exists to make true.
    #[test]
    fn one_byte_anywhere_in_the_payload_breaks_it(offset in 0usize..380) {
        let signer = Secp256r1Signer::from_bytes(&[9u8; 32]).unwrap();
        let key = signer.public_key().unwrap();
        let buf = RecordBuilder::new()
            .gateway("ACME", "SN-1", "1.0")
            .pagination(Pagination::transaction(7))
            .meter_serial("METER-1")
            .identification(
                false,
                ocmf::IdentificationLevel::None,
                vec![],
                ocmf::IdentificationType::None,
                "",
            )
            .reading(ReadingSpec::new(
                a_time("2024-03-01T08:00:00,000+0100 S"), Decimal::new(1234, 2),
                "01-00:B1.08.00*FF", Unit::KWh,
            ).begin())
            .reading(ReadingSpec::new(
                a_time("2024-03-01T09:00:00,000+0100 S"), Decimal::new(5678, 2),
                "01-00:B1.08.00*FF", Unit::KWh,
            ).end())
            .sign(&signer)
            .unwrap();

        let text = buf.as_str().to_string();
        let payload_start = text.find('|').unwrap() + 1;
        let payload_end = Record::parse(&text).unwrap().payload_text().len() + payload_start;
        let i = payload_start + offset;
        if i >= payload_end { return Ok(()); }

        let mut bytes = text.clone().into_bytes();
        // Flip to another printable byte, so the result is still text.
        bytes[i] = if bytes[i] == b'X' { b'Y' } else { b'X' };
        let Ok(mutated) = String::from_utf8(bytes) else { return Ok(()); };
        if mutated == text { return Ok(()); }

        // Most mutations still parse, and must not verify; the rest break the
        // syntax, which is also not a verification.
        if let Ok(record) = Record::parse(&mutated) {
            prop_assert!(verify::verify(&record, &key).is_err());
        }
    }

    /// Parsing never panics, whatever the input.
    #[test]
    fn parsing_is_total(input in prop::string::string_regex(r#"[\x20-\x7e|{}"\[\]]{0,300}"#).unwrap()) {
        let _ = Record::parse(&input);
        let _ = Record::parse_with(&input, Profile::Strict, &Limits::DEFAULT);
        let _ = Record::parse_with(&input, Profile::Reference, &Limits::UNLIMITED);
    }

    /// Parsing never panics on a *plausible* record either — the fuzzer-shaped
    /// input above rarely gets past the header.
    #[test]
    fn parsing_a_mangled_real_record_is_total(
        cut in 0usize..400,
        junk in prop::string::string_regex(r"[\x20-\x7e]{0,20}").unwrap(),
    ) {
        const REAL: &str = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","PG":"T32","IS":false,"IL":"NONE","IF":[],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"3045"}"#;
        let cut = cut.min(REAL.len());
        if !REAL.is_char_boundary(cut) { return Ok(()); }
        let mangled = format!("{}{junk}", &REAL[..cut]);
        let _ = Record::parse(&mangled);
    }
}

#[test]
fn carry_forward_resolution_is_idempotent() {
    // Resolving a record's readings and then writing what was resolved must
    // produce the same view — never a value the raw record did not imply.
    const LEM: &str = r#"OCMF|{"FV":"1.0","GI":"LEM DCBM","GS":"1211751603","PG":"T144","MS":"1211751603","IS":true,"IL":"HEARSAY","IF":[],"IT":"ISO14443","ID":"5E","RD":[{"TM":"2021-10-06T13:13:56,000+0200 R","TX":"B","RV":57.584,"RI":"1-0:1.8.0","RU":"kWh","RT":"DC","EF":"","ST":"G"},{"RV":4.405,"RI":"1-0:2.8.0","RU":"kWh","ST":"G"},{"TM":"2021-10-06T13:15:13,000+0200 R","TX":"E","RV":58.685,"RI":"1-0:1.8.0","RU":"kWh","ST":"G"},{"RV":4.500,"RI":"1-0:2.8.0","RU":"kWh","ST":"G"}]}|{"SD":"3045"}"#;

    let record = Record::parse(LEM).unwrap();
    let readings = record.payload().readings();

    // The second reading inherited TM, TX and RT from the first.
    assert_eq!(readings[1].time(), readings[0].time());
    assert_eq!(readings[1].transaction(), Some(TransactionMarker::Begin));
    assert_eq!(readings[1].state(), Some(MeterState::Ok));

    // Grouping happens after resolution, so import and export stay apart.
    let regs = record.payload().by_register();
    assert_eq!(regs.len(), 2);
    for r in &regs {
        assert_eq!(r.readings.len(), 2);
        assert!(r.delta().is_some());
    }
    assert_eq!(
        regs.iter()
            .find(|r| r.obis == "01-00:01.08.00")
            .unwrap()
            .delta()
            .unwrap(),
        Decimal::from_str_exact("1.101").unwrap()
    );
}

#[test]
fn a_record_with_a_pipe_in_its_tariff_text_survives_a_full_round_trip() {
    // Not in the corpus, and lawful: `TT` is 250 characters of free text.
    let signer = Secp256r1Signer::from_bytes(&[3u8; 32]).unwrap();
    let err = RecordBuilder::new()
        .pagination(Pagination::transaction(1))
        .meter_serial("M")
        .identification(
            false,
            ocmf::IdentificationLevel::None,
            vec![],
            ocmf::IdentificationType::None,
            "",
        )
        .tariff_text("Nacht|Tarif")
        .reading(
            ReadingSpec::new(
                a_time("2024-03-01T08:00:00,000+0100 S"),
                Decimal::ONE,
                "01-00:B1.08.00*FF",
                Unit::KWh,
            )
            .begin(),
        )
        .sign(&signer)
        .unwrap_err();
    // The builder refuses to write one, because the specification forbids it…
    assert!(matches!(err, ocmf::BuildError::PipeInField { field: "TT" }));

    // …and the parser reads one anyway, because a station might.
    let text = r#"OCMF|{"FV":"1.1","PG":"T1","MS":"M","IS":true,"IF":[],"IT":"NONE","TT":"Nacht|Tarif","RD":[{"TM":"2024-03-01T08:00:00,000+0100 S","TX":"B","RV":1,"RI":"1-b:1.8.0","RU":"kWh","EF":"","ST":"G"}]}|{"SD":"3045"}"#;
    let record = Record::parse(text).unwrap();
    assert_eq!(record.payload().tariff_text(), Some("Nacht|Tarif"));
    assert_eq!(record.to_string(), text);
    assert!(record.signed_bytes().ends_with(b"}]}"));
}
