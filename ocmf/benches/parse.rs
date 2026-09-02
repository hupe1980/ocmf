//! The performance budget, measured rather than asserted.
//!
//! Records are small — the largest payload in the reference corpus is 932 bytes
//! — so the numbers here should be unembarrassing, and the point of writing
//! them down is that a regression shows up as a number rather than as a
//! complaint from a CSMS ingesting a million records a day.
//!
//! ```console
//! cargo bench -p ocmf --features full,backend-openssl
//! ```

use divan::{Bencher, black_box};
use ocmf::{Limits, Profile, PublicKey, Record};

/// The KEBA KCP30 record from the reference corpus: 391 bytes of payload, two
/// readings — close to the corpus median.
const RECORD: &str = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;

const KEY: &str = "3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE";

fn main() {
    divan::main();
}

/// Reading a record: sections found, JSON scanned, every field typed,
/// carry-forward resolved, deviations collected.
#[divan::bench]
fn parse(bencher: Bencher) {
    bencher.bench(|| Record::parse(black_box(RECORD)).unwrap());
}

/// The same, refusing anything the specification does not permit.
#[divan::bench]
fn parse_strict(bencher: Bencher) {
    bencher.bench(|| {
        let _ = Record::parse_with(black_box(RECORD), Profile::Strict, &Limits::DEFAULT);
    });
}

/// Writing a record back out. It is a `&str` copy, and that is the point.
#[divan::bench]
fn round_trip(bencher: Bencher) {
    bencher.bench(|| {
        let r = Record::parse(black_box(RECORD)).unwrap();
        black_box(r.to_string())
    });
}

/// The record's identity: SHA-256 over the signed span.
#[divan::bench]
fn payload_digest(bencher: Bencher) {
    let record = Record::parse(RECORD).unwrap();
    bencher.bench(|| black_box(record.payload_digest()));
}

/// Reading a public key out of a `SubjectPublicKeyInfo`.
#[divan::bench]
fn parse_key(bencher: Bencher) {
    bencher.bench(|| PublicKey::from_text(black_box(KEY), None).unwrap());
}

/// Verification, end to end from text — dominated by the ECDSA operation, as it
/// should be.
#[divan::bench]
fn parse_and_verify(bencher: Bencher) {
    let key = PublicKey::from_text(KEY, None).unwrap();
    bencher.bench(|| {
        let record = Record::parse(black_box(RECORD)).unwrap();
        ocmf::verify(&record, &key).unwrap();
    });
}

/// Verification alone, with the record already parsed.
#[divan::bench]
fn verify_only(bencher: Bencher) {
    let record = Record::parse(RECORD).unwrap();
    let key = PublicKey::from_text(KEY, None).unwrap();
    bencher.bench(|| ocmf::verify(black_box(&record), &key).unwrap());
}

/// A serialisable report about a record.
#[divan::bench]
fn summary(bencher: Bencher) {
    let record = Record::parse(RECORD).unwrap();
    bencher.bench(|| black_box(record.summary()));
}

/// The JSON layer alone, to separate scanning from typing.
#[divan::bench]
fn json_only(bencher: Bencher) {
    let payload = Record::parse(RECORD).unwrap().payload_text();
    bencher.bench(|| {
        let mut dev = Vec::new();
        ocmf::json::parse(black_box(payload), &Limits::DEFAULT, &mut dev).unwrap()
    });
}

/// One OBIS code, parsed and canonicalised — called once per reading.
#[divan::bench]
fn obis(bencher: Bencher) {
    bencher.bench(|| {
        ocmf::ObisCode::parse(black_box("1-b:1.8.0"))
            .unwrap()
            .canonical()
    });
}

/// One `TM`, parsed — also once per reading.
#[divan::bench]
fn time(bencher: Bencher) {
    bencher.bench(|| {
        let mut dev = Vec::new();
        ocmf::OcmfTime::parse(
            black_box("2019-08-13T10:03:15,000+0000 I"),
            &ocmf::Location::at(0),
            &mut dev,
        )
        .unwrap()
    });
}
