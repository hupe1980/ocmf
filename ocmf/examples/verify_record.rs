//! Read a real record, report what it does that the specification does not say
//! it may, and check its signature.
//!
//! ```console
//! cargo run -p ocmf --features full --example verify_record
//! ```

use ocmf::{PublicKey, Record, verify};

/// A KEBA KCP30 record from the S.A.F.E. reference corpus, verbatim.
const RECORD: &str = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;

/// Its public key, as the transparency file writes it: hex, with spaces.
const KEY: &str = "3059 3013 0607 2A86 48CE 3D02 0106 082A 8648 CE3D 0301 0703 4200 043A EEB4 5C39 2357 820A 58FD FB08 57BD 77AD A315 85C6 1C43 0531 DFA5 3B44 0AFB FDD9 5AC8 87C6 58EA 5526 0F80 8F55 CA94 8DF2 35C2 108A 0D6D C7D4 AB1A 5E1A 7955 BE";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let record = Record::parse(RECORD)?;

    // Reading a record and writing it back is the identity function.
    assert_eq!(record.to_string(), RECORD);

    println!(
        "payload is {} bytes, signed as written",
        record.signed_bytes().len()
    );
    for d in record.deviations() {
        println!("  deviation: {d}");
    }

    for series in record.payload().by_register() {
        println!("  {}: Δ {:?}", series.obis, series.delta());
    }

    let key = PublicKey::from_text(KEY, record.signature().curve())?;
    let verified = verify::verify(&record, &key)?;
    println!("verified with {}", verified.algorithm());
    println!(
        "identity: {}",
        ocmf::encoding::hex_encode(&verified.payload_digest())
    );
    Ok(())
}
