//! Build a record, sign it deterministically, and check that it reads back.
//!
//! ```console
//! cargo run -p ocmf --features full --example sign_record
//! ```

use ocmf::sign::{ReadingSpec, RecordBuilder, Secp256r1Signer, Signer};
use ocmf::{
    CurrentType, IdentificationFlag, IdentificationLevel, IdentificationType, Limits, Location,
    OcmfTime, Pagination, Profile, Record, Unit, verify,
};
use rust_decimal::Decimal;

fn time(s: &str) -> OcmfTime {
    OcmfTime::parse(s, &Location::at(0), &mut Vec::new()).expect("a valid TM")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // In a real station this is a secure element, reached through
    // `ExternalSigner`; the private key never leaves it.
    let signer = Secp256r1Signer::from_bytes(&[0x2a; 32])?;

    let record = RecordBuilder::new()
        .gateway("ACME CS-1", "SN-4711", "1.0.0")
        .pagination(Pagination::transaction(1))
        .meter("ACME", "M-100", "1ABC0000000001", "2.3")
        .identification(
            true,
            IdentificationLevel::Verified,
            vec![IdentificationFlag::parse("RFID_PLAIN")],
            IdentificationType::Iso14443,
            "1F2D3A4F5506C7",
        )
        .reading(
            ReadingSpec::new(
                time("2024-03-01T08:00:00,000+0100 S"),
                Decimal::from_str_exact("2935.600")?,
                "01-00:B1.08.00*FF",
                Unit::KWh,
            )
            .begin()
            .current_type(CurrentType::Dc),
        )
        .reading(
            ReadingSpec::new(
                time("2024-03-01T09:30:00,000+0100 S"),
                Decimal::from_str_exact("2965.100")?,
                "01-00:B1.08.00*FF",
                Unit::KWh,
            )
            .end()
            .current_type(CurrentType::Dc),
        )
        .sign(&signer)?;

    println!("{record}\n");

    // What this crate writes has nothing to report about itself.
    let text = record.as_str().to_string();
    let parsed = Record::parse_with(&text, Profile::Strict, &Limits::DEFAULT)?;
    let verified = verify::verify(&parsed, &signer.public_key()?)?;
    println!(
        "reads back clean, verifies as {}, {} kWh across the session",
        verified.algorithm(),
        parsed.payload().by_register()[0].delta().unwrap()
    );

    // RFC 6979: signing the same record twice gives the same bytes.
    Ok(())
}
