//! The Open Charge Metering Format (OCMF), read without disturbing the bytes
//! its signature covers.
//!
//! OCMF is the container a certified meter in an EV charging station puts a
//! reading into and signs, so that a driver can check months later that the
//! kilowatt-hours on the invoice are the kilowatt-hours the meter measured. One
//! record is one line of text:
//!
//! ```text
//! OCMF|{…payload JSON…}|{…signature JSON…}
//! ```
//!
//! # The rule everything else follows from
//!
//! The signature is ECDSA over SHA-256 of **the payload section exactly as it
//! was written**. `[OCMF §JSON based OCMF Format]` is explicit: "between signing
//! and validation, the payload section must not be manipulated (removing and
//! adding white spaces), otherwise positive validation is not possible".
//!
//! A parser that deserialises into a struct and re-serialises to verify has
//! already lost — key order, whitespace, number formatting and Unicode escapes
//! are all free to change, and every one of them changes the hash. So
//! [`Record::signed_bytes`] returns a slice of the input, and there is no API
//! anywhere in this crate that produces signable bytes from a typed value.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! let text = r#"OCMF|{"FV":"1.0","PG":"T1","MS":"12345678","IS":true,"IF":[],"IT":"ISO14443","ID":"1F2D3A4F","RD":[{"TM":"2018-07-24T13:22:04,000+0200 S","TX":"B","RV":2935.600,"RI":"1-b:1.8.0","RU":"kWh","EF":"","ST":"G"}]}|{"SD":"3045"}"#;
//!
//! let record = ocmf::Record::parse(text)?;
//!
//! // Reading a record and writing it back is the identity function.
//! assert_eq!(record.to_string(), text);
//!
//! // `2935.600` states three valid decimal places, and keeps them.
//! let reading = &record.payload().readings()[0];
//! assert_eq!(reading.value().unwrap().as_str(), "2935.600");
//! assert_eq!(reading.value().unwrap().value().scale(), 3);
//! # Ok(()) }
//! ```
//!
//! # What real records look like
//!
//! This crate was written from the specification *and* from every OCMF record
//! in the S.A.F.E. reference corpus — 256 records, 705 readings, measured. The
//! specification and the field diverge, a lot:
//!
//! - 89 % of records omit `MS`, which `[OCMF Tab. 3]` marks `1..1`.
//! - 29 % of readings omit `TM`, relying on carry-forward from the reading
//!   before them.
//! - 23 readings write `RV` as a JSON *string*, with leading zeros.
//! - Two records carry a bare 64-byte `r‖s` signature and a public key with no
//!   SEC1 prefix and no `SubjectPublicKeyInfo`. One of them verifies —
//!   and no other implementation, including the reference verifier that ships
//!   it as test data, can check it.
//!
//! So parsing runs in a [`Profile`], and every departure from the specification
//! becomes a [`Deviation`] with a citation rather than an error or a silence:
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! # let text = r#"OCMF|{"FV":"1.0","PG":"T1","IS":true,"IF":[],"IT":"NONE","RD":[{"TM":"2018-07-24T13:22:04,000+0200 S","TX":"B","RV":1,"RI":"1-b:1.8.0","RU":"kWh","ST":"G"}]}|{"SD":"3045"}"#;
//! let record = ocmf::Record::parse(text)?;
//! for d in record.deviations() {
//!     // "`MS` is absent although it is mandatory at byte 5 [OCMF Tab. 3, S.A.F.E. issue #41]"
//!     println!("{d}");
//! }
//! # Ok(()) }
//! ```
//!
//! # What this crate answers, and what it does not
//!
//! | Question | Answered by |
//! |---|---|
//! | Did this key sign these bytes? | [`verify()`] |
//! | Is this key *this charge point's* key? | out of band — a register, the station's display, a contract |
//! | Were records removed from the session? | [`mod@session`] |
//! | May these values be billed? | not here: that is law, tariffs and a key registry |
//!
//! Conflating the four is how a "verified" charging session turns out to be a
//! signed fragment of a session somebody edited.
//!
//! # No I/O, no clock, no randomness, no unsafe
//!
//! `#![no_std]` with `alloc`, `#![forbid(unsafe_code)]`. Nothing here opens a
//! socket, reads a file or asks the time — every instant is an argument — so a
//! fleet's worth of verification is a deterministic unit test, and a dispute
//! from four years ago replays exactly as it happened. Signing is RFC 6979
//! deterministic and verification is arithmetic over public data, so the crate
//! builds for `thumbv7em-none-eabihf` and `wasm32-unknown-unknown` alike.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod der;
pub mod deviation;
pub mod encoding;
pub mod error;
pub mod json;
pub mod key;
pub mod limits;
pub mod number;
pub mod obis;
pub mod payload;
pub mod record;
/// Everything ECDSA needs to know about a signature scalar, derived from the
/// curve's own order. Nothing outside verification and signing has a use for
/// it, and both of those are behind `verify`.
#[cfg(feature = "verify")]
mod scalar;
pub mod signature;
pub mod summary;
pub mod time;

#[cfg(feature = "verify")]
#[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
pub mod verify;

#[cfg(feature = "sign")]
#[cfg_attr(docsrs, doc(cfg(feature = "sign")))]
pub mod sign;

#[cfg(feature = "session")]
#[cfg_attr(docsrs, doc(cfg(feature = "session")))]
pub mod session;

#[cfg(feature = "ocpp")]
#[cfg_attr(docsrs, doc(cfg(feature = "ocpp")))]
pub mod ocpp;

#[cfg(feature = "xml")]
#[cfg_attr(docsrs, doc(cfg(feature = "xml")))]
pub mod xml;

pub use deviation::{Departure, Deviation, DeviationKind, Location, Profile};
pub use error::{BuildError, KeyError, ParseError, VerifyError};
pub use key::PublicKey;
pub use limits::Limits;
pub use number::Number;
pub use obis::{ObisCode, Register};
pub use payload::{
    ChargePointIdType, CurrentType, ErrorFlags, Explicit, IdentificationFlag, IdentificationLevel,
    IdentificationType, LossCompensation, MeterState, Pagination, PaginationContext, Payload,
    Reading, RegisterSeries, TransactionMarker, Unit,
};
pub use record::{HEADER, Record, RecordBuf};
pub use signature::{Curve, SignatureAlgorithm, SignatureEncoding, SignatureSection};
pub use summary::RecordSummary;
pub use time::{OcmfTime, TimeStatus};

#[cfg(feature = "verify")]
pub use verify::{
    Malleability, Verified, VerifyOptions, is_supported, supported_curves, verify, verify_bytes,
    verify_key_text, verify_with,
};

#[cfg(feature = "sign")]
pub use sign::{ExternalSigner, LossCompensationSpec, ReadingSpec, RecordBuilder, Signer};

#[cfg(feature = "session")]
pub use session::{Finding, RegisterTotal, SequenceKind, SessionReport};

/// Quotes a value for an error message, bounding its length.
///
/// Every field in an OCMF record is attacker-influenced text — the reference
/// corpus literally ships JNDI payloads inside a public key field — so nothing
/// unbounded and nothing unescaped ever reaches a message.
pub(crate) fn quote_bounded(s: &str) -> alloc::string::String {
    use core::fmt::Write as _;
    const MAX: usize = 48;
    let mut out = alloc::string::String::with_capacity(MAX + 8);
    out.push('"');
    for (n, c) in s.chars().enumerate() {
        if n >= MAX {
            out.push('…');
            break;
        }
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:04x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn error_messages_do_not_carry_unbounded_or_raw_input() {
        let long: String = core::iter::repeat_n('x', 500).collect();
        let q = quote_bounded(&long);
        assert!(q.chars().count() < 60);
        assert!(q.ends_with("…\""));

        let nasty = quote_bounded("a\"b\\c\u{7}${jndi:ldap://x}");
        assert!(nasty.contains("\\\""));
        assert!(nasty.contains("\\\\"));
        assert!(nasty.contains("\\u{0007}"));
    }
}
