//! The record: three sections, and the bytes the signature covers.
//!
//! # Finding the sections
//!
//! `[OCMF §Sections]` separates the sections with `|` and says the character
//! "is not allowed within the sections" — a rule the format states and cannot
//! enforce, because `TT` is 250 characters of free text. Every implementation
//! surveyed splits on every pipe and indexes the result, so a record with a
//! pipe inside a tariff name is truncated mid-string, fails to parse, and the
//! evidence is lost.
//!
//! This parser instead **scans the payload as a JSON value** to find where it
//! really ends, then requires the next non-space byte to be the delimiter. Where
//! no pipe hides inside a string the two approaches agree byte for byte; where
//! one does, this one is right.
//!
//! # Structure is fatal; values are not
//!
//! [`Record::parse`] refuses a byte sequence that is not
//! `OCMF|<JSON object>|<JSON object>` — anything else has no payload to be
//! evidence *of*. Everything **inside** those objects is data: a missing `PG`,
//! an `RD` that is not an array, a `TM` nobody can read, an `SA` naming an
//! algorithm the table does not define. Each of those becomes a
//! [`Deviation`] and leaves the typed view honest about what
//! it does not know, because the record is the evidence a dispute turns on and
//! one bad field is not a reason to lose it. A [`Profile`] decides whether the
//! collection is fatal.
//!
//! # The signed span
//!
//! [`Record::signed_bytes`] returns a slice of the input — never a
//! reconstruction. Its bounds are *everything between the first delimiter and
//! the one that ends the payload section*, including any whitespace that
//! follows the delimiter, because that is what the reference implementation's
//! `split("|")[1]` yields and bit-compatibility with the legally recognised
//! verifier is not negotiable.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use ocmf::{Limits, Profile, Record};
//!
//! let text = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
//! let record = Record::parse(text)?;
//!
//! // Printing a record reproduces its input, byte for byte.
//! assert_eq!(record.to_string(), text);
//!
//! // The bytes the signature covers are a slice of `text`, never a rebuild.
//! assert_eq!(record.signed_bytes(), text.split('|').nth(1).unwrap().as_bytes());
//!
//! // This KEBA record omits `MS`, like nine records in ten.
//! assert!(record.payload().meter_serial().is_none());
//! assert!(record.deviations().iter().any(|d| d.is_breach()));
//!
//! // The same record under the profile that answers "will the official tool
//! // take this?" — which does not mind a missing `MS`.
//! Record::parse_with(text, Profile::Reference, &Limits::DEFAULT)?;
//! # Ok(()) }
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::deviation::{Deviation, DeviationKind, Location, Profile, rejected};
use crate::error::ParseError;
use crate::json::{Span, parse_value};
use crate::limits::Limits;
use crate::payload::Payload;
use crate::signature::SignatureSection;

/// The literal header that identifies the format `[OCMF §Header]`.
pub const HEADER: &str = "OCMF";

/// One OCMF record, borrowed from the text it was read from.
#[derive(Debug, Clone)]
pub struct Record<'a> {
    src: &'a str,
    payload_span: Span,
    signature_span: Span,
    public_key_span: Option<Span>,
    payload: Payload<'a>,
    signature: SignatureSection<'a>,
    deviations: Vec<Deviation>,
}

impl<'a> Record<'a> {
    /// Reads a record under [`Profile::Interop`] and the default [`Limits`].
    ///
    /// # Errors
    ///
    /// [`ParseError`] when the record cannot be read at all. Under `Interop`,
    /// departures from the specification are collected into
    /// [`Record::deviations`] rather than raised.
    pub fn parse(src: &'a str) -> Result<Self, ParseError> {
        Self::parse_with(src, Profile::Interop, &Limits::DEFAULT)
    }

    /// Reads a record under an explicit profile and limits.
    ///
    /// # Errors
    ///
    /// [`ParseError::Deviates`] when the profile refuses something the record
    /// does, and the other variants when it cannot be read at all.
    pub fn parse_with(src: &'a str, profile: Profile, limits: &Limits) -> Result<Self, ParseError> {
        if src.len() > limits.record {
            return Err(ParseError::LimitExceeded {
                limit: "record",
                allowed: limits.record,
            });
        }
        let mut dev = Vec::new();

        // Whitespace around the whole record is not part of any section: XML
        // containers routinely put the record on its own line.
        let lead = src.len() - src.trim_start().len();
        let rest = &src[lead..];
        if !rest.starts_with(HEADER) {
            return Err(ParseError::NotOcmf);
        }
        let after_header = lead + HEADER.len();
        if src.as_bytes().get(after_header) != Some(&b'|') {
            return Err(ParseError::MissingDelimiter);
        }

        // ── Payload section ────────────────────────────────────────────────
        let payload_start = after_header + 1;
        let payload_value = parse_value(src, payload_start, limits, &mut dev)?;
        let payload_value_end = payload_value.span().end;
        let payload_end =
            next_delimiter(src, payload_value_end)?.ok_or(ParseError::MissingSignatureSection)?;
        let payload_span = payload_start..payload_end;
        if payload_span.len() > limits.payload {
            return Err(ParseError::LimitExceeded {
                limit: "payload",
                allowed: limits.payload,
            });
        }
        if has_whitespace_outside_strings(&src[payload_span.clone()]) {
            dev.push(Deviation::new(
                DeviationKind::PrettyPrintedPayload,
                Location::at(payload_span.start),
            ));
        }
        // Moved out of the parsed value rather than cloned: the payload tree
        // holds every reading, and deep-copying it to hand it on is most of
        // what a naive parser spends its time doing.
        let payload_obj = match payload_value {
            crate::json::Value::Object(o) => o,
            other => {
                return Err(ParseError::SectionNotAnObject {
                    section: "payload",
                    found: other.kind(),
                });
            }
        };

        // ── Signature section ──────────────────────────────────────────────
        let signature_start = payload_end + 1;
        let signature_value = parse_value(src, signature_start, limits, &mut dev)?;
        let signature_end = next_delimiter(src, signature_value.span().end)?;
        let signature_span = signature_start..signature_end.unwrap_or(src.len());
        let signature_obj = match signature_value {
            crate::json::Value::Object(o) => o,
            other => {
                return Err(ParseError::SectionNotAnObject {
                    section: "signature",
                    found: other.kind(),
                });
            }
        };

        // ── The withdrawn fourth section ───────────────────────────────────
        let public_key_span = match signature_end {
            None => None,
            Some(pipe) => {
                let start = pipe + 1;
                if src[start..].contains('|') {
                    return Err(ParseError::TooManySections);
                }
                dev.push(Deviation::new(
                    DeviationKind::FourthSectionPublicKey,
                    Location::at(start),
                ));
                Some(start..src.len())
            }
        };

        let payload = Payload::from_object(payload_obj, limits, &mut dev);
        let signature = SignatureSection::from_object(signature_obj, &mut dev);
        // The payload sorts the deviations it found; the section scanner's own
        // and the signature section's arrive around them.
        dev.sort_by_key(|d| d.at.offset);

        let refused = rejected(profile, &dev);
        if !refused.is_empty() {
            return Err(ParseError::Deviates(refused));
        }

        Ok(Self {
            src,
            payload_span,
            signature_span,
            public_key_span,
            payload,
            signature,
            deviations: dev,
        })
    }

    /// **The bytes the signature covers**, as a slice of the input.
    ///
    /// Never reconstructed, never re-serialised, never normalised.
    #[must_use]
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.src[self.payload_span.clone()].as_bytes()
    }

    /// The payload section as text.
    #[must_use]
    pub fn payload_text(&self) -> &'a str {
        &self.src[self.payload_span.clone()]
    }

    /// The signature section as text.
    #[must_use]
    pub fn signature_text(&self) -> &'a str {
        &self.src[self.signature_span.clone()]
    }

    /// The record exactly as it arrived.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.src
    }

    /// The typed payload.
    #[must_use]
    pub const fn payload(&self) -> &Payload<'a> {
        &self.payload
    }

    /// The typed signature section.
    #[must_use]
    pub const fn signature(&self) -> &SignatureSection<'a> {
        &self.signature
    }

    /// The withdrawn fourth section's contents, when the record carries one.
    #[must_use]
    pub fn embedded_public_key(&self) -> Option<&'a str> {
        self.public_key_span.clone().map(|s| self.src[s].trim())
    }

    /// Every departure from the specification found while reading this record.
    #[must_use]
    pub fn deviations(&self) -> &[Deviation] {
        &self.deviations
    }

    /// SHA-256 of [`Record::signed_bytes`] — **the record's identity**.
    ///
    /// Not the identity of the record *text*: ECDSA signatures are malleable
    /// and DER admits non-canonical encodings, so one payload can appear under
    /// many distinct `SD` values that all verify. Deduplicating on the text
    /// therefore stores the same reading twice, and in a billing pipeline that
    /// is a double charge. Key on this.
    #[cfg(feature = "digest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
    #[must_use]
    pub fn payload_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.signed_bytes());
        h.finalize().into()
    }
}

impl core::fmt::Display for Record<'_> {
    /// Writes the record exactly as it was read.
    ///
    /// `Record::parse(s)?.to_string() == s`, byte for byte, is a property test.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.src)
    }
}

/// From `from`, skips whitespace and returns the index of the `|` that follows,
/// or `None` at end of input.
fn next_delimiter(src: &str, from: usize) -> Result<Option<usize>, ParseError> {
    let bytes = src.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'|' => return Ok(Some(i)),
            c if c.is_ascii_whitespace() => i += 1,
            _ => return Err(ParseError::TrailingSectionBytes { offset: i }),
        }
    }
    Ok(None)
}

/// Whether a JSON text contains whitespace outside of string literals — which
/// is what "pretty-printed" means for a payload that must not be re-serialised.
fn has_whitespace_outside_strings(s: &str) -> bool {
    let mut in_string = false;
    let mut escaped = false;
    for &c in s.as_bytes() {
        match c {
            _ if escaped => escaped = false,
            b'\\' if in_string => escaped = true,
            b'"' => in_string = !in_string,
            b' ' | b'\t' | b'\n' | b'\r' if !in_string => return true,
            _ => {}
        }
    }
    false
}

/// An owned record.
///
/// Holds the text and re-borrows on demand rather than storing a self-reference:
/// parsing a record is measured in single-digit microseconds, and a crate whose
/// entire premise is "do not disturb the bytes" has no business reaching for
/// `unsafe` to save one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordBuf {
    text: String,
    profile: Profile,
    limits: Limits,
}

impl RecordBuf {
    /// Takes ownership of a record's text, checking that it parses.
    ///
    /// # Errors
    ///
    /// Whatever [`Record::parse_with`] would return.
    pub fn new(text: String, profile: Profile, limits: Limits) -> Result<Self, ParseError> {
        Record::parse_with(&text, profile, &limits)?;
        Ok(Self {
            text,
            profile,
            limits,
        })
    }

    /// Borrows the parsed record.
    ///
    /// # Errors
    ///
    /// Cannot fail in practice — the text parsed once already — but the result
    /// is threaded through rather than unwrapped, because a panic in a
    /// verification path is worse than an error.
    pub fn record(&self) -> Result<Record<'_>, ParseError> {
        Record::parse_with(&self.text, self.profile, &self.limits)
    }

    /// The record's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl core::fmt::Display for RecordBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    const KEBA: &str = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;

    #[test]
    fn a_real_record_round_trips_byte_for_byte() {
        let r = Record::parse(KEBA).unwrap();
        assert_eq!(r.to_string(), KEBA);
    }

    #[test]
    fn the_signed_span_is_exactly_what_the_reference_would_split_out() {
        let r = Record::parse(KEBA).unwrap();
        let naive: Vec<&str> = KEBA.split('|').collect();
        assert_eq!(r.payload_text(), naive[1]);
        assert_eq!(r.signature_text(), naive[2]);
        assert_eq!(r.signed_bytes(), naive[1].as_bytes());
    }

    #[test]
    fn leading_whitespace_from_an_xml_container_does_not_disturb_the_span() {
        let wrapped = alloc::format!("\n        {KEBA}\n");
        let r = Record::parse(&wrapped).unwrap();
        assert_eq!(
            r.payload_text(),
            Record::parse(KEBA).unwrap().payload_text()
        );
        assert_eq!(r.to_string(), wrapped, "and the record still round-trips");
    }

    #[test]
    fn a_pipe_inside_a_tariff_text_does_not_end_the_section() {
        let src = r#"OCMF|{"FV":"1.1","PG":"T1","MS":"x","IS":true,"IF":[],"IT":"NONE","TT":"Tarif|Nacht","RD":[{"TM":"2018-07-24T13:22:04,000+0200 S","TX":"B","RV":1,"RI":"1-b:1.8.0","RU":"kWh","ST":"G"}]}|{"SD":"00"}"#;
        let r = Record::parse(src).unwrap();
        assert_eq!(r.payload().tariff_text(), Some("Tarif|Nacht"));

        // What every `split('|')` implementation would have done instead:
        let naive: Vec<&str> = src.split('|').collect();
        assert_ne!(naive[1], r.payload_text());
        assert!(naive.len() > 3, "the naive split sees four sections");
    }

    #[test]
    fn whitespace_after_the_delimiter_is_part_of_the_signed_bytes() {
        // The reference implementation's split keeps it, so this one must too.
        let src = r#"OCMF| {"FV":"1.0","PG":"T1","MS":"x","IS":true,"IF":[],"IT":"NONE","RD":[{"TM":"2018-07-24T13:22:04,000+0200 S","TX":"B","RV":1,"RI":"1-b:1.8.0","RU":"kWh","ST":"G"}]} |{"SD":"00"}"#;
        let r = Record::parse(src).unwrap();
        assert_eq!(r.payload_text(), src.split('|').nth(1).unwrap());
        assert!(r.payload_text().starts_with(' '));
        assert!(r.payload_text().ends_with(' '));
    }

    #[test]
    fn a_pretty_printed_payload_is_read_and_reported() {
        let src = "OCMF|{\n  \"FV\": \"1.0\",\n  \"PG\": \"T1\",\n  \"MS\": \"x\",\n  \"IS\": true,\n  \"IF\": [],\n  \"IT\": \"NONE\",\n  \"RD\": [{\"TM\":\"2018-07-24T13:22:04,000+0200 S\",\"TX\":\"B\",\"RV\":1,\"RI\":\"1-b:1.8.0\",\"RU\":\"kWh\",\"ST\":\"G\"}]\n}|{\"SD\":\"00\"}";
        let r = Record::parse(src).unwrap();
        assert!(
            r.deviations()
                .iter()
                .any(|d| d.kind == DeviationKind::PrettyPrintedPayload)
        );
        assert_eq!(r.to_string(), src);
        assert_eq!(r.signed_bytes(), src.split('|').nth(1).unwrap().as_bytes());
    }

    #[test]
    fn the_withdrawn_fourth_section_is_read_and_flagged() {
        let src = alloc::format!("{KEBA}|3059301306072A8648CE3D02");
        let r = Record::parse(&src).unwrap();
        assert_eq!(r.embedded_public_key(), Some("3059301306072A8648CE3D02"));
        assert!(
            r.deviations()
                .iter()
                .any(|d| d.kind == DeviationKind::FourthSectionPublicKey)
        );
    }

    #[test]
    fn strict_refuses_what_interop_reports() {
        let err = Record::parse_with(KEBA, Profile::Strict, &Limits::DEFAULT).unwrap_err();
        let ParseError::Deviates(list) = err else {
            panic!("expected a deviation error")
        };
        assert!(
            list.iter()
                .any(|d| d.kind == DeviationKind::MeterSerialMissing)
        );
    }

    #[test]
    fn the_reference_profile_accepts_a_missing_meter_serial() {
        Record::parse_with(KEBA, Profile::Reference, &Limits::DEFAULT)
            .expect("the official tool reads this record");
    }

    #[test]
    fn identity_is_the_payload_digest_not_the_record_text() {
        // The same payload, re-signed with a differently encoded signature.
        let a = Record::parse(KEBA).unwrap();
        let other = KEBA.replace("\"SD\":\"3045", "\"SD\":\"3046");
        let b = Record::parse(&other).unwrap();
        assert_ne!(a.as_str(), b.as_str());
        #[cfg(feature = "digest")]
        assert_eq!(a.payload_digest(), b.payload_digest());
    }

    #[test]
    fn malformed_input_is_refused_by_name() {
        assert!(matches!(Record::parse("nope"), Err(ParseError::NotOcmf)));
        assert!(matches!(
            Record::parse("OCMF"),
            Err(ParseError::MissingDelimiter)
        ));
        assert!(matches!(
            Record::parse(r#"OCMF|{"FV":"1.0"}"#),
            Err(ParseError::MissingSignatureSection)
        ));
        assert!(matches!(
            Record::parse(r#"OCMF|{"FV":"1.0"} x |{"SD":"00"}"#),
            Err(ParseError::TrailingSectionBytes { .. })
        ));
        assert!(matches!(
            Record::parse(r#"OCMF|[]|{"SD":"00"}"#),
            Err(ParseError::SectionNotAnObject {
                section: "payload",
                ..
            })
        ));
    }

    #[test]
    fn an_owned_record_borrows_back() {
        let buf = RecordBuf::new(KEBA.to_string(), Profile::Interop, Limits::DEFAULT).unwrap();
        assert_eq!(
            buf.record()
                .unwrap()
                .payload()
                .pagination()
                .unwrap()
                .to_string(),
            "T32"
        );
        assert_eq!(buf.to_string(), KEBA);
    }
}
