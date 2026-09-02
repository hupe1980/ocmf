//! The S.A.F.E. transparency container.
//!
//! This is the file a driver feeds to the Transparenzsoftware, and producing it
//! is half of what §33 `MessEG` actually asks for: the law does not require a
//! measured value to be *correct*, it requires the affected party to be able to
//! **check** it. A platform that verifies internally and reports "verified" has
//! satisfied nobody.
//!
//! The schema (`values.xsd` in the reference implementation) is small:
//!
//! ```xml
//! <values>
//!   <value transactionId="1" context="Transaction.Begin">
//!     <signedData format="OCMF" encoding="plain">OCMF|…|…</signedData>
//!     <publicKey encoding="hex">3059 3013 …</publicKey>
//!   </value>
//! </values>
//! ```
//!
//! Reading one back matters as much as writing it: the other half of the duty
//! arrives when a driver disputes a bill and sends the file *back*, and an
//! operator has to check its records against their own registry.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use ocmf::xml::Values;
//! use ocmf::{PublicKey, Record};
//!
//! let text = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
//! let record = Record::parse(text)?;
//! let key = PublicKey::from_text("3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE", record.signature().curve())?;
//!
//! let container = Values::from_records([(&record, Some(&key))]);
//! let xml = container.to_xml()?;
//!
//! // A signature is over bytes, so the transport has to be *checked*
//! // transparent rather than assumed to be.
//! let back = Values::parse(&xml)?;
//! assert_eq!(back.entries[0].record()?.signed_bytes(), record.signed_bytes());
//! # Ok(()) }
//! ```

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};

use crate::deviation::Profile;
use crate::encoding::hex_encode_upper;
use crate::key::PublicKey;
use crate::limits::Limits;
use crate::record::Record;

/// One `<value>`: a record and, usually, the key to check it with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValueEntry {
    /// `@transactionId`.
    pub transaction_id: Option<String>,
    /// `@context`, e.g. `Transaction.Begin`.
    pub context: Option<String>,
    /// `<signedData>` — the OCMF record, verbatim.
    pub signed_data: String,
    /// `<signedData @format>`; `OCMF` for this crate.
    pub format: String,
    /// `<signedData @encoding>`; `plain` for OCMF records.
    pub encoding: String,
    /// `<publicKey>`, as written.
    pub public_key: Option<String>,
    /// `<publicKey @encoding>`; `hex` in practice.
    pub public_key_encoding: Option<String>,
}

impl ValueEntry {
    /// Whether this entry claims to carry an **OCMF record as plain text**.
    ///
    /// A transparency container is not an OCMF file: of the 247 `<signedData>`
    /// elements S.A.F.E. ships, 234 are `format="OCMF"`, 11 are
    /// `ISA_EDL_40_P` and 2 are `SML_EDL40_P`. Reading one of the other 13 as
    /// OCMF gets a confusing error about a missing header instead of the true
    /// answer, which is "this value is not this format".
    ///
    /// An **absent** `format` is `true`: the reference leaves the choice to
    /// the user in that case, and the honest thing here is to try and let
    /// [`Self::record`] say what it found.
    ///
    /// The matching follows `SignedData.getFormatAsVerificationType`: trimmed
    /// and case-insensitive.
    #[must_use]
    pub fn is_ocmf(&self) -> bool {
        let format = self.format.trim();
        let encoding = self.encoding.trim();
        (format.is_empty() || format.eq_ignore_ascii_case(FORMAT_OCMF))
            // An OCMF record is already text, so `plain` is the only encoding
            // that leaves one where this crate can read it.
            && (encoding.is_empty() || encoding.eq_ignore_ascii_case(ENCODING_PLAIN))
    }

    /// The record this entry carries, under [`Profile::Interop`] and the
    /// default [`Limits`].
    ///
    /// # Errors
    ///
    /// [`crate::ParseError`] when the element does not hold a readable record.
    pub fn record(&self) -> Result<Record<'_>, crate::ParseError> {
        Record::parse(&self.signed_data)
    }

    /// The record this entry carries, under an explicit profile and limits.
    ///
    /// A transparency file arrives from outside — a driver's download, an
    /// operator's archive — so the caller who wants to bound it, or to ask
    /// "would the official tool take this?", needs somewhere to say so.
    ///
    /// # Errors
    ///
    /// As [`Record::parse_with`].
    pub fn record_with(
        &self,
        profile: Profile,
        limits: &Limits,
    ) -> Result<Record<'_>, crate::ParseError> {
        Record::parse_with(&self.signed_data, profile, limits)
    }

    /// The public key this entry carries, if any.
    ///
    /// `hint` supplies the curve for a key that names none — pass
    /// `record.signature().curve()`.
    ///
    /// # Errors
    ///
    /// [`crate::KeyError`] when the element holds something that is not a key.
    pub fn key(&self, hint: Option<crate::Curve>) -> Result<Option<PublicKey>, crate::KeyError> {
        self.public_key
            .as_deref()
            .map(|t| PublicKey::from_text(t, hint))
            .transpose()
    }
}

/// `@context` for the value that opens a transaction, as
/// `Verifier.verifyTransaction` matches it.
pub const CONTEXT_BEGIN: &str = "Transaction.Begin";
/// `@context` for the value that closes one.
pub const CONTEXT_END: &str = "Transaction.End";
/// `<signedData @format>` for this format.
pub const FORMAT_OCMF: &str = "OCMF";
/// `<signedData @encoding>` for an OCMF record, which travels as its own text.
pub const ENCODING_PLAIN: &str = "plain";

/// A `<values>` document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Values {
    /// The entries, in document order.
    pub entries: Vec<ValueEntry>,
}

/// Something wrong with a transparency container.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum XmlError {
    /// The document is not well-formed.
    #[error("malformed XML: {0}")]
    Malformed(String),
    /// The root element is not `<values>`.
    #[error("the root element is `{0}`, expected `values`")]
    WrongRoot(String),
    /// A [`Limits`] bound was reached.
    #[error("the container exceeds the {limit} limit of {allowed}")]
    LimitExceeded {
        /// Which bound.
        limit: &'static str,
        /// Its value.
        allowed: usize,
    },
}

/// Refuses input past a bound, by name.
fn bound(seen: usize, allowed: usize, limit: &'static str) -> Result<(), XmlError> {
    if seen > allowed {
        return Err(XmlError::LimitExceeded { limit, allowed });
    }
    Ok(())
}

impl Values {
    /// Builds a container from records and their keys.
    ///
    /// # How records become transactions
    ///
    /// `transactionId` is not decoration: the Transparenzsoftware **groups by
    /// it**, and `Verifier.verifyTransaction` then demands exactly one value
    /// with `context = "Transaction.Begin"` and one with `"Transaction.End"`.
    /// Giving each record its own id — which is the obvious thing to do —
    /// produces a file the tool refuses with *"no stop value for transaction
    /// found"*, on records that are individually perfect.
    ///
    /// So the grouping follows what the reference's own 257 test values do,
    /// counted rather than assumed:
    ///
    /// | The record | `transactionId` | `context` | Reference values |
    /// |---|---|---|---:|
    /// | marks a begin **and** an end | none | none | 223 |
    /// | marks a begin only | a new one | `Transaction.Begin` | 9 |
    /// | marks an end only | the open one | `Transaction.End` | 9 |
    /// | marks neither | the open one, if any | none | 22 |
    ///
    /// A record that carries both markers is a whole transaction by itself and
    /// is written as a standalone value — which is what a driver's file looks
    /// like for 223 of the 257 values S.A.F.E. ships. Set the fields on
    /// [`ValueEntry`] directly to say something else.
    #[must_use]
    pub fn from_records<'r>(
        records: impl IntoIterator<Item = (&'r Record<'r>, Option<&'r PublicKey>)>,
    ) -> Self {
        let mut entries = Vec::new();
        let mut open: Option<u64> = None;
        let mut next_id: u64 = 1;

        for (record, key) in records {
            let payload = record.payload();
            let (begins, ends) = (
                payload.marks_transaction_begin(),
                payload.marks_transaction_end(),
            );
            let (transaction_id, context) = match (begins, ends) {
                // A whole transaction in one record: it needs no partner, and
                // giving it an id would make the tool look for one.
                (true, true) => {
                    open = None;
                    (None, None)
                }
                (true, false) => {
                    let id = next_id;
                    next_id += 1;
                    open = Some(id);
                    (Some(id), Some(CONTEXT_BEGIN))
                }
                // An end with nothing open is not half of anything this
                // container can describe, so it is written as it is rather
                // than joined to a transaction that does not exist.
                (false, true) => (open.take(), Some(CONTEXT_END)),
                (false, false) => (open, None),
            };
            entries.push(ValueEntry {
                transaction_id: transaction_id.map(|id| id.to_string()),
                context: context.map(ToString::to_string),
                signed_data: record.as_str().to_string(),
                format: String::from(FORMAT_OCMF),
                encoding: String::from(ENCODING_PLAIN),
                public_key: key.map(|k| hex_encode_upper(&k.to_spki())),
                public_key_encoding: key.map(|_| String::from("hex")),
            });
        }
        Self { entries }
    }

    /// Reads a container under the default [`Limits`].
    ///
    /// # Errors
    ///
    /// [`XmlError`] when the document is malformed, is not a `<values>` file,
    /// or exceeds a bound.
    pub fn parse(xml: &str) -> Result<Self, XmlError> {
        Self::parse_with(xml, &Limits::DEFAULT)
    }

    /// Reads a container under explicit [`Limits`].
    ///
    /// A transparency file arrives from outside — a driver's download, an
    /// operator's archive — so it is bounded like every other input this crate
    /// reads. `Limits::entries` caps the number of `<value>` elements and
    /// `Limits::record` caps the text of any one of them; pass
    /// [`Limits::UNLIMITED`] for a caller that has already bounded its input.
    ///
    /// # Errors
    ///
    /// [`XmlError`] when the document is malformed, is not a `<values>` file,
    /// or exceeds a bound.
    #[allow(clippy::too_many_lines, reason = "one event-driven reader, kept whole")]
    pub fn parse_with(xml: &str, limits: &Limits) -> Result<Self, XmlError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(false);

        let mut entries: Vec<ValueEntry> = Vec::new();
        let mut current: Option<ValueEntry> = None;
        let mut in_signed = false;
        let mut in_key = false;
        let mut text = String::new();
        // The *first* element decides whether this is a container. Accepting a
        // `<values>` nested inside something else would read a record out of a
        // document that is not a transparency file, which is precisely the kind
        // of "we found something that looked right" a verifier must not do.
        let mut root: Option<bool> = None;

        loop {
            match reader
                .read_event()
                .map_err(|e| XmlError::Malformed(e.to_string()))?
            {
                Event::Start(e) | Event::Empty(e) => {
                    let name = e.local_name().as_ref().to_string();
                    if root.is_none() {
                        root = Some(name == "values");
                        if root != Some(true) {
                            return Err(XmlError::WrongRoot(name));
                        }
                        continue;
                    }
                    match name.as_str() {
                        "value" => {
                            let mut entry = ValueEntry::default();
                            for attr in e.attributes().flatten() {
                                let key = attr.key.local_name().as_ref().to_string();
                                let val = attr
                                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                    .map(|v| v.to_string())
                                    .unwrap_or_default();
                                match key.as_str() {
                                    "transactionId" => entry.transaction_id = Some(val),
                                    "context" => entry.context = Some(val),
                                    _ => {}
                                }
                            }
                            current = Some(entry);
                        }
                        "signedData" | "encodedData" => {
                            in_signed = true;
                            text.clear();
                            if let Some(entry) = current.as_mut() {
                                for attr in e.attributes().flatten() {
                                    let key = attr.key.local_name().as_ref().to_string();
                                    let val = attr
                                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                        .map(|v| v.to_string())
                                        .unwrap_or_default();
                                    match key.as_str() {
                                        "format" => entry.format = val,
                                        "encoding" => entry.encoding = val,
                                        _ => {}
                                    }
                                }
                            }
                        }
                        "publicKey" => {
                            in_key = true;
                            text.clear();
                            if let Some(entry) = current.as_mut() {
                                for attr in e.attributes().flatten() {
                                    if attr.key.local_name().as_ref() == "encoding" {
                                        entry.public_key_encoding = attr
                                            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                            .ok()
                                            .map(|v| v.to_string());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Event::Text(t) => {
                    if in_signed || in_key {
                        let raw = t.xml_content(quick_xml::XmlVersion::Implicit1_0);
                        text.push_str(
                            &quick_xml::escape::unescape(&raw)
                                .map_err(|e| XmlError::Malformed(e.to_string()))?,
                        );
                        bound(text.len(), limits.record, "element text")?;
                    }
                }
                Event::CData(t) => {
                    if in_signed || in_key {
                        text.push_str(t.as_ref());
                        bound(text.len(), limits.record, "element text")?;
                    }
                }
                Event::End(e) => {
                    let name = e.local_name().as_ref().to_string();
                    match name.as_str() {
                        "signedData" | "encodedData" => {
                            in_signed = false;
                            if let Some(entry) = current.as_mut() {
                                entry.signed_data = text.trim().to_string();
                            }
                        }
                        "publicKey" => {
                            in_key = false;
                            if let Some(entry) = current.as_mut() {
                                entry.public_key = Some(text.trim().to_string());
                            }
                        }
                        "value" => {
                            if let Some(entry) = current.take() {
                                bound(entries.len() + 1, limits.entries, "entries")?;
                                entries.push(entry);
                            }
                        }
                        _ => {}
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if root.is_none() {
            return Err(XmlError::WrongRoot(String::from("(no element at all)")));
        }
        Ok(Self { entries })
    }

    /// Writes the container.
    ///
    /// # Errors
    ///
    /// Only if the writer itself fails, which it cannot for an in-memory
    /// buffer; the signature is fallible so the type can grow.
    pub fn to_xml(&self) -> Result<String, XmlError> {
        let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
        w.write_event(Event::Start(BytesStart::new("values")))
            .map_err(|e| XmlError::Malformed(e.to_string()))?;

        for entry in &self.entries {
            let mut v = BytesStart::new("value");
            if let Some(id) = &entry.transaction_id {
                v.push_attribute(("transactionId", id.as_str()));
            }
            if let Some(c) = &entry.context {
                v.push_attribute(("context", c.as_str()));
            }
            w.write_event(Event::Start(v))
                .map_err(|e| XmlError::Malformed(e.to_string()))?;

            let mut sd = BytesStart::new("signedData");
            sd.push_attribute(("format", entry.format.as_str()));
            sd.push_attribute(("encoding", entry.encoding.as_str()));
            w.write_event(Event::Start(sd))
                .map_err(|e| XmlError::Malformed(e.to_string()))?;
            w.write_event(Event::Text(BytesText::from_escaped(
                quick_xml::escape::minimal_escape(entry.signed_data.as_str()),
            )))
            .map_err(|e| XmlError::Malformed(e.to_string()))?;
            w.write_event(Event::End(BytesEnd::new("signedData")))
                .map_err(|e| XmlError::Malformed(e.to_string()))?;

            if let Some(key) = &entry.public_key {
                let mut pk = BytesStart::new("publicKey");
                if let Some(enc) = &entry.public_key_encoding {
                    pk.push_attribute(("encoding", enc.as_str()));
                }
                w.write_event(Event::Start(pk))
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
                w.write_event(Event::Text(BytesText::from_escaped(
                    quick_xml::escape::minimal_escape(key.as_str()),
                )))
                .map_err(|e| XmlError::Malformed(e.to_string()))?;
                w.write_event(Event::End(BytesEnd::new("publicKey")))
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
            }

            w.write_event(Event::End(BytesEnd::new("value")))
                .map_err(|e| XmlError::Malformed(e.to_string()))?;
        }
        w.write_event(Event::End(BytesEnd::new("values")))
            .map_err(|e| XmlError::Malformed(e.to_string()))?;

        let bytes = w.into_inner();
        let body = String::from_utf8(bytes).map_err(|e| XmlError::Malformed(e.to_string()))?;
        Ok(alloc::format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{body}\n"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEBA: &str = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
    const KEBA_KEY: &str = "3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE";

    /// A file in the shape the reference implementation ships, spacing and all.
    const REFERENCE_FILE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<values>
<value transactionId="1" context="Transaction.Begin">
        <signedData format="OCMF" encoding="plain" transactionId="29">OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}</signedData>
        <publicKey encoding="hex">3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE</publicKey>
    </value>
</values>"#;

    #[test]
    fn a_reference_container_reads_back_into_a_record_and_a_key() {
        let v = Values::parse(REFERENCE_FILE).unwrap();
        assert_eq!(v.entries.len(), 1);
        let e = &v.entries[0];
        assert_eq!(e.format, "OCMF");
        assert_eq!(e.encoding, "plain");
        assert_eq!(e.context.as_deref(), Some("Transaction.Begin"));

        let r = e.record().unwrap();
        assert_eq!(r.payload().pagination().unwrap().to_string(), "T32");
        let key = e.key(None).unwrap().unwrap();
        assert_eq!(key.curve(), crate::Curve::Secp256r1);

        #[cfg(feature = "curve-p256")]
        crate::verify::verify(&r, &key).expect("and it verifies");
    }

    #[test]
    fn a_container_can_be_read_under_a_chosen_profile() {
        let v = Values::parse(REFERENCE_FILE).unwrap();
        let e = &v.entries[0];
        // The KEBA record omits `MS`, like nine records in ten.
        assert!(
            e.record_with(crate::Profile::Interop, &crate::Limits::DEFAULT)
                .is_ok()
        );
        assert!(
            e.record_with(crate::Profile::Reference, &crate::Limits::DEFAULT)
                .is_ok(),
            "the official tool reads it"
        );
        assert!(
            e.record_with(crate::Profile::Strict, &crate::Limits::DEFAULT)
                .is_err(),
            "and the specification as written does not"
        );
    }

    #[test]
    fn a_container_can_hold_formats_that_are_not_this_one() {
        // 13 of the 247 `<signedData>` elements S.A.F.E. ships are not OCMF.
        // "This value is not this format" is a different answer from "this
        // record has no header", and a reader that cannot tell them apart
        // sends an operator looking for a broken station.
        let mut entry = ValueEntry {
            format: String::from("OCMF"),
            encoding: String::from("plain"),
            ..ValueEntry::default()
        };
        assert!(entry.is_ocmf());
        entry.format = String::from(" ocmf ");
        assert!(
            entry.is_ocmf(),
            "trimmed and case-insensitive, as the Java is"
        );
        entry.format = String::from("SML_EDL40_P");
        assert!(!entry.is_ocmf());
        entry.format = String::new();
        assert!(entry.is_ocmf(), "an absent format is a question, not a no");
        entry.encoding = String::from("base64");
        assert!(!entry.is_ocmf(), "an OCMF record is already text");
    }

    #[test]
    fn a_container_is_bounded_like_every_other_input() {
        // A transparency file arrives from outside; nothing that arrives from
        // outside is read without a bound.
        let one = REFERENCE_FILE
            .split_once("<value")
            .map(|(_, rest)| alloc::format!("<value{}", rest.rsplit_once("</values>").unwrap().0))
            .unwrap();
        let many = alloc::format!("<values>{}</values>", one.repeat(8));
        let err = Values::parse_with(&many, &Limits::DEFAULT.entries(4)).unwrap_err();
        assert_eq!(
            err,
            XmlError::LimitExceeded {
                limit: "entries",
                allowed: 4
            }
        );
        assert_eq!(
            Values::parse_with(&many, &Limits::DEFAULT)
                .unwrap()
                .entries
                .len(),
            8
        );

        let err = Values::parse_with(REFERENCE_FILE, &Limits::DEFAULT.record(16)).unwrap_err();
        assert!(matches!(
            err,
            XmlError::LimitExceeded {
                limit: "element text",
                ..
            }
        ));
    }

    #[test]
    fn a_key_written_in_groups_of_two_bytes_still_reads() {
        let spaced =
            REFERENCE_FILE.replace("3059301306072A8648CE3D02", "3059 3013 0607 2A86 48CE 3D02");
        let v = Values::parse(&spaced).unwrap();
        assert!(v.entries[0].key(None).is_ok());
    }

    #[test]
    fn a_written_container_reads_back_into_the_same_record() {
        let r = Record::parse(KEBA).unwrap();
        let k = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let xml = Values::from_records([(&r, Some(&k))]).to_xml().unwrap();

        assert!(xml.contains(r#"format="OCMF""#));
        // The KEBA record marks both the begin and the end, so it is a whole
        // transaction by itself: no id to group it by, no context to pair it
        // with. That is what 223 of the reference's own 257 values look like.
        assert!(!xml.contains("transactionId"), "{xml}");
        assert!(!xml.contains("context="), "{xml}");

        let back = Values::parse(&xml).unwrap();
        assert_eq!(back.entries[0].record().unwrap().as_str(), KEBA);
        assert_eq!(back.entries[0].key(None).unwrap().unwrap(), k);
    }

    #[test]
    fn a_split_session_becomes_one_transaction_the_official_tool_can_verify() {
        // One id per *record* would make `Verifier.verifyTransaction` see two
        // transactions, each missing half of itself, and refuse a pair of
        // individually perfect records with "no stop value for transaction
        // found".
        let begin = KEBA
            .replace(
                r#"{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}"#,
                r#"{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"C","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}"#,
            );
        let end = KEBA.replace(r#""TX":"B""#, r#""TX":"C""#);
        let (b, e) = (Record::parse(&begin).unwrap(), Record::parse(&end).unwrap());
        assert!(b.payload().marks_transaction_begin() && !b.payload().marks_transaction_end());
        assert!(e.payload().marks_transaction_end() && !e.payload().marks_transaction_begin());

        let values = Values::from_records([(&b, None), (&e, None)]);
        assert_eq!(
            values.entries[0].transaction_id, values.entries[1].transaction_id,
            "one session is one transaction",
        );
        assert_eq!(values.entries[0].context.as_deref(), Some(CONTEXT_BEGIN));
        assert_eq!(values.entries[1].context.as_deref(), Some(CONTEXT_END));

        // …and two sessions are two transactions.
        let more = Values::from_records([(&b, None), (&e, None), (&b, None), (&e, None)]);
        assert_eq!(more.entries[0].transaction_id.as_deref(), Some("1"));
        assert_eq!(more.entries[2].transaction_id.as_deref(), Some("2"));
        assert_ne!(
            more.entries[1].transaction_id,
            more.entries[2].transaction_id
        );
    }

    #[test]
    fn an_intermediate_record_joins_the_transaction_it_sits_inside() {
        let begin = KEBA.replace(r#""TX":"E""#, r#""TX":"C""#);
        let middle = KEBA
            .replace(r#""TX":"B""#, r#""TX":"C""#)
            .replace(r#""TX":"E""#, r#""TX":"C""#);
        let end = KEBA.replace(r#""TX":"B""#, r#""TX":"C""#);
        let rs: Vec<Record<'_>> = [&begin, &middle, &end]
            .iter()
            .map(|t| Record::parse(t).unwrap())
            .collect();
        let values = Values::from_records(rs.iter().map(|r| (r, None)));
        assert_eq!(values.entries[1].transaction_id.as_deref(), Some("1"));
        assert_eq!(values.entries[1].context, None, "no marker, no claim");
        assert_eq!(values.entries[2].context.as_deref(), Some(CONTEXT_END));
    }

    #[test]
    fn the_records_bytes_survive_the_xml_round_trip_exactly() {
        // The signature is over bytes; an XML layer that re-wraps or re-indents
        // the element text would silently invalidate every record it carries.
        let r = Record::parse(KEBA).unwrap();
        let xml = Values::from_records([(&r, None)]).to_xml().unwrap();
        let back = Values::parse(&xml).unwrap();
        assert_eq!(back.entries[0].signed_data, KEBA);
        assert_eq!(
            back.entries[0].record().unwrap().signed_bytes(),
            r.signed_bytes()
        );
    }

    #[test]
    fn the_encoded_data_element_of_older_files_is_read_too() {
        let older = REFERENCE_FILE
            .replace("<signedData", "<encodedData")
            .replace("</signedData>", "</encodedData>");
        let v = Values::parse(&older).unwrap();
        assert!(v.entries[0].record().is_ok());
    }

    #[test]
    fn a_document_that_is_not_a_container_is_refused() {
        // The root element decides, and only the root element.
        assert!(matches!(
            Values::parse("<other/>"),
            Err(XmlError::WrongRoot(name)) if name == "other"
        ));
        assert!(
            matches!(
                Values::parse("<html><values><value/></values></html>"),
                Err(XmlError::WrongRoot(name)) if name == "html"
            ),
            "a container nested in something else is not a container"
        );
        assert!(matches!(
            Values::parse("   \n"),
            Err(XmlError::WrongRoot(_))
        ));
        assert!(
            Values::parse("<values><value>").is_ok(),
            "unclosed is tolerated"
        );
        assert!(
            Values::parse("<values/>").unwrap().entries.is_empty(),
            "an empty container is a container"
        );
    }
}
