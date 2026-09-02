//! Carrying a record over OCPP, per the OCA application note.
//!
//! `[OCA Signed Meter Values in OCPP v1.0, 2025-02-10]` settles how an OCMF
//! record travels between a charging station and a CSMS in OCPP 1.6, 2.0.1 and
//! 2.1. The container is `SignedMeterValueType`, and three of its four fields
//! are less obvious than they look:
//!
//! - **`signedMeterData` is Base64 of the OCMF string**, not the string itself.
//! - **`signingMethod` may be empty**: "May already be included in the
//!   `signedMeterData` block … If it is already included … then this SHALL be
//!   an empty string". For OCMF it *is* included, in `SA`.
//! - **`publicKey` is Base64 of a colon-composed string**:
//!   `oca:<encoding>:<content-type>:<printed-public-key>`, where the last part
//!   is the key *as printed on the certified meter*. As far as this crate's
//!   author could establish, no other open-source implementation reads or
//!   writes that composition — see [`PublicKey::to_oca_base64`].
//!
//! Where the record goes is settled too, and it depends on how the meter
//! packages readings: start and end in *separate* containers go in two
//! `sampledValue`s with contexts `Transaction.Begin` and `Transaction.End`;
//! both in *one* container go in a single `sampledValue` with context
//! `Transaction.End`. [`MeterValueContext`] names the three.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use ocmf::ocpp::{MeterValueContext, SignedMeterValue};
//! use ocmf::{PublicKey, Record};
//!
//! let text = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
//! let record = Record::parse(text)?;
//! let key = PublicKey::from_text("3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE", record.signature().curve())?;
//!
//! let value = SignedMeterValue::from_record(&record, Some(&key));
//! assert_eq!(value.encoding_method, ocmf::ocpp::ENCODING_METHOD);
//! assert!(value.signing_method.is_empty(), "`SA` already carries it");
//!
//! // The record survives the round trip as the bytes it was signed as.
//! assert_eq!(value.record_text()?, text);
//! assert_eq!(
//!     MeterValueContext::for_record(&record),
//!     MeterValueContext::TransactionEnd,
//! );
//! # Ok(()) }
//! ```

use alloc::string::{String, ToString};

use crate::encoding::{base64_decode, base64_encode};
use crate::error::KeyError;
use crate::key::PublicKey;
use crate::record::{Record, RecordBuf};

/// The value `encodingMethod` takes for this format.
pub const ENCODING_METHOD: &str = "OCMF";

/// Where in a transaction a `sampledValue` sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MeterValueContext {
    /// `Transaction.Begin` — a container holding only the start reading.
    TransactionBegin,
    /// `Transaction.End` — the end reading, or a container holding both.
    TransactionEnd,
    /// `Sample.Periodic` — an intermediate reading.
    SamplePeriodic,
    /// `Sample.Clock` — a clock-aligned reading.
    SampleClock,
}

impl MeterValueContext {
    /// The OCPP string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransactionBegin => "Transaction.Begin",
            Self::TransactionEnd => "Transaction.End",
            Self::SamplePeriodic => "Sample.Periodic",
            Self::SampleClock => "Sample.Clock",
        }
    }

    /// The context a record should be sent under, from its own markers.
    ///
    /// A record holding both the begin and the end goes under
    /// `Transaction.End`, which is what the application note prescribes for a
    /// single container.
    ///
    /// **The transparency container disagrees, and both are right.** The same
    /// record goes into a S.A.F.E. `<value>` with no context and no transaction
    /// id at all, because there the attribute is what
    /// `Verifier.verifyTransaction` *pairs* on and a self-contained record has
    /// nothing to be paired with — see [`crate::xml::Values::from_records`].
    /// One record, two containers, two conventions; neither can borrow the
    /// other's answer.
    #[must_use]
    pub fn for_record(record: &Record<'_>) -> Self {
        let p = record.payload();
        match (p.marks_transaction_begin(), p.marks_transaction_end()) {
            (_, true) => Self::TransactionEnd,
            (true, false) => Self::TransactionBegin,
            (false, false) => Self::SamplePeriodic,
        }
    }
}

/// Whether to put the public key on the wire with the record.
///
/// Mirrors the OCPP configuration variable `PublicKeyWithSignedMeterValue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PublicKeyPolicy {
    /// Never send it; the CSMS knows it or fetches it from `MeterPublicKey`.
    ///
    /// The note warns what this costs: after a meter swap, the keys for
    /// historical transactions are no longer retrievable, "This could be a
    /// compliance issue".
    Never,
    /// Send it with this value.
    #[default]
    Include,
}

/// OCPP's `SignedMeterValueType`, as the application note requires it.
///
/// This is the one type in the crate that is `Deserialize` under the `serde`
/// feature, and the exception proves the rule: the record travels inside it as
/// **Base64 of its own text**, so a round trip through JSON reproduces the
/// signed bytes exactly. There is still no `Deserialize` for
/// [`crate::Record`] itself — see [`mod@crate::summary`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SignedMeterValue {
    /// Base64 of the OCMF record.
    pub signed_meter_data: String,
    /// Empty for OCMF, because `SA` already carries it.
    #[cfg_attr(feature = "serde", serde(default))]
    pub signing_method: String,
    /// `"OCMF"`.
    pub encoding_method: String,
    /// Base64 of `oca:base16:asn1:<hex SPKI>`, or empty.
    #[cfg_attr(feature = "serde", serde(default))]
    pub public_key: String,
}

impl SignedMeterValue {
    /// Packages a record for transmission.
    #[must_use]
    pub fn from_record(record: &Record<'_>, key: Option<&PublicKey>) -> Self {
        Self::from_record_with(record, key, PublicKeyPolicy::default())
    }

    /// Packages a record, choosing whether to include the key.
    #[must_use]
    pub fn from_record_with(
        record: &Record<'_>,
        key: Option<&PublicKey>,
        policy: PublicKeyPolicy,
    ) -> Self {
        let public_key = match (policy, key) {
            (PublicKeyPolicy::Include, Some(k)) => k.to_oca_base64(),
            _ => String::new(),
        };
        Self {
            signed_meter_data: base64_encode(record.as_str().as_bytes()),
            // "If it is already included in the signedMeterData, then this
            // SHALL be an empty string."
            signing_method: String::new(),
            encoding_method: ENCODING_METHOD.to_string(),
            public_key,
        }
    }

    /// The OCMF record text this value carries.
    ///
    /// # Errors
    ///
    /// The Base64 or the UTF-8 inside it was invalid.
    pub fn record_text(&self) -> Result<String, OcppError> {
        let bytes = base64_decode(&self.signed_meter_data).ok_or(OcppError::NotBase64 {
            field: "signedMeterData",
        })?;
        String::from_utf8(bytes).map_err(|_| OcppError::NotUtf8)
    }

    /// The record this value carries, owned and checked.
    ///
    /// The convenient shape: `signedMeterData` is Base64 of the record's text,
    /// so the text has to be materialised before it can be borrowed from, and
    /// a [`RecordBuf`] is the type that owns it. Verification is then
    /// `ocmf::verify(&buf.record()?, &key)`.
    ///
    /// # Errors
    ///
    /// [`OcppError`] when the field is not Base64 or not UTF-8, and
    /// [`OcppError::Record`] when what it holds is not an OCMF record.
    pub fn record(&self) -> Result<RecordBuf, OcppError> {
        RecordBuf::new(
            self.record_text()?,
            crate::Profile::Interop,
            crate::Limits::DEFAULT,
        )
        .map_err(OcppError::Record)
    }

    /// The public key, when one travelled with the record.
    ///
    /// Reads the OCA composition, and — because implementations exist that skip
    /// it — also a plain Base64 or hex key.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when the field is present and unreadable.
    pub fn key(&self, hint: Option<crate::Curve>) -> Result<Option<PublicKey>, KeyError> {
        if self.public_key.is_empty() {
            return Ok(None);
        }
        PublicKey::from_text(&self.public_key, hint).map(Some)
    }
}

/// Something wrong with an OCPP container.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OcppError {
    /// A field that must be Base64 was not.
    #[error("OCPP field `{field}` is not valid Base64")]
    NotBase64 {
        /// The field name.
        field: &'static str,
    },
    /// The decoded `signedMeterData` is not UTF-8, so it is not an OCMF record.
    #[error("the decoded signedMeterData is not UTF-8")]
    NotUtf8,
    /// The decoded `signedMeterData` is text, and is not an OCMF record.
    #[error(transparent)]
    Record(#[from] crate::ParseError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Record;

    const KEBA: &str = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
    const KEBA_KEY: &str = "3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE";

    #[test]
    fn a_record_survives_the_round_trip_through_ocpp_byte_for_byte() {
        let r = Record::parse(KEBA).unwrap();
        let key = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let smv = SignedMeterValue::from_record(&r, Some(&key));

        assert_eq!(smv.encoding_method, "OCMF");
        assert!(smv.signing_method.is_empty(), "SA is inside the record");
        assert_eq!(smv.record_text().unwrap(), KEBA);
        assert_eq!(smv.key(None).unwrap().unwrap(), key);
    }

    #[test]
    fn the_public_key_is_the_oca_composition_and_not_a_bare_key() {
        let r = Record::parse(KEBA).unwrap();
        let key = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let smv = SignedMeterValue::from_record(&r, Some(&key));
        let decoded = String::from_utf8(base64_decode(&smv.public_key).unwrap()).unwrap();
        assert!(decoded.starts_with("oca:base16:asn1:"));
        assert!(decoded.ends_with(&KEBA_KEY.to_lowercase()));
    }

    #[test]
    fn the_never_policy_sends_an_empty_string_not_a_missing_field() {
        let r = Record::parse(KEBA).unwrap();
        let key = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let smv = SignedMeterValue::from_record_with(&r, Some(&key), PublicKeyPolicy::Never);
        assert_eq!(smv.public_key, "");
        assert_eq!(smv.key(None).unwrap(), None);
    }

    #[test]
    fn a_record_holding_both_readings_goes_under_transaction_end() {
        let r = Record::parse(KEBA).unwrap();
        assert_eq!(
            MeterValueContext::for_record(&r),
            MeterValueContext::TransactionEnd
        );
        assert_eq!(
            MeterValueContext::TransactionEnd.as_str(),
            "Transaction.End"
        );
    }

    #[test]
    fn a_begin_only_container_goes_under_transaction_begin() {
        let begin_only = KEBA.replace(r#""TX":"E""#, r#""TX":"C""#);
        let r = Record::parse(&begin_only).unwrap();
        assert_eq!(
            MeterValueContext::for_record(&r),
            MeterValueContext::TransactionBegin
        );
    }

    #[test]
    fn a_plain_base64_key_is_also_accepted_because_implementations_send_one() {
        let key = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let smv = SignedMeterValue {
            signed_meter_data: base64_encode(KEBA.as_bytes()),
            signing_method: String::new(),
            encoding_method: ENCODING_METHOD.to_string(),
            public_key: base64_encode(&key.to_spki()),
        };
        assert_eq!(smv.key(None).unwrap().unwrap(), key);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn the_container_is_the_json_an_ocpp_message_carries() {
        let r = Record::parse(KEBA).unwrap();
        let key = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let smv = SignedMeterValue::from_record(&r, Some(&key));

        let json = serde_json::to_string(&smv).unwrap();
        assert!(json.contains("\"signedMeterData\""), "{json}");
        assert!(json.contains("\"encodingMethod\":\"OCMF\""), "{json}");

        // And back: the record survives the whole trip byte for byte, which is
        // the only reason `Deserialize` is safe on this type at all.
        let back: SignedMeterValue = serde_json::from_str(&json).unwrap();
        assert_eq!(back, smv);
        assert_eq!(back.record_text().unwrap(), KEBA);
    }

    #[test]
    fn the_owned_record_is_the_convenient_way_back() {
        let r = Record::parse(KEBA).unwrap();
        let smv = SignedMeterValue::from_record(&r, None);
        let buf = smv.record().expect("it is a record");
        assert_eq!(buf.as_str(), KEBA);
        assert_eq!(buf.record().unwrap().signed_bytes(), r.signed_bytes());

        let not_a_record = SignedMeterValue {
            signed_meter_data: base64_encode(b"hello"),
            signing_method: String::new(),
            encoding_method: ENCODING_METHOD.to_string(),
            public_key: String::new(),
        };
        assert!(matches!(
            not_a_record.record(),
            Err(OcppError::Record(crate::ParseError::NotOcmf))
        ));
    }

    #[test]
    fn garbage_is_reported_by_field() {
        let smv = SignedMeterValue {
            signed_meter_data: String::from("!!!!"),
            signing_method: String::new(),
            encoding_method: ENCODING_METHOD.to_string(),
            public_key: String::new(),
        };
        assert_eq!(
            smv.record_text().unwrap_err(),
            OcppError::NotBase64 {
                field: "signedMeterData"
            }
        );
    }
}
