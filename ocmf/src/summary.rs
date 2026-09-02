//! A serialisable report *about* a record — never the record itself.
//!
//! # Why this is not `impl Serialize for Record`
//!
//! A record's only faithful serialisation is its own text. Deriving
//! `Serialize`/`Deserialize` on [`Record`] would invite exactly the bug this
//! crate exists to prevent: a struct goes into a database, comes back out, is
//! re-serialised, and the bytes the signature covers are no longer the bytes
//! that were signed. There is therefore **no `Deserialize` anywhere in this
//! crate**, and the way to store a record is to store
//! [`Record::as_str`](crate::Record::as_str).
//!
//! What a CSMS, a billing pipeline or a support tool actually wants is a
//! *report*: what the record says, what it deviates from, what it hashes to.
//! That is this module. It owns its data, it is `Serialize`, and it carries the
//! record verbatim alongside so that nothing is lost — but it is documented,
//! named and shaped as a derived view.
//!
//! # Decimals are strings here
//!
//! `RV` states a number of valid decimal places, and JSON numbers go through
//! `f64` in most consumers — which is the whole reason
//! [`Number`](crate::Number) exists. So every quantity in this module is the
//! decimal's **exact text**, with its scale beside it. A consumer that wants
//! arithmetic parses the string; a consumer that wants to display it already
//! has what the meter wrote.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! let text = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
//! let record = ocmf::Record::parse(text)?;
//! let summary = record.summary();
//!
//! // The record travels verbatim; everything else is derived from it.
//! assert_eq!(summary.record, text);
//! assert_eq!(summary.readings.len(), 2);
//!
//! // Every quantity is the decimal's exact text, because a JSON number goes
//! // through `f64` in most consumers and `0.2596` is money.
//! assert_eq!(summary.readings[0].value.as_deref(), Some("0.2596"));
//! assert_eq!(summary.readings[0].value_scale, Some(4));
//! # Ok(()) }
//! ```

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::obis::Register;
use crate::payload::TransactionMarker;
use crate::payload::{Payload, Reading};
use crate::record::Record;
use crate::signature::{SignatureAlgorithm, SignatureEncoding};
use crate::time::TimeStatus;

#[cfg(feature = "serde")]
use serde::Serialize;

/// One departure from the specification, flattened for transport.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct DeviationSummary {
    /// The machine-readable kind, e.g. `MeterSerialMissing`.
    pub kind: String,
    /// `Specification` when the record breaches the specification, `Advisory`
    /// when it does something lawful that a reader still needs to know.
    pub departure: &'static str,
    /// What it means, in a sentence.
    pub message: String,
    /// The offending value, quoted and bounded, where the kind has one.
    pub value: Option<String>,
    /// The table or issue it is measured against.
    pub spec: String,
    /// Byte offset into the record.
    pub offset: usize,
    /// The field or path, when there is one.
    pub path: Option<String>,
}

/// One reading, with carry-forward already resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ReadingSummary {
    /// `TM`, in the canonical `[OCMF Tab. 7]` spelling.
    pub time: Option<String>,
    /// Milliseconds since the Unix epoch, from the record's own offset.
    pub time_unix_millis: Option<i64>,
    /// The clock's synchronisation state: `U`, `I`, `S` or `R`.
    pub time_status: Option<char>,
    /// `TX`.
    pub transaction: Option<char>,
    /// `RV`, exactly as written.
    pub value: Option<String>,
    /// The number of decimal places the meter stated.
    pub value_scale: Option<u32>,
    /// `RI`, as written.
    pub obis: Option<String>,
    /// `RI`, normalised to the `[OCMF Tab. 25]` form.
    pub obis_canonical: Option<String>,
    /// What the register measures, when the code sets say.
    pub register: Option<String>,
    /// `RU`.
    pub unit: Option<String>,
    /// `RT`.
    pub current_type: Option<String>,
    /// `CL`, exactly as written.
    pub cumulated_loss: Option<String>,
    /// `EF`, exactly as written.
    pub error_flags: String,
    /// `ST`.
    pub state: Option<char>,
    /// Whether this reading alone could contribute to a bill: meter good, no
    /// error flag, a value, an energy unit. Necessary, never sufficient.
    pub billable: bool,
    /// Which fields this reading wrote rather than inherited.
    pub explicit: Vec<&'static str>,
}

/// A register's begin, end and difference within one record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct RegisterSummary {
    /// The canonical OBIS code.
    pub obis: String,
    /// What it measures.
    pub register: Option<String>,
    /// `end − begin`, exactly, when both readings exist and share a unit.
    pub delta: Option<String>,
    /// The unit both readings were in.
    pub unit: Option<String>,
    /// How many readings of this register the record carries.
    pub readings: usize,
}

/// The signing component `[OCMF Tab. 1]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct GatewaySummary {
    /// `GI`.
    pub id: Option<String>,
    /// `GS`.
    pub serial: Option<String>,
    /// `GV`.
    pub version: Option<String>,
}

/// The meter `[OCMF Tab. 3]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct MeterSummary {
    /// `MV`.
    pub vendor: Option<String>,
    /// `MM`.
    pub model: Option<String>,
    /// `MS`, which `[OCMF Tab. 3]` marks `1..1` and 89 % of real records omit.
    pub serial: Option<String>,
    /// `MF`.
    pub firmware: Option<String>,
}

/// The charge point `[OCMF Tab. 6]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ChargePointSummary {
    /// `CT`.
    pub id_type: String,
    /// `CI`.
    pub id: Option<String>,
}

/// Cable-loss compensation `[OCMF Tab. 24]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LossCompensationSummary {
    /// `LN`.
    pub name: Option<String>,
    /// `LI`, exactly as written.
    pub id: Option<String>,
    /// `LR`, exactly as written. Mandatory in `[OCMF Tab. 24]`, and absent from
    /// records that break it.
    pub resistance: Option<String>,
    /// `LU`. Mandatory on the same terms.
    pub unit: Option<String>,
}

/// The user assignment `[OCMF Tab. 4]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct IdentificationSummary {
    /// `IS`.
    pub assigned: Option<bool>,
    /// `IL`.
    pub level: Option<String>,
    /// Whether `IL` reports an error state.
    pub level_is_error: bool,
    /// `IF`.
    pub flags: Vec<String>,
    /// `IT`.
    pub kind: Option<String>,
    /// `ID`.
    pub data: Option<String>,
    /// `TT`.
    pub tariff_text: Option<String>,
}

/// A report about one record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct RecordSummary {
    /// **The record, verbatim.** The only field that round-trips; everything
    /// else here is derived from it.
    pub record: String,
    /// SHA-256 of the signed span, lower-case hex — the record's identity.
    #[cfg(feature = "digest")]
    pub payload_digest: String,
    /// How many bytes the signature covers.
    pub signed_bytes: usize,
    /// The algorithm in force, from `SA` or its default. `None` when `SA` names
    /// something `[OCMF Tab. 22]` does not define.
    pub algorithm: Option<SignatureAlgorithm>,
    /// `SA` exactly as written, when the record wrote one.
    pub algorithm_text: Option<String>,
    /// Whether `SA` was actually written.
    pub algorithm_written: bool,
    /// The encoding in force, from `SE` or its default. `None` when `SE` names
    /// something `[OCMF Tab. 8]` does not define.
    pub signature_encoding: Option<SignatureEncoding>,
    /// Whether `SD` decoded at all.
    pub signature_readable: bool,
    /// `FV`.
    pub format_version: Option<String>,
    /// `GI`, `GS`, `GV`.
    pub gateway: GatewaySummary,
    /// `MV`, `MM`, `MS`, `MF`.
    pub meter: MeterSummary,
    /// `PG`, as written. `None` when it is absent or unreadable.
    pub pagination: Option<String>,
    /// Which counter `PG` belongs to: `Transaction`, `Fiscal`, or the letter
    /// the record wrote.
    pub pagination_context: Option<String>,
    /// `CF`.
    pub charge_controller_firmware: Option<String>,
    /// `CT` and `CI`.
    pub charge_point: Option<ChargePointSummary>,
    /// `LC`.
    pub loss_compensation: Option<LossCompensationSummary>,
    /// The user assignment, when the record has a transaction reference.
    pub identification: Option<IdentificationSummary>,
    /// The readings, carry-forward resolved.
    pub readings: Vec<ReadingSummary>,
    /// The readings grouped per register.
    pub registers: Vec<RegisterSummary>,
    /// Vendor extension keys, in source order: `UCPN` at the top level,
    /// `RD[0].UC` inside a reading.
    ///
    /// These sit **inside the signature** and are dropped by every reader that
    /// models only the extension points the specification reserves — which are
    /// at the payload's top level, and not where extensions actually occur.
    pub extensions: Vec<String>,
    /// The withdrawn fourth section's contents, when the record carries one.
    pub embedded_public_key: Option<String>,
    /// Whether the signature was checked, and what it said.
    ///
    /// `None` from [`Record::summary`], which reads a record and does not
    /// verify it; `Some` from [`Verified::summary`](crate::Verified::summary),
    /// where the answer exists.
    pub verification: Option<VerificationSummary>,
    /// Everything the record does that the specification does not say it may.
    ///
    /// From [`Verified::summary`](crate::Verified::summary) this includes the
    /// three that are only discoverable while checking a signature —
    /// `RawSignatureNotDer`, `NonCanonicalDer` and `HighSSignature`.
    pub deviations: Vec<DeviationSummary>,
}

/// What checking a record's signature said about it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VerificationSummary {
    /// Whether the signature is authentic — and **nothing else**. Not that the
    /// key belongs to this charge point, not that the session is complete, not
    /// that the values may be billed.
    pub verified: bool,
    /// The algorithm the check actually ran.
    pub algorithm: SignatureAlgorithm,
    /// The curve of the key it ran against.
    pub key_curve: String,
    /// The key, as a DER `SubjectPublicKeyInfo` in lower-case hex — so a report
    /// says *which* key it trusted, which is the question a dispute turns on
    /// after the signature itself.
    pub key: String,
}

#[cfg(feature = "serde")]
impl Serialize for SignatureAlgorithm {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl Serialize for SignatureEncoding {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

fn register_label(r: Register) -> Option<String> {
    Some(
        match r {
            Register::ActiveEnergyImport => "ActiveEnergyImport",
            Register::ActiveEnergyExport => "ActiveEnergyExport",
            Register::TotalImportMains => "TotalImportMains",
            Register::TotalImportDevice => "TotalImportDevice",
            Register::TransactionImportMains => "TransactionImportMains",
            Register::TransactionImportDevice => "TransactionImportDevice",
            Register::TotalExportMains => "TotalExportMains",
            Register::TotalExportDevice => "TotalExportDevice",
            Register::TransactionExportMains => "TransactionExportMains",
            Register::TransactionExportDevice => "TransactionExportDevice",
            Register::Reserved => "Reserved",
            Register::Other => return None,
        }
        .to_string(),
    )
}

fn summarise_reading(r: &Reading<'_>) -> ReadingSummary {
    ReadingSummary {
        time: r.time().map(|t| t.to_string()),
        time_unix_millis: r.time().map(|t| t.unix_millis()),
        time_status: r.time().and_then(|t| t.status).map(TimeStatus::letter),
        transaction: r.transaction().map(TransactionMarker::letter),
        value: r.value().map(|v| v.as_str().to_string()),
        value_scale: r.value().map(|v| v.value().scale()),
        obis: r.obis().map(|o| o.as_str().to_string()),
        obis_canonical: r.obis().map(crate::ObisCode::canonical),
        register: r.obis().and_then(|o| register_label(o.register())),
        unit: r.unit().map(|u| u.as_str().to_string()),
        current_type: r.current_type().map(|c| c.as_str().to_string()),
        cumulated_loss: r.cumulated_loss().map(|v| v.as_str().to_string()),
        error_flags: r.error_flags().as_str().to_string(),
        state: r.state().map(crate::payload::MeterState::letter),
        billable: r.is_billable(),
        explicit: r.explicit().fields().collect(),
    }
}

fn summarise_identification(p: &Payload<'_>) -> Option<IdentificationSummary> {
    if p.identification_status().is_none()
        && p.identification_level().is_none()
        && p.identification_type().is_none()
    {
        return None;
    }
    Some(IdentificationSummary {
        assigned: p.identification_status(),
        level: p.identification_level().map(|l| l.as_str().to_string()),
        level_is_error: p.identification_level().is_some_and(|l| l.is_error()),
        flags: p
            .identification_flags()
            .unwrap_or(&[])
            .iter()
            .map(|f| f.as_str().to_string())
            .collect(),
        kind: p.identification_type().map(|t| t.as_str().to_string()),
        data: p.identification_data().map(ToString::to_string),
        tariff_text: p.tariff_text().map(ToString::to_string),
    })
}

impl Record<'_> {
    /// A serialisable report about this record.
    ///
    /// The record itself travels verbatim in
    /// [`RecordSummary::record`]; everything else is derived. See the module
    /// docs for why this is not `impl Serialize for Record`.
    #[must_use]
    pub fn summary(&self) -> RecordSummary {
        let p = self.payload();
        RecordSummary {
            record: self.as_str().to_string(),
            #[cfg(feature = "digest")]
            payload_digest: crate::encoding::hex_encode(&self.payload_digest()),
            signed_bytes: self.signed_bytes().len(),
            algorithm: self.signature().algorithm(),
            algorithm_text: self.signature().algorithm_text().map(ToString::to_string),
            algorithm_written: self.signature().algorithm_was_written(),
            signature_encoding: self.signature().encoding(),
            signature_readable: self.signature().data().is_some(),
            format_version: p.format_version().map(ToString::to_string),
            gateway: GatewaySummary {
                id: p.gateway_id().map(ToString::to_string),
                serial: p.gateway_serial().map(ToString::to_string),
                version: p.gateway_version().map(ToString::to_string),
            },
            meter: MeterSummary {
                vendor: p.meter_vendor().map(ToString::to_string),
                model: p.meter_model().map(ToString::to_string),
                serial: p.meter_serial().map(ToString::to_string),
                firmware: p.meter_firmware().map(ToString::to_string),
            },
            pagination: p.pagination().map(|p| p.to_string()),
            pagination_context: p.pagination().map(|p| match p.context() {
                crate::PaginationContext::Transaction => String::from("Transaction"),
                crate::PaginationContext::Fiscal => String::from("Fiscal"),
                crate::PaginationContext::Other(c) => c.to_string(),
            }),
            charge_controller_firmware: p.charge_controller_firmware().map(ToString::to_string),
            charge_point: p.charge_point_id_type().map(|t| ChargePointSummary {
                id_type: t.as_str().to_string(),
                id: p.charge_point_id().map(ToString::to_string),
            }),
            loss_compensation: p.loss_compensation().map(|lc| LossCompensationSummary {
                name: lc.name.as_deref().map(ToString::to_string),
                id: lc.id.as_ref().map(|n| n.as_str().to_string()),
                resistance: lc.resistance.as_ref().map(|n| n.as_str().to_string()),
                unit: lc.unit.map(|u| u.as_str().to_string()),
            }),
            identification: summarise_identification(p),
            extensions: p
                .object()
                .extras(&crate::Payload::KNOWN_KEYS)
                .map(|(k, _)| k.decode().into_owned())
                .chain(p.readings().iter().enumerate().flat_map(|(i, r)| {
                    r.object()
                        .extras(&crate::Reading::KNOWN_KEYS)
                        .map(move |(k, _)| alloc::format!("RD[{i}].{}", k.decode()))
                }))
                .collect(),
            embedded_public_key: self.embedded_public_key().map(ToString::to_string),
            verification: None,
            readings: p.readings().iter().map(summarise_reading).collect(),
            registers: p
                .by_register()
                .into_iter()
                .map(|s| RegisterSummary {
                    register: s
                        .readings
                        .first()
                        .and_then(|r| r.obis())
                        .and_then(|o| register_label(o.register())),
                    delta: s.delta().map(|d| d.to_string()),
                    unit: s
                        .readings
                        .first()
                        .and_then(|r| r.unit())
                        .map(|u| u.as_str().to_string()),
                    readings: s.readings.len(),
                    obis: s.obis,
                })
                .collect(),
            deviations: self.deviations().iter().map(summarise_deviation).collect(),
        }
    }
}

#[cfg(feature = "verify")]
#[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
impl crate::Verified<'_, '_> {
    /// A serialisable report about this record **and the check that was run**.
    ///
    /// Two things [`Record::summary`] cannot know: the verdict itself, in
    /// [`RecordSummary::verification`], and the three deviation kinds only a
    /// signature check can find. The key travels with the verdict, because a
    /// report that says "verified" without saying *which key* has answered half
    /// the question.
    #[must_use]
    pub fn summary(&self) -> RecordSummary {
        let mut summary = self.record().summary();
        summary.verification = Some(VerificationSummary {
            verified: true,
            algorithm: self.algorithm(),
            key_curve: self.key().curve().name().to_string(),
            key: crate::encoding::hex_encode(&self.key().to_spki()),
        });
        summary.deviations = self.deviations().iter().map(summarise_deviation).collect();
        summary
    }
}

fn summarise_deviation(d: &crate::Deviation) -> DeviationSummary {
    DeviationSummary {
        kind: d.kind.name().to_string(),
        value: d.value.clone(),
        departure: match d.kind.departure() {
            crate::Departure::Specification => "Specification",
            crate::Departure::Advisory => "Advisory",
        },
        message: d.kind.to_string(),
        spec: d.spec().to_string(),
        offset: d.at.offset,
        path: d.at.path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Record;

    const LEM: &str = r#"OCMF|{"FV":"1.0","GI":"LEM DCBM","GS":"1211751603","PG":"T144","MS":"1211751603","IS":true,"IL":"HEARSAY","IF":["RFID_RELATED"],"IT":"ISO14443","ID":"5E","RD":[{"TM":"2021-10-06T13:13:56,000+0200 R","TX":"B","RV":57.584,"RI":"1-0:1.8.0","RU":"kWh","RT":"DC","EF":"","ST":"G"},{"RV":4.405,"RI":"1-0:2.8.0","RU":"kWh","ST":"G"},{"TM":"2021-10-06T13:15:13,000+0200 R","TX":"E","RV":58.685,"RI":"1-0:1.8.0","RU":"kWh","ST":"G"},{"RV":4.500,"RI":"1-0:2.8.0","RU":"kWh","ST":"G"}]}|{"SD":"3045"}"#;

    #[test]
    fn a_summary_carries_the_record_verbatim_and_everything_derived() {
        let record = Record::parse(LEM).unwrap();
        let s = record.summary();

        assert_eq!(s.record, LEM, "the only field that round-trips");
        assert_eq!(s.signed_bytes, record.signed_bytes().len());
        assert_eq!(s.pagination.as_deref(), Some("T144"));
        assert_eq!(s.pagination_context.as_deref(), Some("Transaction"));
        assert_eq!(s.meter.serial.as_deref(), Some("1211751603"));
        assert_eq!(s.gateway.id.as_deref(), Some("LEM DCBM"));
        assert_eq!(s.readings.len(), 4);
        assert_eq!(s.registers.len(), 2);
    }

    #[test]
    fn quantities_are_exact_text_never_numbers() {
        let record = Record::parse(LEM).unwrap();
        let s = record.summary();
        assert_eq!(s.readings[0].value.as_deref(), Some("57.584"));
        assert_eq!(s.readings[0].value_scale, Some(3));
        assert_eq!(s.registers[0].delta.as_deref(), Some("1.101"));
    }

    #[test]
    fn carry_forward_is_visible_in_the_summary() {
        let record = Record::parse(LEM).unwrap();
        let s = record.summary();
        // The second reading inherited its time; the summary says so twice —
        // once by reporting the resolved value, once by listing what was
        // actually written.
        assert_eq!(s.readings[1].time, s.readings[0].time);
        assert!(s.readings[0].explicit.contains(&"TM"));
        assert!(!s.readings[1].explicit.contains(&"TM"));
        assert_eq!(s.readings[1].explicit, ["RV", "RI", "RU", "ST"]);
    }

    #[test]
    fn registers_are_named_where_the_code_sets_name_them() {
        let record = Record::parse(LEM).unwrap();
        let s = record.summary();
        assert_eq!(s.registers[0].obis, "01-00:01.08.00");
        assert_eq!(
            s.registers[0].register.as_deref(),
            Some("ActiveEnergyImport")
        );
        assert_eq!(
            s.registers[1].register.as_deref(),
            Some("ActiveEnergyExport")
        );
    }

    #[test]
    fn deviations_travel_with_their_citation() {
        let record = Record::parse(LEM).unwrap();
        let s = record.summary();
        let obis = s
            .deviations
            .iter()
            .find(|d| d.kind == "ObisNonCanonical")
            .expect("the corpus form is not canonical");
        assert_eq!(obis.spec, "OCMF Tab. 25");
        assert!(obis.path.as_deref().unwrap().starts_with("RD["));
    }

    #[test]
    fn a_summary_carries_what_sits_inside_the_signature() {
        // Vendor extensions live inside the signed bytes and are dropped by
        // every reader that models only the specified extension points.
        let src = LEM.replace(
            r#"{"RV":4.405,"RI":"1-0:2.8.0","RU":"kWh","ST":"G"}"#,
            r#"{"RV":4.405,"RI":"1-0:2.8.0","RU":"kWh","ST":"G","UC":{"UN":"No_Comp"}}"#,
        );
        let s = Record::parse(&src).unwrap().summary();
        assert_eq!(s.extensions, ["RD[1].UC"]);
        assert!(s.embedded_public_key.is_none());
        assert!(s.verification.is_none(), "reading is not checking");
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn a_verified_summary_says_which_key_said_so() {
        const KEBA: &str = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
        const KEY: &str = "3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE";
        let record = Record::parse(KEBA).unwrap();
        let key = crate::PublicKey::from_text(KEY, record.signature().curve()).unwrap();
        let verified = crate::verify(&record, &key).unwrap();

        let s = verified.summary();
        let v = s.verification.expect("this one was checked");
        assert!(v.verified);
        assert_eq!(v.key_curve, "secp256r1");
        assert_eq!(v.key, KEY.to_lowercase(), "which key said so");

        // …and the deviations only a signature check can find are in there.
        assert!(
            s.deviations.iter().any(|d| d.kind == "HighSSignature"),
            "{:?}",
            s.deviations
        );
        assert!(
            !record
                .summary()
                .deviations
                .iter()
                .any(|d| d.kind == "HighSSignature"),
            "reading alone cannot know it"
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn a_summary_serialises_and_the_numbers_stay_exact() {
        let record = Record::parse(LEM).unwrap();
        let json = serde_json::to_string(&record.summary()).unwrap();
        // The values are strings, so no consumer's `f64` can round them.
        assert!(json.contains(r#""value":"57.584""#));
        assert!(json.contains(r#""delta":"1.101""#));
        assert!(json.contains(r#""algorithm":"ECDSA-secp256r1-SHA256""#));
        // And the record travels whole.
        assert!(json.contains(r#""record":"OCMF|"#));
    }

    #[test]
    fn the_algorithm_serialises_as_the_table_spells_it() {
        assert_eq!(
            SignatureAlgorithm::EcdsaBrainpool256r1Sha256.as_str(),
            "ECDSA-brainpool256r1-SHA256"
        );
    }
}
