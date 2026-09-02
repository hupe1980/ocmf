//! The payload section: everything the signature covers.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! let text = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
//! let record = ocmf::Record::parse(text)?;
//! let payload = record.payload();
//!
//! assert_eq!(payload.pagination().unwrap().to_string(), "T32");
//! assert_eq!(payload.gateway_id(), Some("KEBA_KCP30"));
//! assert_eq!(payload.readings().len(), 2);
//!
//! // Readings are grouped per register *after* carry-forward, so an import
//! // begin is never paired with an export end.
//! let series = payload.by_register();
//! assert_eq!(series.len(), 1);
//! assert_eq!(series[0].obis, "01-0B:01.08.00");
//! assert_eq!(series[0].delta().unwrap().to_string(), "0.0001");
//! # Ok(()) }
//! ```

mod reading;
mod tables;

pub use reading::{Explicit, Reading};
pub use tables::{
    ChargePointIdType, CurrentType, ErrorFlags, IdentificationFlag, IdentificationLevel,
    IdentificationType, MeterState, TransactionMarker, Unit,
};

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use crate::deviation::{Deviation, DeviationKind, Location};
use crate::json::{Object, RawStr, Value};
use crate::limits::Limits;
use crate::number::Number;

/// Which counter a `PG` value belongs to `[OCMF Tab. 2]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PaginationContext {
    /// `T` — readings in transaction reference. Mandatory support.
    Transaction,
    /// `F` — fiscal readings, independent of transactions. Optional support,
    /// and **absent from the entire reference corpus**: the fiscal path is
    /// untested by the official test data.
    Fiscal,
    /// A context letter the table does not define.
    Other(char),
}

/// `PG` — the position of this record in its counter's stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination {
    context: PaginationContext,
    number: u64,
}

impl Pagination {
    /// A transaction-context counter value.
    #[must_use]
    pub const fn transaction(number: u64) -> Self {
        Self {
            context: PaginationContext::Transaction,
            number,
        }
    }

    /// A fiscal-context counter value.
    #[must_use]
    pub const fn fiscal(number: u64) -> Self {
        Self {
            context: PaginationContext::Fiscal,
            number,
        }
    }

    /// The counter this record belongs to.
    #[must_use]
    pub const fn context(&self) -> PaginationContext {
        self.context
    }

    /// The counter value.
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// Whether `other` is the record that immediately follows this one.
    ///
    /// "The respective pagination counter is counted monotonically in
    /// ascending order with an increment of 1" `[OCMF Tab. 2]`, per context —
    /// so a transaction record never follows a fiscal one.
    #[must_use]
    pub fn is_followed_by(&self, other: &Self) -> bool {
        self.context == other.context && other.number == self.number.wrapping_add(1)
    }

    /// Reads a `PG` value; `None` when it is not `<letter><digits>` at all.
    ///
    /// A `PG` nobody can read costs the record its place in a sequence, not its
    /// signature — [`crate::session`] reports the gap.
    fn parse(raw: &str, at: &Location, dev: &mut Vec<Deviation>) -> Option<Self> {
        let mut chars = raw.chars();
        let letter = chars.next()?;
        let digits = chars.as_str();
        if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if digits.len() > 1 && digits.starts_with('0') {
            dev.push(Deviation::with_value(
                DeviationKind::PaginationLeadingZero,
                at.clone(),
                raw,
            ));
        }
        // A counter longer than a `u64` is not a counter a meter produced.
        let number = digits.parse::<u64>().ok()?;
        let context = match letter {
            'T' => PaginationContext::Transaction,
            'F' => PaginationContext::Fiscal,
            other => PaginationContext::Other(other),
        };
        Some(Self { context, number })
    }
}

impl core::fmt::Display for Pagination {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let c = match self.context {
            PaginationContext::Transaction => 'T',
            PaginationContext::Fiscal => 'F',
            PaginationContext::Other(c) => c,
        };
        write!(f, "{c}{}", self.number)
    }
}

/// `LC` — the cable-loss compensation the meter applied `[OCMF Tab. 24]`.
#[derive(Debug, Clone)]
pub struct LossCompensation<'a> {
    /// `LN` — a traceability text for the characteristics used.
    pub name: Option<Cow<'a, str>>,
    /// `LI` — a traceability identifier from the meter's documentation.
    pub id: Option<Number<'a>>,
    /// `LR` — the cable resistance used. Mandatory `[OCMF Tab. 24]`, and
    /// `None` when the record omitted it or wrote something that is not a
    /// number; both are reported.
    pub resistance: Option<Number<'a>>,
    /// `LU` — the unit of `LR`: `mOhm` or `uOhm`. Mandatory, and `None` on the
    /// same terms as [`Self::resistance`].
    pub unit: Option<Unit<'a>>,
}

impl<'a> LossCompensation<'a> {
    /// Keys `[OCMF Tab. 24]` defines.
    pub const KNOWN_KEYS: [&'static str; 4] = ["LN", "LI", "LR", "LU"];

    fn parse(obj: &Object<'a>, at: usize, dev: &mut Vec<Deviation>) -> Self {
        let number = |key: &'static str, dev: &mut Vec<Deviation>| -> Option<Number<'a>> {
            let v = obj.get(key)?;
            match Number::from_value(v) {
                Ok(n) => Some(n),
                Err(text) => {
                    dev.push(Deviation::with_value(
                        DeviationKind::NumberUnrepresentable,
                        Location::named(v.span().start, key),
                        text,
                    ));
                    None
                }
            }
        };
        let resistance = number("LR", dev);
        if resistance.is_none() && !obj.contains("LR") {
            dev.push(Deviation::new(
                DeviationKind::LossCompensationIncomplete,
                Location::named(at, "LR"),
            ));
        }
        let unit = match obj.get("LU") {
            None => {
                dev.push(Deviation::new(
                    DeviationKind::LossCompensationIncomplete,
                    Location::named(at, "LU"),
                ));
                None
            }
            Some(v) => typed(v, "LU", |v| v.as_str(), dev).map(|raw| {
                let u = Unit::parse_decoded(raw);
                report_undefined_value(
                    matches!(u, Unit::MilliOhm | Unit::MicroOhm),
                    "LU",
                    raw.span().start,
                    &raw.decode(),
                    dev,
                );
                u
            }),
        };
        let name = obj.get("LN").and_then(Value::as_str).map(RawStr::decode);
        if name.as_deref().is_some_and(|n| n.chars().count() > 20) {
            dev.push(Deviation::new(
                DeviationKind::FieldTooLong,
                Location::named(at, "LN"),
            ));
        }
        Self {
            name,
            id: number("LI", dev),
            resistance,
            unit,
        }
    }
}

/// A register's readings within one record, in source order.
#[derive(Debug, Clone)]
pub struct RegisterSeries<'r, 'a> {
    /// The canonical OBIS code shared by every reading here.
    pub obis: String,
    /// The readings, in the order the record wrote them.
    pub readings: Vec<&'r Reading<'a>>,
}

impl<'r, 'a> RegisterSeries<'r, 'a> {
    /// The reading marked `TX = B`, if this register has one.
    #[must_use]
    pub fn begin(&self) -> Option<&'r Reading<'a>> {
        self.readings
            .iter()
            .copied()
            .find(|r| r.transaction().is_some_and(TransactionMarker::is_begin))
    }

    /// The reading marked with any of the five endings, if this register has
    /// one.
    #[must_use]
    pub fn end(&self) -> Option<&'r Reading<'a>> {
        self.readings
            .iter()
            .copied()
            .find(|r| r.transaction().is_some_and(TransactionMarker::is_end))
    }

    /// The difference between the end and begin readings, when both exist,
    /// carry values, and share a unit.
    ///
    /// `None` is the honest answer for everything else — and note that this is
    /// arithmetic, not authorisation: it says nothing about whether the meter
    /// was healthy or the clock was synchronised.
    #[must_use]
    pub fn delta(&self) -> Option<rust_decimal::Decimal> {
        let (b, e) = (self.begin()?, self.end()?);
        if b.unit()? != e.unit()? {
            return None;
        }
        Some(e.value()?.value() - b.value()?.value())
    }
}

/// The payload section, typed, with carry-forward resolved.
///
/// The raw JSON is kept alongside: it is the source of truth for reproduction,
/// and the only place vendor extensions live.
#[derive(Debug, Clone)]
pub struct Payload<'a> {
    format_version: Option<Cow<'a, str>>,
    gateway_id: Option<Cow<'a, str>>,
    gateway_serial: Option<Cow<'a, str>>,
    gateway_version: Option<Cow<'a, str>>,
    pagination: Option<Pagination>,
    meter_vendor: Option<Cow<'a, str>>,
    meter_model: Option<Cow<'a, str>>,
    meter_serial: Option<Cow<'a, str>>,
    meter_firmware: Option<Cow<'a, str>>,
    identification_status: Option<bool>,
    identification_level: Option<IdentificationLevel<'a>>,
    identification_flags: Option<Vec<IdentificationFlag<'a>>>,
    identification_type: Option<IdentificationType<'a>>,
    identification_data: Option<Cow<'a, str>>,
    tariff_text: Option<Cow<'a, str>>,
    charge_controller_firmware: Option<Cow<'a, str>>,
    loss_compensation: Option<LossCompensation<'a>>,
    charge_point_id_type: Option<ChargePointIdType<'a>>,
    charge_point_id: Option<Cow<'a, str>>,
    readings: Vec<Reading<'a>>,
    object: Object<'a>,
}

/// Whether the S.A.F.E. Transparenzsoftware's version dispatch reads this `FV`.
///
/// Its `OCMFVerificationParser` selects a reader for `version <= 1.3` after a
/// `MAX_VERSION = 1.5` check, so 1.4 and 1.5 pass the bound and then match no
/// reader (checked against `def928b`). Which of the two documents is right is
/// not a question a Rust crate can settle — reporting the fact is (R7).
fn reference_verifier_reads(fv: &str) -> bool {
    let Some((major, minor)) = fv.split_once('.') else {
        return false;
    };
    let (Ok(major), Ok(minor)) = (major.parse::<u32>(), minor.parse::<u32>()) else {
        return false;
    };
    major < 1 || (major == 1 && minor <= 3)
}

/// The decoded value of a scalar field, its source text, and where it sits.
///
/// The two strings differ when the source used a `\uXXXX` escape — and when
/// the field was not a JSON string at all.
type Scalar<'a> = (Cow<'a, str>, &'a str, usize);

/// `<major>.<minor>` — `[OCMF Tab. 1]`'s shape for `FV`, with the third digit
/// deliberately absent: "the revision … is not transmitted, since this does not
/// change anything in the format itself".
fn is_major_minor(v: &str) -> bool {
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit());
    v.split_once('.')
        .is_some_and(|(major, minor)| digits(major) && digits(minor))
}

/// Reads a value through `f`, reporting the mismatch when it is not that shape.
///
/// The one place `FieldTypeMismatch` is raised for a structured field: the
/// value cannot be used, the field is dropped, and the record survives.
fn typed<'v, 'a, T>(
    v: &'v Value<'a>,
    key: &'static str,
    f: impl FnOnce(&'v Value<'a>) -> Option<T>,
    dev: &mut Vec<Deviation>,
) -> Option<T> {
    let out = f(v);
    if out.is_none() {
        dev.push(Deviation::with_value(
            DeviationKind::FieldTypeMismatch,
            Location::named(v.span().start, key),
            v.kind(),
        ));
    }
    out
}

/// Reports a value a closed table does not define.
///
/// Every such type keeps the value verbatim and answers `false` to every
/// predicate that could authorise money (D22). This is the other half of that
/// bargain: the caller is *told*.
fn report_undefined_value(
    defined: bool,
    field: &str,
    at: usize,
    value: &str,
    dev: &mut Vec<Deviation>,
) {
    if !defined {
        dev.push(Deviation::with_value(
            DeviationKind::UndefinedTableValue,
            Location::named(at, field),
            value,
        ));
    }
}

macro_rules! text_accessor {
    ($(#[$m:meta])* $name:ident, $field:ident) => {
        $(#[$m])*
        #[must_use]
        pub fn $name(&self) -> Option<&str> {
            self.$field.as_deref()
        }
    };
}

impl<'a> Payload<'a> {
    /// Keys `[OCMF Tab. 1–7]` defines at the top level.
    pub const KNOWN_KEYS: [&'static str; 20] = [
        "FV", "GI", "GS", "GV", "PG", "MV", "MM", "MS", "MF", "IS", "IL", "IF", "IT", "ID", "TT",
        "CF", "LC", "CT", "CI", "RD",
    ];

    text_accessor!(
        /// `FV` — the format version, `<major>.<minor>`.
        format_version, format_version);
    text_accessor!(
        /// `GI` — identification of the signing component.
        gateway_id, gateway_id);
    text_accessor!(
        /// `GS` — serial number of the signing component.
        gateway_serial, gateway_serial);
    text_accessor!(
        /// `GV` — software version of the signing component.
        gateway_version, gateway_version);
    text_accessor!(
        /// `MV` — meter manufacturer.
        meter_vendor, meter_vendor);
    text_accessor!(
        /// `MM` — meter model.
        meter_model, meter_model);
    text_accessor!(
        /// `MS` — meter serial number. Marked `1..1` by `[OCMF Tab. 3]` and
        /// absent from 89 % of real records.
        meter_serial, meter_serial);
    text_accessor!(
        /// `MF` — meter firmware version.
        meter_firmware, meter_firmware);
    text_accessor!(
        /// `ID` — the identification data, formatted per `IT`.
        identification_data, identification_data);
    text_accessor!(
        /// `TT` — the tariff text, up to 250 characters of free text.
        tariff_text, tariff_text);
    text_accessor!(
        /// `CF` — charge-controller firmware version (OCMF 1.3+).
        charge_controller_firmware, charge_controller_firmware);
    text_accessor!(
        /// `CI` — the charge point's identifier.
        charge_point_id, charge_point_id);

    /// `PG` — pagination.
    ///
    /// `None` when the record wrote no `PG`, or wrote one that is not a context
    /// letter followed by digits. Both are reported; neither is a reason to
    /// refuse a record whose signature is still checkable.
    #[must_use]
    pub const fn pagination(&self) -> Option<Pagination> {
        self.pagination
    }

    /// `IS` — whether a user was successfully assigned.
    #[must_use]
    pub const fn identification_status(&self) -> Option<bool> {
        self.identification_status
    }

    /// `IL` — the overall status of the user assignment.
    #[must_use]
    pub const fn identification_level(&self) -> Option<IdentificationLevel<'a>> {
        self.identification_level
    }

    /// `IF` — detail flags of the user assignment.
    #[must_use]
    pub fn identification_flags(&self) -> Option<&[IdentificationFlag<'a>]> {
        self.identification_flags.as_deref()
    }

    /// `IT` — the type of the identification data.
    #[must_use]
    pub const fn identification_type(&self) -> Option<IdentificationType<'a>> {
        self.identification_type
    }

    /// `LC` — cable-loss compensation parameters.
    #[must_use]
    pub const fn loss_compensation(&self) -> Option<&LossCompensation<'a>> {
        self.loss_compensation.as_ref()
    }

    /// `CT` — how the charge point is identified.
    #[must_use]
    pub const fn charge_point_id_type(&self) -> Option<ChargePointIdType<'a>> {
        self.charge_point_id_type
    }

    /// `RD` — the readings, with carry-forward resolved.
    #[must_use]
    pub fn readings(&self) -> &[Reading<'a>] {
        &self.readings
    }

    /// The payload's raw JSON — with one hole.
    ///
    /// `RD` is moved into [`Self::readings`] while parsing rather than copied,
    /// so its member here is a `null` placeholder holding the array's original
    /// span. Everything else is exactly as it was written. This exists to reach
    /// vendor extensions at the top level; each reading's own JSON is on
    /// [`Reading::object`].
    ///
    /// Reproduction never goes through here: that is
    /// [`Record::payload_text`](crate::Record::payload_text), which is a slice
    /// of the input.
    #[must_use]
    pub const fn object(&self) -> &Object<'a> {
        &self.object
    }

    /// Whether any reading marks the **beginning** of a transaction
    /// (`TX = B`) `[OCMF Tab. 7]`.
    ///
    /// Both transports need this and neither can share the other's answer: the
    /// OCA application note puts a record holding *both* markers under
    /// `Transaction.End`, while the S.A.F.E. transparency container treats it
    /// as a complete value with no transaction at all. So the question is
    /// answered here and the two conventions are applied where they belong.
    #[must_use]
    pub fn marks_transaction_begin(&self) -> bool {
        self.readings
            .iter()
            .any(|r| r.transaction().is_some_and(TransactionMarker::is_begin))
    }

    /// Whether any reading marks the **end** of a transaction, in any of the
    /// five spellings `[OCMF Tab. 7]`.
    #[must_use]
    pub fn marks_transaction_end(&self) -> bool {
        self.readings
            .iter()
            .any(|r| r.transaction().is_some_and(TransactionMarker::is_end))
    }

    /// Whether this record refers to a transaction at all.
    ///
    /// Fiscal records — readings taken outside any transaction — have no `TX`
    /// and no user assignment `[OCMF Tab. 7]`.
    #[must_use]
    pub fn is_transaction(&self) -> bool {
        self.pagination
            .is_some_and(|p| p.context == PaginationContext::Transaction)
            || self.readings.iter().any(|r| r.transaction().is_some())
    }

    /// The readings grouped by register, in first-seen order.
    ///
    /// Grouping happens **after** carry-forward, which is the whole point: LEM
    /// meters interleave an import and an export register in one record, and a
    /// naive first/last pairing matches an import begin with an export end.
    #[must_use]
    pub fn by_register<'r>(&'r self) -> Vec<RegisterSeries<'r, 'a>> {
        let mut out: Vec<RegisterSeries<'r, 'a>> = Vec::new();
        for r in &self.readings {
            let Some(obis) = r.obis() else { continue };
            let key = obis.canonical();
            if let Some(series) = out.iter_mut().find(|s| s.obis == key) {
                series.readings.push(r);
            } else {
                out.push(RegisterSeries {
                    obis: key,
                    readings: alloc::vec![r],
                });
            }
        }
        out
    }

    #[allow(clippy::too_many_lines, reason = "one block per field of Tables 1-6")]
    pub(crate) fn from_object(obj: Object<'a>, limits: &Limits, dev: &mut Vec<Deviation>) -> Self {
        // `RD` is *moved* out of the payload object rather than copied: it
        // holds every reading, and deep-copying it to hand it on is most of
        // what a naive parser spends its time doing. What stays behind in
        // `Payload::object()` is a `null` placeholder, which is why the
        // readings are reached through `Payload::readings` and their own JSON
        // through `Reading::object`.
        let mut obj = obj;
        let rd = match obj.members.iter().rposition(|(k, _)| k.equals("RD")) {
            None => {
                dev.push(Deviation::new(
                    DeviationKind::ReadingsMissing,
                    Location::named(obj.span().start, "RD"),
                ));
                None
            }
            Some(i) => {
                let span = obj.members[i].1.span();
                let moved = core::mem::replace(&mut obj.members[i].1, Value::Null(span));
                match moved {
                    Value::Array(a) => Some(a),
                    other => {
                        dev.push(Deviation::with_value(
                            DeviationKind::FieldTypeMismatch,
                            Location::named(other.span().start, "RD"),
                            other.kind(),
                        ));
                        None
                    }
                }
            }
        };
        let readings = match rd {
            None => Vec::new(),
            Some(mut a) => {
                // A limit is the one thing that still truncates rather than
                // reports, because the point of it is to bound the work: the
                // record is kept, the surplus readings are not, and the caller
                // is told which limit bit.
                if a.items.len() > limits.readings {
                    dev.push(Deviation::with_value(
                        DeviationKind::ReadingsTruncated,
                        Location::named(a.span().start, "RD"),
                        &alloc::format!("{} readings", a.items.len()),
                    ));
                    a.items.truncate(limits.readings);
                }
                reading::parse_readings(a, dev)
            }
        };

        // A scalar the tables type as `String`, read leniently: a number or a
        // boolean is taken as its literal text and reported (`"FV":1.0` and
        // `"CT":0` both occur). A structure has no text to take, so the field
        // is dropped and reported — and neither costs the record.
        let scalar = |key: &'static str, dev: &mut Vec<Deviation>| -> Option<Scalar<'a>> {
            match obj.get(key)? {
                Value::Str(s) => Some((s.decode(), s.as_raw(), s.span().start)),
                Value::Number(n) => {
                    dev.push(Deviation::new(
                        DeviationKind::ScalarFieldNotAString,
                        Location::named(n.span().start, key),
                    ));
                    Some((Cow::Borrowed(n.as_str()), n.as_str(), n.span().start))
                }
                Value::Bool(b, span) => {
                    let literal = if *b { "true" } else { "false" };
                    dev.push(Deviation::new(
                        DeviationKind::ScalarFieldNotAString,
                        Location::named(span.start, key),
                    ));
                    Some((Cow::Borrowed(literal), literal, span.start))
                }
                other => {
                    dev.push(Deviation::with_value(
                        DeviationKind::FieldTypeMismatch,
                        Location::named(other.span().start, key),
                        other.kind(),
                    ));
                    None
                }
            }
        };
        let text = |key: &'static str, dev: &mut Vec<Deviation>| -> Option<Cow<'a, str>> {
            scalar(key, dev).map(|(decoded, _, _)| decoded)
        };
        let bounded = |key: &'static str,
                       max: usize,
                       value: &Option<Cow<'a, str>>,
                       dev: &mut Vec<Deviation>| {
            if value.as_deref().is_some_and(|t| t.chars().count() > max) {
                dev.push(Deviation::new(
                    DeviationKind::FieldTooLong,
                    Location::named(obj.span().start, key),
                ));
            }
        };

        // `FV` is `0..1` in the table and mandatory in the reference verifier.
        let format_version = text("FV", dev);
        match format_version.as_deref() {
            None => dev.push(Deviation::new(
                DeviationKind::FormatVersionMissing,
                Location::at(obj.span().start),
            )),
            Some(v) if is_major_minor(v) => {
                // The reference verifier dispatches on `version <= 1.3` and
                // answers "not compatible" above it (R7). A record may lawfully
                // say 1.4; the tool a driver runs will still refuse it.
                if !reference_verifier_reads(v) {
                    dev.push(Deviation::with_value(
                        DeviationKind::FormatVersionAheadOfReference,
                        Location::named(obj.span().start, "FV"),
                        v,
                    ));
                }
            }
            Some(v) => dev.push(Deviation::with_value(
                DeviationKind::FormatVersionMalformed,
                Location::named(obj.span().start, "FV"),
                v,
            )),
        }

        let pagination = match scalar("PG", dev) {
            None => {
                if !obj.contains("PG") {
                    dev.push(Deviation::new(
                        DeviationKind::PaginationMissing,
                        Location::named(obj.span().start, "PG"),
                    ));
                }
                None
            }
            Some((decoded, _, at)) => {
                let loc = Location::named(at, "PG");
                let parsed = Pagination::parse(&decoded, &loc, dev);
                match parsed {
                    Some(p) => report_undefined_value(
                        !matches!(p.context(), PaginationContext::Other(_)),
                        "PG",
                        at,
                        &decoded,
                        dev,
                    ),
                    None => dev.push(Deviation::with_value(
                        DeviationKind::PaginationMalformed,
                        loc,
                        &decoded,
                    )),
                }
                parsed
            }
        };
        let in_transaction = pagination
            .is_none_or(|p| p.context() == PaginationContext::Transaction)
            && obj.contains("PG");

        let meter_serial = text("MS", dev);
        if meter_serial.is_none() {
            dev.push(Deviation::new(
                DeviationKind::MeterSerialMissing,
                Location::at(obj.span().start),
            ));
        }

        let identification_status = match obj.get("IS") {
            None => {
                // "Present iff there is a transaction reference, even when
                // nobody could be assigned" — so a `T`-context record without
                // it is missing a `1..1` field, and a fiscal one is not.
                if in_transaction {
                    dev.push(Deviation::new(
                        DeviationKind::IdentificationStatusMissing,
                        Location::at(obj.span().start),
                    ));
                }
                None
            }
            Some(v) => typed(v, "IS", Value::as_bool, dev),
        };

        let identification_flags = match obj.get("IF") {
            None => {
                if identification_status.is_some() {
                    dev.push(Deviation::new(
                        DeviationKind::IdentificationFlagsMissing,
                        Location::at(obj.span().start),
                    ));
                }
                None
            }
            Some(v) => typed(v, "IF", |v| v.as_array(), dev).map(|a| {
                // `[OCMF Tab. 4]`: `0..4`, because there are four flag groups
                // and an assignment has one statement to make about each.
                if a.items.len() > 4 {
                    dev.push(Deviation::with_value(
                        DeviationKind::IdentificationFlagsCardinality,
                        Location::named(v.span().start, "IF"),
                        &alloc::format!("{} elements", a.items.len()),
                    ));
                }
                let mut flags: Vec<IdentificationFlag<'a>> = Vec::with_capacity(a.items.len());
                for item in &a.items {
                    let Some(s) = typed(item, "IF", |i| i.as_str(), dev) else {
                        continue;
                    };
                    let flag = IdentificationFlag::parse_decoded(s);
                    let decoded = s.decode();
                    report_undefined_value(flag.is_defined(), "IF", s.span().start, &decoded, dev);
                    // Two flags from one group state two things about the same
                    // assignment, and nothing downstream can choose between
                    // them.
                    if flag.group().is_some() && flags.iter().any(|f| f.group() == flag.group()) {
                        dev.push(Deviation::with_value(
                            DeviationKind::IdentificationFlagsDuplicateGroup,
                            Location::named(s.span().start, "IF"),
                            &decoded,
                        ));
                    }
                    flags.push(flag);
                }
                flags
            }),
        };

        // `"ISO14443"` is a lawful spelling of `"ISO14443"`, so the table
        // is matched on the *decoded* value — and an escaped value that is not
        // in the table keeps its own text rather than being flattened to an
        // empty unknown, which is what a caller reading `IT` needs to see.
        if identification_status.is_some() && !obj.contains("IT") {
            dev.push(Deviation::new(
                DeviationKind::IdentificationTypeMissing,
                Location::at(obj.span().start),
            ));
        }
        let identification_type = scalar("IT", dev).map(|(decoded, raw, at)| {
            let kind = IdentificationType::from_parts(&decoded, raw);
            report_undefined_value(kind.is_defined(), "IT", at, &decoded, dev);
            kind
        });

        let tariff_text = text("TT", dev);
        bounded("TT", 250, &tariff_text, dev);
        let charge_controller_firmware = text("CF", dev);
        bounded("CF", 25, &charge_controller_firmware, dev);

        let loss_compensation = match obj.get("LC") {
            None => None,
            Some(v) => typed(v, "LC", |v| v.as_object(), dev)
                .map(|o| LossCompensation::parse(o, v.span().start, dev)),
        };

        let identification_level = scalar("IL", dev).map(|(decoded, raw, at)| {
            let level = IdentificationLevel::from_parts(&decoded, raw);
            report_undefined_value(level.is_defined(), "IL", at, &decoded, dev);
            level
        });
        // `"CT": 0` is a real record. Dropping it silently would report "this
        // station names no charge point" about one that named a bad one.
        let charge_point_id_type = scalar("CT", dev).map(|(decoded, raw, at)| {
            let kind = ChargePointIdType::from_parts(&decoded, raw);
            report_undefined_value(kind.is_defined(), "CT", at, &decoded, dev);
            kind
        });
        let ci = scalar("CI", dev);
        if let (Some(kind), Some((id, _, at))) = (charge_point_id_type, ci.as_ref())
            && kind.id_is_well_formed(id) == Some(false)
        {
            dev.push(Deviation::with_value(
                DeviationKind::ChargePointIdFormat,
                Location::named(*at, "CI"),
                id,
            ));
        }
        let charge_point_id = ci.map(|(decoded, _, _)| decoded);

        // `ID` is checked against the shape `IT` prescribes for it.
        let id = scalar("ID", dev);
        if let (Some(kind), Some((data, _, at))) = (identification_type, id.as_ref())
            && kind.data_is_well_formed(data) == Some(false)
        {
            dev.push(Deviation::with_value(
                DeviationKind::IdentificationDataFormat,
                Location::named(*at, "ID"),
                data,
            ));
        }
        let identification_data = id.map(|(decoded, _, _)| decoded);

        // `[OCMF §Relation of Serial Numbers, Charge Point and Public Key]`:
        // the meter's serial, or the gateway's, or a direct identification of
        // the charge point. With none of the three there is no route by which
        // a key can be bound to this record at all.
        if meter_serial.is_none()
            && !obj.contains("GS")
            && !(charge_point_id_type.is_some() && charge_point_id.is_some())
        {
            dev.push(Deviation::new(
                DeviationKind::SourceUnidentifiable,
                Location::at(obj.span().start),
            ));
        }

        // Top-level extension points: `U`-`Z` are reserved for vendors
        // `[OCMF §Extension Points in Payload Data Section]`.
        for (k, _) in obj.extras(&Self::KNOWN_KEYS) {
            let name = k.decode();
            if !matches!(name.as_bytes().first(), Some(b'U'..=b'Z')) {
                dev.push(Deviation::with_value(
                    DeviationKind::UnknownKey,
                    Location::named(k.span().start, &name),
                    &name,
                ));
            }
        }

        let this = Self {
            format_version,
            gateway_id: text("GI", dev),
            gateway_serial: text("GS", dev),
            gateway_version: text("GV", dev),
            pagination,
            meter_vendor: text("MV", dev),
            meter_model: text("MM", dev),
            meter_serial,
            meter_firmware: text("MF", dev),
            identification_status,
            identification_level,
            identification_flags,
            identification_type,
            identification_data,
            tariff_text,
            charge_controller_firmware,
            loss_compensation,
            charge_point_id_type,
            charge_point_id,
            readings,
            object: obj,
        };
        // Deviations are collected as the fields are read, which is not the
        // order they appear in. A report that jumps about the record is a
        // report nobody reads twice.
        dev.sort_by_key(|d| d.at.offset);
        this
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn payload(src: &str) -> (Payload<'_>, Vec<Deviation>) {
        let mut dev = vec![];
        let v = crate::json::parse_value(src, 0, &Limits::DEFAULT, &mut dev).unwrap();
        let o = v.as_object().expect("object").clone();
        let p = Payload::from_object(o, &Limits::DEFAULT, &mut dev);
        (p, dev)
    }

    const KEBA: &str = r#"{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}"#;

    #[test]
    fn a_real_record_reads_field_for_field() {
        let (p, dev) = payload(KEBA);
        assert_eq!(p.format_version(), Some("1.0"));
        assert_eq!(p.gateway_id(), Some("KEBA_KCP30"));
        assert_eq!(p.pagination().unwrap().to_string(), "T32");
        assert_eq!(
            p.pagination().unwrap().context(),
            PaginationContext::Transaction
        );
        assert_eq!(p.identification_status(), Some(false));
        assert_eq!(p.identification_level(), Some(IdentificationLevel::None));
        assert_eq!(p.identification_flags().unwrap().len(), 4);
        assert_eq!(p.readings().len(), 2);
        assert!(p.is_transaction());
        // ... and it is missing the meter serial, like nine records in ten.
        assert!(p.meter_serial().is_none());
        assert!(
            dev.iter()
                .any(|d| d.kind == DeviationKind::MeterSerialMissing)
        );
    }

    #[test]
    fn pagination_knows_what_follows_it() {
        let a = Pagination::transaction(32);
        assert!(a.is_followed_by(&Pagination::transaction(33)));
        assert!(!a.is_followed_by(&Pagination::transaction(34)));
        assert!(!a.is_followed_by(&Pagination::fiscal(33)));
        assert_eq!(Pagination::fiscal(7).to_string(), "F7");
    }

    #[test]
    fn a_leading_zero_in_the_counter_is_reported() {
        let mut dev = vec![];
        Pagination::parse("T007", &Location::at(0), &mut dev).unwrap();
        assert_eq!(dev[0].kind, DeviationKind::PaginationLeadingZero);
    }

    #[test]
    fn interleaved_registers_are_grouped_before_they_are_paired() {
        let (p, _) = payload(
            r#"{"FV":"1.0","PG":"T144","MS":"1211751603","IS":true,"IF":[],"IT":"NONE","RD":[
                {"TM":"2021-10-06T13:13:56,000+0200 R","TX":"B","RV":57.584,"RI":"1-0:1.8.0","RU":"kWh","RT":"DC","EF":"","ST":"G"},
                {"RV":4.405,"RI":"1-0:2.8.0","RU":"kWh","ST":"G"},
                {"TM":"2021-10-06T13:15:13,000+0200 R","TX":"E","RV":58.685,"RI":"1-0:1.8.0","RU":"kWh","ST":"G"},
                {"RV":4.500,"RI":"1-0:2.8.0","RU":"kWh","ST":"G"}
            ]}"#,
        );
        let regs = p.by_register();
        assert_eq!(regs.len(), 2, "import and export are separate series");

        let import = regs.iter().find(|r| r.obis == "01-00:01.08.00").unwrap();
        assert_eq!(import.delta().unwrap().to_string(), "1.101");

        // The export register's readings inherited B and E from the import
        // readings before them — the grouping is what keeps them apart.
        let export = regs.iter().find(|r| r.obis == "01-00:02.08.00").unwrap();
        assert_eq!(export.delta().unwrap().to_string(), "0.095");
    }

    #[test]
    fn loss_compensation_reads_all_four_fields() {
        let (p, _) = payload(
            r#"{"FV":"1.4","PG":"T1","MS":"x","IS":true,"IF":[],"IT":"NONE","LC":{"LN":"cable_name","LI":1,"LR":2,"LU":"mOhm"},"RD":[{"TM":"2018-07-24T13:22:04,000+0200 S","TX":"B","RV":1,"RI":"1-b:1.8.0","RU":"kWh","ST":"G"}]}"#,
        );
        let lc = p.loss_compensation().unwrap();
        assert_eq!(lc.name.as_deref(), Some("cable_name"));
        assert_eq!(lc.resistance.as_ref().unwrap().as_str(), "2");
        assert_eq!(lc.unit, Some(Unit::MilliOhm));
    }

    #[test]
    fn a_missing_pg_is_a_deviation_and_the_record_survives() {
        // Structure is fatal; values are not. A payload with no `PG` has no
        // place in a sequence — and its signature is still checkable, which is
        // the whole reason the record exists.
        let mut dev = vec![];
        let v = crate::json::parse_value(r#"{"FV":"1.0","RD":[]}"#, 0, &Limits::DEFAULT, &mut dev)
            .unwrap();
        let o = v.as_object().unwrap().clone();
        let p = Payload::from_object(o, &Limits::DEFAULT, &mut dev);
        assert!(p.pagination().is_none());
        assert!(
            dev.iter()
                .any(|d| d.kind == DeviationKind::PaginationMissing)
        );
    }

    #[test]
    fn a_field_nobody_can_read_costs_the_field_and_not_the_record() {
        let (p, dev) = payload(
            r#"{"FV":"1.0","PG":"nope","MS":{"a":1},"IS":"yes","IF":{},"IT":"NONE","RD":[{"TM":"never","TX":"B","RV":"x","RI":"nope","RU":"kWh","ST":"G"}]}"#,
        );
        assert!(p.pagination().is_none());
        assert!(p.meter_serial().is_none());
        assert!(p.identification_status().is_none());
        assert_eq!(p.readings().len(), 1, "the reading is still there");
        assert!(p.readings()[0].time().is_none());
        assert!(p.readings()[0].obis().is_none());
        assert!(p.readings()[0].value().is_none());
        let kinds: alloc::vec::Vec<_> = dev.iter().map(|d| d.kind).collect();
        for want in [
            DeviationKind::PaginationMalformed,
            DeviationKind::FieldTypeMismatch,
            DeviationKind::TimeMalformed,
            DeviationKind::ObisMalformed,
            DeviationKind::NumberUnrepresentable,
        ] {
            assert!(kinds.contains(&want), "{want:?} missing from {kinds:?}");
        }
    }

    #[test]
    fn deviations_are_reported_in_the_order_they_appear_in_the_record() {
        let (_, dev) = payload(KEBA);
        let offsets: alloc::vec::Vec<_> = dev.iter().map(|d| d.at.offset).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted, "a report that jumps about is unreadable");
    }

    #[test]
    fn a_top_level_vendor_extension_is_allowed_and_a_stray_key_is_not() {
        let base = r#"{"FV":"1.0","PG":"T1","MS":"x","IS":true,"IF":[],"IT":"NONE","RD":[{"TM":"2018-07-24T13:22:04,000+0200 S","TX":"B","RV":1,"RI":"1-b:1.8.0","RU":"kWh","ST":"G"}]"#;
        let (_, dev) = payload(&alloc::format!(r#"{base},"UCPN":1}}"#));
        assert!(!dev.iter().any(|d| d.kind == DeviationKind::UnknownKey));

        let (_, dev) = payload(&alloc::format!(r#"{base},"QQ":1}}"#));
        assert!(dev.iter().any(|d| d.kind == DeviationKind::UnknownKey));
    }
}
