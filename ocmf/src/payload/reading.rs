//! `RD`: readings, and the carry-forward rule that voids half their
//! cardinalities.
//!
//! > "For the readings, fields that have an identical value to the previous
//! > reading are omitted. However, this only applies within a signed record."
//! > `[OCMF Tab. 7 preamble]`
//!
//! The rule is stated over *fields*, with `RI` and `TX` as examples rather than
//! as the list, so `TM`, `RU`, `RT`, `EF` and `ST` carry on exactly the same
//! footing. This is not a corner case: **205 of 705 readings in the reference
//! corpus have no `TM` at all**, because LEM's DCBM writes one fully-specified
//! reading and then a second, for a different register, carrying only what
//! changed.
//!
//! # Two fields that deliberately do not carry
//!
//! `RV` and `CL` are values, and the specification gives a *second* meaning to
//! their absence: "The fields `RV`, `RI`, `RU` and `RT` can be omitted if only
//! the occurrence of an error condition (event) of the meter is to be
//! indicated". An omitted `RV` is therefore ambiguous — same value as before,
//! or no value at all — and only one of the two readings can invent money. So
//! they are left absent, and a caller sees `None`.
//!
//! `RI` and `RU` are carried, and carried *together*: "The fields `RI` and `RU`
//! form a group. Fields of a group are either all present together or omitted
//! together."
//!
//! # `EF` is the field that decides money
//!
//! An omitted `EF` on a later reading means *unchanged*. A record whose first
//! reading is flagged `E` and whose second omits the field is a record whose
//! second reading is **still flagged**. Reading the omission as "no error"
//! clears a fault the station signed, and that error only ever runs towards
//! billing a kilowatt-hour the meter disowned. On the first reading there is no
//! previous value, so an omitted `EF` genuinely means no flags.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use crate::deviation::{Deviation, DeviationKind, Location};
use crate::json::Object;
use crate::number::Number;
use crate::obis::ObisCode;
use crate::time::OcmfTime;

use super::tables::{CurrentType, ErrorFlags, MeterState, TransactionMarker, Unit};

/// Which fields a reading wrote for itself, as opposed to inheriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Explicit(u16);

impl Explicit {
    /// `TM` was written.
    pub const TIME: Self = Self(1 << 0);
    /// `TX` was written.
    pub const TRANSACTION: Self = Self(1 << 1);
    /// `RV` was written.
    pub const VALUE: Self = Self(1 << 2);
    /// `RI` was written.
    pub const OBIS: Self = Self(1 << 3);
    /// `RU` was written.
    pub const UNIT: Self = Self(1 << 4);
    /// `RT` was written.
    pub const CURRENT_TYPE: Self = Self(1 << 5);
    /// `CL` was written.
    pub const CUMULATED_LOSS: Self = Self(1 << 6);
    /// `EF` was written.
    pub const ERROR_FLAGS: Self = Self(1 << 7);
    /// `ST` was written.
    pub const STATE: Self = Self(1 << 8);

    /// Every flag, with the OCMF key it stands for, in `[OCMF Tab. 7]` order.
    pub const ALL: [(Self, &'static str); 9] = [
        (Self::TIME, "TM"),
        (Self::TRANSACTION, "TX"),
        (Self::VALUE, "RV"),
        (Self::OBIS, "RI"),
        (Self::UNIT, "RU"),
        (Self::CURRENT_TYPE, "RT"),
        (Self::CUMULATED_LOSS, "CL"),
        (Self::ERROR_FLAGS, "EF"),
        (Self::STATE, "ST"),
    ];

    /// Whether all of `other`'s bits are set.
    #[must_use]
    pub const fn has(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The OCMF keys this reading wrote for itself, in table order.
    ///
    /// The complement is what it inherited from the reading before it — which
    /// is why a record's readings cannot be read independently of one another.
    pub fn fields(self) -> impl Iterator<Item = &'static str> {
        Self::ALL
            .into_iter()
            .filter(move |(bit, _)| self.has(*bit))
            .map(|(_, name)| name)
    }

    const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// One reading, with carry-forward already resolved.
///
/// Every accessor answers what the reading *means*; [`Reading::explicit`] says
/// what it *wrote*.
#[derive(Debug, Clone)]
pub struct Reading<'a> {
    time: Option<OcmfTime>,
    transaction: Option<TransactionMarker>,
    value: Option<Number<'a>>,
    obis: Option<ObisCode<'a>>,
    unit: Option<Unit<'a>>,
    current_type: Option<CurrentType<'a>>,
    cumulated_loss: Option<Number<'a>>,
    error_flags: ErrorFlags<'a>,
    state: Option<MeterState>,
    explicit: Explicit,
    object: Object<'a>,
}

impl<'a> Reading<'a> {
    /// `TM` — the instant and the clock's synchronisation state.
    #[must_use]
    pub const fn time(&self) -> Option<OcmfTime> {
        self.time
    }

    /// `TX` — where this reading sits in a transaction. `None` means the record
    /// has no transaction reference at all (fiscal metering).
    #[must_use]
    pub const fn transaction(&self) -> Option<TransactionMarker> {
        self.transaction
    }

    /// `RV` — the reading. `None` when the reading reports only an event.
    #[must_use]
    pub const fn value(&self) -> Option<&Number<'a>> {
        self.value.as_ref()
    }

    /// `RI` — which register was read.
    #[must_use]
    pub const fn obis(&self) -> Option<&ObisCode<'a>> {
        self.obis.as_ref()
    }

    /// `RU` — the unit of [`Self::value`].
    #[must_use]
    pub const fn unit(&self) -> Option<Unit<'a>> {
        self.unit
    }

    /// `RT` — alternating or direct current. No default is defined.
    #[must_use]
    pub const fn current_type(&self) -> Option<CurrentType<'a>> {
        self.current_type
    }

    /// `CL` — cumulated cable loss withdrawn from this reading, in the same
    /// unit as `RV`.
    #[must_use]
    pub const fn cumulated_loss(&self) -> Option<&Number<'a>> {
        self.cumulated_loss.as_ref()
    }

    /// `EF` — which quantities an error has made unusable.
    #[must_use]
    pub const fn error_flags(&self) -> &ErrorFlags<'a> {
        &self.error_flags
    }

    /// `ST` — the state of the meter.
    #[must_use]
    pub const fn state(&self) -> Option<MeterState> {
        self.state
    }

    /// Which fields this reading wrote rather than inherited.
    #[must_use]
    pub const fn explicit(&self) -> Explicit {
        self.explicit
    }

    /// The reading's own JSON, for reproduction and vendor extensions.
    #[must_use]
    pub const fn object(&self) -> &Object<'a> {
        &self.object
    }

    /// Whether this reading may contribute to a bill: the meter was good, no
    /// error flag is set, and there is a value in an energy unit.
    ///
    /// This is a *necessary* condition, never a sufficient one — whether the
    /// session may be billed is a question for the chain, the key registry and
    /// the law, not for one reading.
    #[must_use]
    pub fn is_billable(&self) -> bool {
        self.state.is_some_and(MeterState::is_ok)
            && !self.error_flags.any()
            && self.value.is_some()
            && self.unit.is_some_and(|u| u.is_energy())
    }

    /// Keys `[OCMF Tab. 7]` defines for a reading.
    pub const KNOWN_KEYS: [&'static str; 9] =
        ["TM", "TX", "RV", "RI", "RU", "RT", "CL", "EF", "ST"];
}

/// Reports a reading field whose value the closed table does not define —
/// with the value, because "not one the table defines" is half a sentence.
fn report_undefined(
    defined: bool,
    field: &str,
    at: usize,
    index: usize,
    value: &str,
    dev: &mut Vec<Deviation>,
) {
    if !defined {
        dev.push(Deviation::with_value(
            DeviationKind::UndefinedTableValue,
            Location::reading(at, index, field),
            value,
        ));
    }
}

/// Reads a reading field the tables type as a scalar.
///
/// The same leniency the payload's top level applies `[D35]`: a number or a
/// boolean where a string belongs is read as the literal text it was written
/// with and reported; a structure has no text to take, so the field is dropped
/// and reported. Neither costs the record.
fn scalar<'a>(
    obj: &Object<'a>,
    key: &'static str,
    index: usize,
    dev: &mut Vec<Deviation>,
) -> Option<Scalar<'a>> {
    match obj.get(key)? {
        crate::json::Value::Str(s) => Some((s.decode(), s.as_raw(), s.span().start)),
        crate::json::Value::Number(n) => {
            dev.push(Deviation::new(
                DeviationKind::ScalarFieldNotAString,
                Location::reading(n.span().start, index, key),
            ));
            Some((Cow::Borrowed(n.as_str()), n.as_str(), n.span().start))
        }
        crate::json::Value::Bool(b, span) => {
            let literal = if *b { "true" } else { "false" };
            dev.push(Deviation::new(
                DeviationKind::ScalarFieldNotAString,
                Location::reading(span.start, index, key),
            ));
            Some((Cow::Borrowed(literal), literal, span.start))
        }
        other => {
            dev.push(Deviation::with_value(
                DeviationKind::FieldTypeMismatch,
                Location::reading(other.span().start, index, key),
                other.kind(),
            ));
            None
        }
    }
}

/// The decoded value of a scalar field, its source text, and where it sits.
type Scalar<'a> = (Cow<'a, str>, &'a str, usize);

/// Reads a numeric reading field, reporting a value no exact decimal can hold.
fn number<'a>(
    obj: &Object<'a>,
    key: &'static str,
    index: usize,
    dev: &mut Vec<Deviation>,
) -> Option<Number<'a>> {
    let v = obj.get(key)?;
    match Number::from_value(v) {
        Ok(n) => Some(n),
        Err(text) => {
            dev.push(Deviation::with_value(
                DeviationKind::NumberUnrepresentable,
                Location::reading(v.span().start, index, key),
                text,
            ));
            None
        }
    }
}

/// Reads `RD` and resolves carry-forward across the array.
#[allow(clippy::too_many_lines, reason = "one block per field of Table 7")]
pub(crate) fn parse_readings<'a>(
    array: crate::json::Array<'a>,
    dev: &mut Vec<Deviation>,
) -> Vec<Reading<'a>> {
    let mut out: Vec<Reading<'a>> = Vec::with_capacity(array.items.len());

    for (index, item) in array.items.into_iter().enumerate() {
        let obj = match item {
            crate::json::Value::Object(o) => o,
            other => {
                // Not a reading, and nothing in it to read. The array keeps its
                // place in the record and the record keeps its signature.
                dev.push(Deviation::with_value(
                    DeviationKind::FieldTypeMismatch,
                    Location::named(other.span().start, &alloc::format!("RD[{index}]")),
                    other.kind(),
                ));
                continue;
            }
        };
        let mut explicit = Explicit::default();

        let mut time = None;
        if let Some((decoded, _, at)) = scalar(&obj, "TM", index, dev) {
            explicit = explicit.with(Explicit::TIME);
            let loc = Location::reading(at, index, "TM");
            time = OcmfTime::parse(&decoded, &loc, dev);
            if time.is_none() {
                dev.push(Deviation::with_value(
                    DeviationKind::TimeMalformed,
                    loc,
                    &decoded,
                ));
            }
        }

        let transaction = scalar(&obj, "TX", index, dev).map(|(decoded, _, at)| {
            explicit = explicit.with(Explicit::TRANSACTION);
            let marker = TransactionMarker::parse(&decoded);
            report_undefined(marker.is_defined(), "TX", at, index, &decoded, dev);
            marker
        });

        let mut value = None;
        if let Some(v) = obj.get("RV") {
            if v.as_str().is_some() {
                dev.push(Deviation::new(
                    DeviationKind::RvIsString,
                    Location::reading(v.span().start, index, "RV"),
                ));
            }
            explicit = explicit.with(Explicit::VALUE);
            value = number(&obj, "RV", index, dev);
        }

        let mut obis = None;
        if let Some((decoded, _, at)) = scalar(&obj, "RI", index, dev) {
            explicit = explicit.with(Explicit::OBIS);
            let loc = Location::reading(at, index, "RI");
            let text = decoded.clone();
            obis = ObisCode::parse_cow(decoded);
            match &obis {
                Some(code) if !code.is_canonical() => dev.push(Deviation::with_value(
                    DeviationKind::ObisNonCanonical,
                    loc,
                    &text,
                )),
                Some(_) => {}
                None => dev.push(Deviation::with_value(
                    DeviationKind::ObisMalformed,
                    loc,
                    &text,
                )),
            }
        }

        // Matched on the decoded value: `"\u006bWh"` is a lawful spelling of
        // `"kWh"`, and reading it as an unknown unit would make a lawful
        // reading silently unbillable.
        let unit = scalar(&obj, "RU", index, dev).map(|(decoded, raw, at)| {
            explicit = explicit.with(Explicit::UNIT);
            let unit = Unit::from_parts(&decoded, raw);
            report_undefined(unit.is_defined(), "RU", at, index, &decoded, dev);
            unit
        });

        let current_type = scalar(&obj, "RT", index, dev).map(|(decoded, raw, at)| {
            explicit = explicit.with(Explicit::CURRENT_TYPE);
            let current = CurrentType::from_parts(&decoded, raw);
            report_undefined(current.is_defined(), "RT", at, index, &decoded, dev);
            current
        });

        let cumulated_loss = if obj.contains("CL") {
            explicit = explicit.with(Explicit::CUMULATED_LOSS);
            number(&obj, "CL", index, dev)
        } else {
            None
        };

        let error_flags = match scalar(&obj, "EF", index, dev) {
            Some((decoded, _, at)) => {
                explicit = explicit.with(Explicit::ERROR_FLAGS);
                // The *decoded* value, like every other closed table: `"E"`
                // is a lawful spelling of `"E"`, and a reader that compared the
                // source bytes would report the station's own energy fault as an
                // unknown flag character.
                let flags = ErrorFlags::new(decoded);
                report_undefined(
                    flags.undefined().next().is_none(),
                    "EF",
                    at,
                    index,
                    flags.as_str(),
                    dev,
                );
                Some(flags)
            }
            None => None,
        };

        let state = scalar(&obj, "ST", index, dev).map(|(decoded, _, at)| {
            explicit = explicit.with(Explicit::STATE);
            let state = MeterState::parse(&decoded);
            report_undefined(state.is_defined(), "ST", at, index, &decoded, dev);
            state
        });

        // Vendor extensions inside a reading: the specification reserves
        // extension initials only at the payload's top level, yet this is
        // where they occur in the field (LEM's `UC`, others' `XI`/`XT`/`EI`).
        for (k, _) in obj.extras(&Reading::KNOWN_KEYS) {
            let name = k.decode();
            dev.push(Deviation::with_value(
                DeviationKind::ExtensionInsideReading,
                Location::reading(k.span().start, index, &name),
                &name,
            ));
        }

        let previous = out.last();
        let mut carried = |present: bool, field: &str| {
            if !present && previous.is_some() {
                dev.push(Deviation::new(
                    DeviationKind::CarriedForwardMandatoryField,
                    Location::reading(obj.span().start, index, field),
                ));
            }
        };
        carried(time.is_some(), "TM");
        carried(unit.is_some() || obis.is_some(), "RU");
        carried(state.is_some(), "ST");

        // `RI` and `RU` are a group: carried together or not at all.
        let (obis, unit) = match (obis, unit) {
            (None, None) => previous.map_or((None, None), |p| (p.obis.clone(), p.unit)),
            pair => pair,
        };

        // …and after resolution, the fields `[OCMF Tab. 7]` marks `1..1` must
        // actually have a value. Carry-forward makes them optional *on the
        // wire*, not optional in the record: a first reading with no `TM` has
        // nothing to inherit and nothing to report a time from.
        let resolved_time = time.or_else(|| previous.and_then(|p| p.time));
        let resolved_state = state.or_else(|| previous.and_then(|p| p.state));
        let mut missing = |field: &str| {
            dev.push(Deviation::new(
                DeviationKind::MandatoryReadingFieldMissing,
                Location::reading(obj.span().start, index, field),
            ));
        };
        if resolved_time.is_none() {
            missing("TM");
        }
        if resolved_state.is_none() {
            missing("ST");
        }
        // The table's exemption — "can be omitted if only the occurrence of an
        // error condition (event) … is to be indicated" — is an exemption for a
        // reading with no value. A value with no unit is not a quantity.
        if value.is_some() && unit.is_none() {
            missing("RU");
        }

        out.push(Reading {
            time: resolved_time,
            transaction: transaction.or_else(|| previous.and_then(|p| p.transaction)),
            value,
            obis,
            unit,
            current_type: current_type.or_else(|| previous.and_then(|p| p.current_type)),
            cumulated_loss,
            error_flags: error_flags
                .or_else(|| previous.map(|p| p.error_flags.clone()))
                .unwrap_or_default(),
            state: resolved_state,
            explicit,
            object: obj,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{Value, parse_value};
    use crate::limits::Limits;
    use alloc::vec;

    fn readings(src: &str) -> (Vec<Reading<'_>>, Vec<Deviation>) {
        let mut dev = vec![];
        let v = parse_value(src, 0, &Limits::DEFAULT, &mut dev).unwrap();
        let Value::Array(a) = v else {
            panic!("not an array")
        };
        let r = parse_readings(a, &mut dev);
        (r, dev)
    }

    /// The LEM DCBM shape, verbatim from the reference corpus.
    const LEM: &str = r#"[
        {"TM":"2021-10-06T13:13:56,000+0200 R","TX":"B","RV":57.584,"RI":"1-0:1.8.0","RU":"kWh","RT":"DC","EF":"","ST":"G"},
        {"RV":4.405,"RI":"1-0:2.8.0","RU":"kWh","ST":"G"},
        {"TM":"2021-10-06T13:15:13,000+0200 R","TX":"E","RV":58.685,"RI":"1-0:1.8.0","RU":"kWh","ST":"G"},
        {"RV":4.405,"RI":"1-0:2.8.0","RU":"kWh","ST":"G"}
    ]"#;

    #[test]
    fn time_and_transaction_carry_forward() {
        let (r, _) = readings(LEM);
        assert!(r[1].explicit().has(Explicit::VALUE));
        assert!(!r[1].explicit().has(Explicit::TIME));
        assert_eq!(r[1].time(), r[0].time(), "TM carried");
        assert_eq!(r[1].transaction(), Some(TransactionMarker::Begin));
        assert_eq!(r[3].transaction(), Some(TransactionMarker::End));
    }

    #[test]
    fn current_type_carries_but_the_register_does_not() {
        let (r, _) = readings(LEM);
        assert_eq!(r[1].current_type(), Some(CurrentType::Dc), "RT carried");
        assert_eq!(r[1].obis().unwrap().as_str(), "1-0:2.8.0", "RI is its own");
    }

    #[test]
    fn a_carried_mandatory_field_is_reported() {
        let (_, dev) = readings(LEM);
        assert!(
            dev.iter()
                .any(|d| d.kind == DeviationKind::CarriedForwardMandatoryField),
            "TM was carried and that is worth saying"
        );
    }

    #[test]
    fn error_flags_carry_forward_so_a_fault_is_not_cleared_by_omission() {
        let (r, _) = readings(
            r#"[
                {"TM":"2021-10-06T13:13:56,000+0200 R","TX":"B","RV":1,"RI":"1-0:1.8.0","RU":"kWh","EF":"E","ST":"G"},
                {"RV":2}
            ]"#,
        );
        assert!(r[1].error_flags().energy_unusable(), "the fault carries");
        assert!(!r[1].is_billable());
    }

    #[test]
    fn a_mandatory_field_with_nothing_to_carry_from_is_reported() {
        // Carry-forward makes `TM` and `ST` optional *on the wire*, not
        // optional in the record. The first reading has nothing to inherit.
        let (r, dev) = readings(r#"[{"TX":"B","RV":1,"RI":"1-0:1.8.0","RU":"kWh"}]"#);
        assert!(r[0].time().is_none() && r[0].state().is_none());
        let missing: Vec<_> = dev
            .iter()
            .filter(|d| d.kind == DeviationKind::MandatoryReadingFieldMissing)
            .filter_map(|d| d.at.path.clone())
            .collect();
        assert_eq!(missing, ["RD[0].TM", "RD[0].ST"]);
        assert!(!r[0].is_billable());

        // A value with no unit is not a quantity, whatever the event exemption
        // says about readings that carry no value at all.
        let (_, dev) =
            readings(r#"[{"TM":"2024-03-01T08:00:00,000+0100 S","TX":"B","RV":1,"ST":"G"}]"#);
        assert!(
            dev.iter()
                .any(|d| d.kind == DeviationKind::MandatoryReadingFieldMissing
                    && d.at.path.as_deref() == Some("RD[0].RU"))
        );

        // …and an event-only reading, which the table exempts, is clean.
        let (_, dev) =
            readings(r#"[{"TM":"2024-03-01T08:00:00,000+0100 S","TX":"X","EF":"E","ST":"F"}]"#);
        assert!(
            !dev.iter()
                .any(|d| d.kind == DeviationKind::MandatoryReadingFieldMissing),
            "{dev:?}"
        );
    }

    #[test]
    fn an_omitted_ef_on_the_first_reading_is_genuinely_no_flags() {
        let (r, _) = readings(
            r#"[{"TM":"2021-10-06T13:13:56,000+0200 S","TX":"B","RV":1,"RI":"1-0:1.8.0","RU":"kWh","ST":"G"}]"#,
        );
        assert!(!r[0].error_flags().any());
        assert!(r[0].is_billable());
    }

    #[test]
    fn a_value_never_carries_because_an_omitted_rv_may_mean_an_event() {
        let (r, _) = readings(
            r#"[
                {"TM":"2021-10-06T13:13:56,000+0200 S","TX":"B","RV":1,"RI":"1-0:1.8.0","RU":"kWh","ST":"G"},
                {"TX":"X","EF":"E","ST":"F"}
            ]"#,
        );
        assert!(r[1].value().is_none(), "an event reading has no value");
        assert!(!r[1].is_billable());
    }

    #[test]
    fn an_escaped_unit_is_still_the_unit_it_spells() {
        // `\u006bWh` is `kWh`. Comparing the raw text would make this reading
        // carry an unknown unit — and an unknown unit is not energy, so a
        // lawful reading would quietly stop being billable.
        let (r, _) = readings(
            r#"[{"TM":"2024-03-01T08:00:00,000+0100 S","TX":"B","RV":1,"RI":"1-b:1.8.0","RU":"kWh","RT":"DC","EF":"","ST":"G"}]"#,
        );
        assert_eq!(r[0].unit(), Some(Unit::KWh));
        assert_eq!(r[0].current_type(), Some(CurrentType::Dc));
        assert!(r[0].is_billable());
    }

    #[test]
    fn a_quoted_reading_value_parses_and_is_reported() {
        let (r, dev) = readings(
            r#"[{"TM":"2023-06-27T18:02:28,000+0200 I","TX":"B","RV":"00000000.000","RI":"1-b:1.8.e","RU":"kWh","ST":"G"}]"#,
        );
        assert!(r[0].value().unwrap().was_quoted());
        assert!(dev.iter().any(|d| d.kind == DeviationKind::RvIsString));
    }

    #[test]
    fn a_vendor_extension_inside_a_reading_is_reported_and_kept() {
        let (r, dev) = readings(
            r#"[{"TM":"2021-10-06T13:13:56,000+0200 R","TX":"B","RV":1,"RI":"1-0:1.8.0","RU":"kWh","ST":"G","UC":{"UN":"No_Comp","UI":2,"UR":0}}]"#,
        );
        assert!(
            dev.iter()
                .any(|d| d.kind == DeviationKind::ExtensionInsideReading)
        );
        assert!(
            r[0].object().contains("UC"),
            "and it survives in the object"
        );
    }
}
