//! The rules the specification assigns to a *check component*, not to the
//! format.
//!
//! > "The cohesion between several individual data records is ensured by
//! > continuous pagination. In addition to the signature, this must be verified
//! > by a check component. The first record must be marked as the start of a
//! > charging process, the last as the end of the charging process. In between,
//! > no data records may have been removed or added. Likewise, intermediate
//! > error conditions (error counters) and the detection of unusable variables
//! > must lead to an error during the test. Furthermore, all data records must
//! > come from the same source (serial number)."
//! > `[OCMF §Signing and Verification Process]`
//!
//! Every sentence of that is a check here. The reference verifier adds four
//! more in `checkLawIntegrityForTransaction` — exactly one begin and one end,
//! `RV(start) ≤ RV(stop)`, `t(start) ≤ t(stop)`, `ST == G` on both, and an `IL`
//! outside the four error states — and those are here too, because that is the
//! behaviour a driver's own check will show them.
//!
//! # This module does not decide money
//!
//! It reports findings. Whether a session may be invoiced depends on tariffs,
//! on a key registry binding each record to *this* charge point, and on law —
//! none of which is in scope. What it does guarantee is that no finding is
//! silently absent: a clean [`SessionReport`] means every rule above held.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use ocmf::{Finding, Record, session};
//!
//! let one = |page: u32, marker: &str, value: &str| {
//!     format!(
//!         r#"OCMF|{{"FV":"1.3","PG":"T{page}","MS":"M-1","IS":true,"IL":"VERIFIED","IF":[],"IT":"NONE","RD":[{{"TM":"2024-03-01T0{page}:00:00,000+0100 S","TX":"{marker}","RV":{value},"RI":"01-00:B1.08.00*FF","RU":"kWh","EF":"","ST":"G"}}]}}|{{"SD":"00"}}"#
//!     )
//! };
//!
//! let texts = [one(1, "B", "100.000"), one(2, "E", "129.500")];
//! let records: Vec<Record<'_>> = texts
//!     .iter()
//!     .map(|t| Record::parse(t))
//!     .collect::<Result<_, _>>()?;
//!
//! let report = session::validate(&records);
//! assert!(report.is_clean(), "{:?}", report.findings());
//! assert_eq!(report.totals()[0].delta.to_string(), "29.500");
//!
//! // Remove the second record and the pagination says so.
//! let short = session::validate(&records[..1]);
//! assert!(short.findings().contains(&Finding::NoEnd));
//! # Ok(()) }
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use rust_decimal::Decimal;

use crate::payload::{MeterState, TransactionMarker};
use crate::record::Record;
use crate::time::TimeStatus;

/// One thing wrong with a sequence of records.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "finding"))]
#[non_exhaustive]
pub enum Finding {
    /// No records at all.
    Empty,
    /// The pagination counter skipped, repeated or went backwards — records
    /// were removed, duplicated or reordered `[OCMF Tab. 2]`.
    PaginationBroken {
        /// The counter value of the earlier record.
        from: u64,
        /// The counter value of the record that followed it.
        to: u64,
        /// Index of the later record.
        index: usize,
    },
    /// A record carries no readable `PG`, so it has no place in the sequence
    /// `[OCMF Tab. 2]`.
    PaginationUnreadable {
        /// Index of the record.
        index: usize,
    },
    /// Two records belong to different pagination contexts.
    PaginationContextChanged {
        /// Index of the record that changed it.
        index: usize,
    },
    /// No reading anywhere marks the beginning of the transaction.
    NoBegin,
    /// No reading anywhere marks its end.
    NoEnd,
    /// More than one reading marks the beginning.
    MultipleBegins,
    /// More than one reading marks the end.
    MultipleEnds,
    /// The transaction begins somewhere other than in the first record, or ends
    /// somewhere other than in the last.
    MarkerOutOfPlace {
        /// Index of the record carrying the misplaced marker.
        index: usize,
    },
    /// The records do not all come from the same meter or gateway.
    SourceChanged {
        /// Index of the record that changed it.
        index: usize,
        /// The serial the sequence started with.
        expected: String,
        /// The serial this record carries.
        found: String,
    },
    /// A reading reports a meter that was not working correctly
    /// `[OCMF Tab. 10]`.
    MeterNotOk {
        /// Index of the record.
        index: usize,
        /// The state reported.
        state: MeterState,
    },
    /// A reading carries an error flag: energy or time is unusable for billing
    /// `[OCMF Tab. 7]`.
    ErrorFlagged {
        /// Index of the record.
        index: usize,
        /// The flags, as written.
        flags: String,
    },
    /// A reading marks an exception, abort or power failure `[OCMF Tab. 7]`.
    TransactionFaulted {
        /// Index of the record.
        index: usize,
        /// The marker.
        marker: TransactionMarker,
    },
    /// The user assignment reports an error `[OCMF Tab. 11]`.
    IdentificationError {
        /// Index of the record.
        index: usize,
        /// The level reported.
        level: String,
    },
    /// A register's end reading is below its begin reading.
    MeterWentBackwards {
        /// The register.
        obis: String,
    },
    /// A register has an end reading and no begin reading anywhere in the
    /// sequence, so nothing can be subtracted from anything.
    ///
    /// The reference verifier compares the *largest* start against the
    /// *smallest* stop across every law-relevant register at once
    /// (`Meter.validateListStartStop`), which pairs an import start with an
    /// export stop on the interleaved records LEM meters write. This is the
    /// same question asked per register, which is the only way it has an
    /// answer.
    RegisterEndWithoutBegin {
        /// The register.
        obis: String,
    },
    /// The end reading is stamped earlier than the begin reading.
    TimeWentBackwards,
    /// Some reading in the sequence came from a clock that cannot support a
    /// time-based tariff `[OCMF Tab. 19]`.
    ///
    /// Judged on the **weakest** clock in the sequence, not the strongest: one
    /// synchronised reading says nothing about the twenty around it, and the
    /// error of taking the best one always runs towards billing.
    ClockNotSynchronised {
        /// The weakest status seen, or `None` when no reading carried one.
        status: Option<TimeStatus>,
    },
    /// Two records carry the same payload — the same statement counted twice.
    DuplicateRecord {
        /// Index of the repeat.
        index: usize,
    },
}

impl core::fmt::Display for Finding {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("no records"),
            Self::PaginationBroken { from, to, index } => write!(
                f,
                "pagination went {from} → {to} at record {index}: a record was removed, duplicated or reordered"
            ),
            Self::PaginationUnreadable { index } => {
                write!(f, "record {index} has no readable `PG` counter")
            }
            Self::PaginationContextChanged { index } => {
                write!(
                    f,
                    "record {index} belongs to a different pagination context"
                )
            }
            Self::NoBegin => f.write_str("no reading marks the begin of the transaction"),
            Self::NoEnd => f.write_str("no reading marks the end of the transaction"),
            Self::MultipleBegins => f.write_str("more than one reading marks the begin"),
            Self::MultipleEnds => f.write_str("more than one reading marks the end"),
            Self::MarkerOutOfPlace { index } => write!(
                f,
                "record {index} carries a begin or end marker out of its place in the sequence"
            ),
            Self::SourceChanged {
                index,
                expected,
                found,
            } => write!(
                f,
                "record {index} comes from {found}, the sequence started with {expected}"
            ),
            Self::MeterNotOk { index, state } => write!(
                f,
                "record {index} reports meter state {state} ({})",
                state.identifier()
            ),
            Self::ErrorFlagged { index, flags } => {
                write!(f, "record {index} flags {flags} as unusable for billing")
            }
            Self::TransactionFaulted { index, marker } => {
                write!(f, "record {index} marks the transaction {marker}")
            }
            Self::IdentificationError { index, level } => {
                write!(f, "record {index} reports user assignment error {level}")
            }
            Self::MeterWentBackwards { obis } => {
                write!(f, "register {obis} ends below where it began")
            }
            Self::RegisterEndWithoutBegin { obis } => {
                write!(f, "register {obis} has an end reading and no begin")
            }
            Self::TimeWentBackwards => f.write_str("the end is stamped before the begin"),
            Self::ClockNotSynchronised { status } => match status {
                Some(s) => write!(
                    f,
                    "the weakest clock in the sequence is `{}`, which cannot support a duration",
                    s.letter()
                ),
                None => f.write_str("no reading carries a clock status"),
            },
            Self::DuplicateRecord { index } => {
                write!(
                    f,
                    "record {index} repeats a payload already in the sequence"
                )
            }
        }
    }
}

/// Which rules a sequence is judged by `[OCMF Tab. 2]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum SequenceKind {
    /// The records reference a transaction, so every rule applies: one begin in
    /// the first record, one end in the last, nothing removed in between.
    #[default]
    Transaction,
    /// **Fiscal readings, independent of transactions.**
    ///
    /// `[OCMF Tab. 2]` defines the `F` pagination context as exactly that, and
    /// `[OCMF Tab. 7]` says an absent `TX` means "fiscal, no transaction". So a
    /// fiscal sequence *cannot* carry a begin or an end marker, and demanding
    /// one reports a fault against a record for obeying the specification.
    ///
    /// Everything else still applies: continuous pagination, one source, no
    /// repeats, meter state, error flags, the clock. Only the four
    /// transaction-marker rules are skipped, and
    /// [`RegisterTotal`] is then first-to-last rather than begin-to-end.
    Fiscal,
}

/// The energy a register moved across the whole sequence.
///
/// Arithmetic, not authorisation: it says nothing about whether the meter was
/// healthy or the assignment held. Read [`SessionReport::findings`] for that.
///
/// For a [`SequenceKind::Transaction`] sequence the ends are the readings
/// marked `TX = B` and `TX = E`; for a [`SequenceKind::Fiscal`] one they are
/// the first and last readings of the register, because a fiscal reading
/// carries no marker to find.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct RegisterTotal {
    /// The canonical OBIS code.
    pub obis: String,
    /// The begin reading.
    #[cfg_attr(feature = "serde", serde(serialize_with = "decimal_as_text"))]
    pub begin: Decimal,
    /// The end reading.
    #[cfg_attr(feature = "serde", serde(serialize_with = "decimal_as_text"))]
    pub end: Decimal,
    /// `end − begin`.
    #[cfg_attr(feature = "serde", serde(serialize_with = "decimal_as_text"))]
    pub delta: Decimal,
    /// The unit both readings were in.
    pub unit: String,
}

/// Writes a decimal as its **exact text**, never as a JSON number.
///
/// The same rule [`RecordSummary`](crate::RecordSummary) follows and for the
/// same reason: a JSON number goes through `f64` in most consumers, `f64`
/// cannot hold `9.2`, and these are kilowatt-hours somebody is invoiced for.
#[cfg(feature = "serde")]
fn decimal_as_text<S: serde::Serializer>(d: &Decimal, s: S) -> Result<S::Ok, S::Error> {
    use alloc::string::ToString as _;
    s.serialize_str(&d.to_string())
}

/// What a sequence of records says about itself.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SessionReport {
    kind: SequenceKind,
    /// Empty when every rule held — which is what `is_clean` reports.
    findings: Vec<Finding>,
    totals: Vec<RegisterTotal>,
    /// The clock the sequence is judged on: the **weakest** one in it.
    worst_clock: Option<TimeStatus>,
    best_clock: Option<TimeStatus>,
}

impl SessionReport {
    /// Everything wrong with the sequence, in the order the checks ran.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Which rule set was applied — and therefore which findings were even
    /// possible.
    #[must_use]
    pub const fn kind(&self) -> SequenceKind {
        self.kind
    }

    /// Whether every rule held.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Per-register begin, end and difference.
    #[must_use]
    pub fn totals(&self) -> &[RegisterTotal] {
        &self.totals
    }

    /// The **weakest** clock status seen anywhere in the sequence — the one the
    /// session should be judged on.
    ///
    /// `None` when no reading carried a status letter at all, which is not the
    /// same as "unknown": it means the record never said.
    #[must_use]
    pub const fn clock(&self) -> Option<TimeStatus> {
        self.worst_clock
    }

    /// The strongest clock status seen anywhere in the sequence.
    ///
    /// Reported for completeness. Nothing should be authorised on it: see
    /// [`Self::clock`].
    #[must_use]
    pub const fn best_clock(&self) -> Option<TimeStatus> {
        self.best_clock
    }
}

/// Runs every check-component rule over records whose signatures have already
/// been checked.
///
/// The rules are the same as [`validate`]'s. The difference is what the
/// signature of this function says: a `SessionReport` over unverified records
/// answers "do these records hang together", never "is this session real", and
/// the two are easy to confuse at a call site three files away. Where a caller
/// has [`Verified`](crate::Verified) values in hand, threading them through
/// keeps the two questions visibly answered rather than visibly conflated.
#[cfg(feature = "verify")]
#[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
#[must_use]
pub fn validate_verified(verified: &[crate::Verified<'_, '_>]) -> SessionReport {
    let records: Vec<&Record<'_>> = verified.iter().map(crate::Verified::record).collect();
    validate_refs(&records)
}

/// Runs every check-component rule over a transaction's records, in order.
///
/// The records must be in the order the station produced them; this function
/// checks that the pagination agrees, it does not sort.
///
/// **This says nothing about the signatures.** Checking those is
/// [`verify()`](crate::verify()), and [`validate_verified`] is the entry point that
/// keeps the two questions apart at the call site.
#[must_use]
pub fn validate(records: &[Record<'_>]) -> SessionReport {
    let refs: Vec<&Record<'_>> = records.iter().collect();
    validate_refs(&refs)
}

/// As [`validate`], over borrowed records.
///
/// The implementation both other entry points share, and the one to call when a
/// caller already holds `&Record` values — out of a `Vec<Verified>`, or out of
/// several containers — rather than a contiguous slice of owned ones.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn validate_refs(records: &[&Record<'_>]) -> SessionReport {
    let mut report = SessionReport::default();
    let Some(first) = records.first() else {
        report.findings.push(Finding::Empty);
        return report;
    };
    // `[OCMF Tab. 2]`: `F` is "fiscal readings, independent of transactions",
    // and `[OCMF Tab. 7]` makes an absent `TX` mean the same thing. A sequence
    // where no record refers to a transaction cannot carry a begin or an end,
    // and asking it for one reports a fault against a record for obeying the
    // specification. Every other rule still applies.
    report.kind = if records.iter().any(|r| r.payload().is_transaction()) {
        SequenceKind::Transaction
    } else {
        SequenceKind::Fiscal
    };

    // ── Pagination: continuous, one context, nothing removed ───────────────
    //
    // A record whose `PG` is absent or unreadable cannot take its place in the
    // sequence at all. That is a finding of its own rather than a break between
    // two neighbours, because the counter that would say which is missing.
    for (i, r) in records.iter().enumerate() {
        if r.payload().pagination().is_none() {
            report
                .findings
                .push(Finding::PaginationUnreadable { index: i });
        }
    }
    for (i, pair) in records.windows(2).enumerate() {
        let (Some(a), Some(b)) = (
            pair[0].payload().pagination(),
            pair[1].payload().pagination(),
        ) else {
            continue;
        };
        if a.context() != b.context() {
            report
                .findings
                .push(Finding::PaginationContextChanged { index: i + 1 });
        } else if !a.is_followed_by(&b) {
            report.findings.push(Finding::PaginationBroken {
                from: a.number(),
                to: b.number(),
                index: i + 1,
            });
        }
    }

    // ── One source ─────────────────────────────────────────────────────────
    let source = |r: &&Record<'_>| -> String {
        let p = r.payload();
        match (p.meter_serial(), p.gateway_serial()) {
            (Some(m), Some(g)) => alloc::format!("{g}/{m}"),
            (Some(m), None) => String::from(m),
            (None, Some(g)) => String::from(g),
            (None, None) => String::new(),
        }
    };
    let expected = source(first);
    for (i, r) in records.iter().enumerate().skip(1) {
        let found = source(r);
        if found != expected {
            report.findings.push(Finding::SourceChanged {
                index: i,
                expected: expected.clone(),
                found,
            });
        }
    }

    // ── No record repeated ─────────────────────────────────────────────────
    #[cfg(feature = "digest")]
    {
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(records.len());
        for (i, r) in records.iter().enumerate() {
            let d = r.payload_digest();
            if seen.contains(&d) {
                report.findings.push(Finding::DuplicateRecord { index: i });
            }
            seen.push(d);
        }
    }

    // ── Markers, meter state, error flags, user assignment ─────────────────
    let mut begins = Vec::new();
    let mut ends = Vec::new();
    for (i, r) in records.iter().enumerate() {
        let p = r.payload();
        if let Some(level) = p.identification_level()
            && level.is_error()
        {
            report.findings.push(Finding::IdentificationError {
                index: i,
                level: String::from(level.as_str()),
            });
        }
        for reading in p.readings() {
            match reading.state() {
                Some(st) if !st.is_ok() => {
                    report.findings.push(Finding::MeterNotOk {
                        index: i,
                        state: st,
                    });
                }
                _ => {}
            }
            if reading.error_flags().any() {
                report.findings.push(Finding::ErrorFlagged {
                    index: i,
                    flags: String::from(reading.error_flags().as_str()),
                });
            }
            if let Some(tx) = reading.transaction() {
                if tx.is_fault() {
                    report.findings.push(Finding::TransactionFaulted {
                        index: i,
                        marker: tx,
                    });
                }
                if tx.is_begin() {
                    begins.push(i);
                }
                if tx.is_end() {
                    ends.push(i);
                }
            }
            if let Some(t) = reading.time() {
                // A `TM` with no status letter is a clock that declined to say
                // anything about itself, which is the weakest statement there
                // is — weaker than `U`, but the format has no letter for it, so
                // it is folded into `Unknown` rather than invented.
                let status = t.status.unwrap_or(TimeStatus::Unknown);
                report.worst_clock = Some(report.worst_clock.map_or(status, |w| w.min(status)));
                report.best_clock = Some(report.best_clock.map_or(status, |b| {
                    if status.rank() > b.rank() { status } else { b }
                }));
            }
        }
    }

    // A record can legitimately carry several registers, each with its own
    // begin and end — the markers are counted per record, not per reading.
    begins.dedup();
    ends.dedup();
    if report.kind == SequenceKind::Transaction {
        check_markers(&begins, &ends, records.len(), &mut report.findings);
    }
    if report.worst_clock.is_none_or(|s| !s.duration_is_billable()) {
        report.findings.push(Finding::ClockNotSynchronised {
            status: report.worst_clock,
        });
    }

    // ── Per-register ends, across the whole sequence ───────────────────────
    //
    // A transaction names its own ends with `TX`; a fiscal sequence has none to
    // name, so its ends are the first and last readings of each register. Both
    // are arithmetic over what the records say, and neither authorises anything.
    let mut totals: Vec<RegisterTotal> = Vec::new();
    let mut unpaired: Vec<String> = Vec::new();
    let mut begin_time = None;
    let mut end_time = None;
    let fiscal = report.kind == SequenceKind::Fiscal;
    for r in records {
        for series in r.payload().by_register() {
            let (opens, closes) = if fiscal {
                (
                    series.readings.first().copied(),
                    series.readings.last().copied(),
                )
            } else {
                (series.begin(), series.end())
            };
            if let Some(b) = opens
                && let (Some(v), Some(u)) = (b.value(), b.unit())
                && !totals.iter().any(|t| t.obis == series.obis)
            {
                totals.push(RegisterTotal {
                    obis: series.obis.clone(),
                    begin: v.value(),
                    end: v.value(),
                    delta: Decimal::ZERO,
                    unit: String::from(u.as_str()),
                });
                begin_time = begin_time.or_else(|| b.time().map(|t| t.unix_millis()));
            }
            if let Some(e) = closes
                && let Some(v) = e.value()
            {
                match totals.iter_mut().find(|t| t.obis == series.obis) {
                    Some(t) => {
                        t.end = v.value();
                        t.delta = t.end - t.begin;
                        if let Some(stamp) = e.time() {
                            end_time = Some(stamp.unix_millis());
                        }
                    }
                    None => unpaired.push(series.obis.clone()),
                }
            }
        }
    }
    for t in &totals {
        if t.delta < Decimal::ZERO {
            report.findings.push(Finding::MeterWentBackwards {
                obis: t.obis.clone(),
            });
        }
    }
    unpaired.dedup();
    for obis in unpaired {
        report
            .findings
            .push(Finding::RegisterEndWithoutBegin { obis });
    }
    if let (Some(b), Some(e)) = (begin_time, end_time)
        && e < b
    {
        report.findings.push(Finding::TimeWentBackwards);
    }
    report.totals = totals;
    report
}

/// The four transaction-marker rules `[OCMF §Signing and Verification Process]`
/// assigns to a check component: one begin, one end, in the right places.
fn check_markers(begins: &[usize], ends: &[usize], count: usize, out: &mut Vec<Finding>) {
    match begins {
        [] => out.push(Finding::NoBegin),
        [only] if *only != 0 => out.push(Finding::MarkerOutOfPlace { index: *only }),
        [_] => {}
        _ => out.push(Finding::MultipleBegins),
    }
    match ends {
        [] => out.push(Finding::NoEnd),
        [only] if *only != count - 1 => out.push(Finding::MarkerOutOfPlace { index: *only }),
        [_] => {}
        _ => out.push(Finding::MultipleEnds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Record;
    use alloc::string::ToString;
    use alloc::vec;

    fn record(pg: u32, tx: &str, rv: &str, extra: &str) -> String {
        alloc::format!(
            r#"OCMF|{{"FV":"1.4","GS":"GW-1","PG":"T{pg}","MS":"METER-1","IS":true,"IL":"VERIFIED","IF":[],"IT":"ISO14443","ID":"AA","RD":[{{"TM":"2018-07-24T13:{:02}:04,000+0200 S","TX":"{tx}","RV":{rv},"RI":"1-b:1.8.0","RU":"kWh","EF":"","ST":"G"{extra}}}]}}|{{"SD":"00"}}"#,
            20 + pg
        )
    }

    fn parse_all(texts: &[String]) -> Vec<Record<'_>> {
        texts.iter().map(|t| Record::parse(t).unwrap()).collect()
    }

    #[test]
    fn a_clean_two_record_session_reports_nothing() {
        let texts = vec![record(1, "B", "10.000", ""), record(2, "E", "12.500", "")];
        let report = validate(&parse_all(&texts));
        assert!(report.is_clean(), "{:?}", report.findings());
        assert_eq!(report.totals()[0].delta.to_string(), "2.500");
        assert_eq!(report.clock(), Some(TimeStatus::Synchronized));
    }

    #[test]
    fn a_removed_record_is_caught_by_the_pagination() {
        let texts = vec![record(1, "B", "10.000", ""), record(3, "E", "12.500", "")];
        let report = validate(&parse_all(&texts));
        assert!(report.findings().contains(&Finding::PaginationBroken {
            from: 1,
            to: 3,
            index: 1
        }));
    }

    #[test]
    fn a_session_that_never_ends_is_not_a_session() {
        let texts = vec![record(1, "B", "10.000", "")];
        let report = validate(&parse_all(&texts));
        assert!(report.findings().contains(&Finding::NoEnd));
    }

    #[test]
    fn records_from_another_meter_do_not_belong_to_this_session() {
        let texts = vec![
            record(1, "B", "10.000", ""),
            record(2, "E", "12.500", "").replace("METER-1", "METER-2"),
        ];
        let report = validate(&parse_all(&texts));
        assert!(
            report
                .findings()
                .iter()
                .any(|f| matches!(f, Finding::SourceChanged { .. }))
        );
    }

    #[test]
    fn a_meter_fault_and_an_error_flag_are_both_findings() {
        let texts = vec![
            record(1, "B", "10.000", ""),
            record(2, "E", "12.500", "").replace(r#""ST":"G""#, r#""ST":"F""#),
        ];
        let report = validate(&parse_all(&texts));
        assert!(
            report
                .findings()
                .iter()
                .any(|f| matches!(f, Finding::MeterNotOk { .. }))
        );

        let texts = vec![
            record(1, "B", "10.000", ""),
            record(2, "E", "12.500", "").replace(r#""EF":"""#, r#""EF":"E""#),
        ];
        let report = validate(&parse_all(&texts));
        assert!(
            report
                .findings()
                .iter()
                .any(|f| matches!(f, Finding::ErrorFlagged { .. }))
        );
    }

    #[test]
    fn a_meter_that_runs_backwards_is_a_finding() {
        let texts = vec![record(1, "B", "12.500", ""), record(2, "E", "10.000", "")];
        let report = validate(&parse_all(&texts));
        assert!(
            report
                .findings()
                .iter()
                .any(|f| matches!(f, Finding::MeterWentBackwards { .. }))
        );
    }

    #[test]
    fn an_unsynchronised_clock_blocks_a_time_tariff() {
        let texts = vec![
            record(1, "B", "10.000", "").replace("+0200 S", "+0200 U"),
            record(2, "E", "12.500", "").replace("+0200 S", "+0200 U"),
        ];
        let report = validate(&parse_all(&texts));
        assert!(
            report
                .findings()
                .iter()
                .any(|f| matches!(f, Finding::ClockNotSynchronised { .. }))
        );
    }

    #[test]
    fn one_synchronised_reading_does_not_vouch_for_an_unsynchronised_session() {
        // Judging by the *best* clock would let a single `S` reading among
        // unsynchronised ones report nothing wrong, and that error always runs
        // towards billing.
        let texts = vec![
            record(1, "B", "10.000", ""),
            record(2, "E", "12.500", "").replace("+0200 S", "+0200 U"),
        ];
        let report = validate(&parse_all(&texts));
        assert_eq!(report.clock(), Some(TimeStatus::Unknown), "the weakest");
        assert_eq!(
            report.best_clock(),
            Some(TimeStatus::Synchronized),
            "reported, and not what anything is decided on"
        );
        assert!(report.findings().contains(&Finding::ClockNotSynchronised {
            status: Some(TimeStatus::Unknown)
        }));
    }

    #[test]
    fn a_relative_clock_is_good_enough_for_a_duration() {
        let texts = vec![
            record(1, "B", "10.000", "").replace("+0200 S", "+0200 R"),
            record(2, "E", "12.500", "").replace("+0200 S", "+0200 R"),
        ];
        let report = validate(&parse_all(&texts));
        assert!(
            !report
                .findings()
                .iter()
                .any(|f| matches!(f, Finding::ClockNotSynchronised { .. }))
        );
    }

    #[test]
    fn a_failed_user_assignment_is_a_finding() {
        let texts = vec![
            record(1, "B", "10.000", "").replace("VERIFIED", "MISMATCH"),
            record(2, "E", "12.500", ""),
        ];
        let report = validate(&parse_all(&texts));
        assert!(
            report
                .findings()
                .iter()
                .any(|f| matches!(f, Finding::IdentificationError { .. }))
        );
    }

    #[test]
    #[cfg(feature = "digest")]
    fn the_same_record_twice_is_caught_even_with_a_valid_pagination() {
        let one = record(1, "B", "10.000", "");
        let texts = vec![one.clone(), one];
        let report = validate(&parse_all(&texts));
        assert!(
            report
                .findings()
                .iter()
                .any(|f| matches!(f, Finding::DuplicateRecord { .. }))
        );
    }

    #[test]
    fn a_register_that_ends_without_beginning_has_no_delta_and_says_so() {
        // The export register of an interleaved record, with its begin lost.
        // The reference verifier would compare the import start against this
        // export stop and call the session valid; per register, it has no
        // answer at all, and saying so is the answer.
        let texts = vec![
            record(1, "B", "10.000", ""),
            record(2, "E", "12.500", "").replace(r#""RI":"1-b:1.8.0""#, r#""RI":"1-b:2.8.0""#),
        ];
        let report = validate(&parse_all(&texts));
        assert!(
            report
                .findings()
                .contains(&Finding::RegisterEndWithoutBegin {
                    obis: String::from("01-0B:02.08.00")
                }),
            "{:?}",
            report.findings()
        );
        assert!(report.totals().iter().all(|t| t.delta == Decimal::ZERO));
    }

    /// A fiscal record: `PG` in the `F` context and no `TX` anywhere, which is
    /// what `[OCMF Tab. 2]` and `[OCMF Tab. 7]` between them define it as.
    fn fiscal(pg: u32, rv: &str) -> String {
        alloc::format!(
            r#"OCMF|{{"FV":"1.3","PG":"F{pg}","MS":"METER-1","RD":[{{"TM":"2024-03-01T0{pg}:00:00,000+0100 S","RV":{rv},"RI":"01-00:B1.08.00*FF","RU":"kWh","EF":"","ST":"G"}}]}}|{{"SD":"00"}}"#
        )
    }

    #[test]
    fn a_fiscal_sequence_is_not_asked_for_markers_it_cannot_carry() {
        // No corpus record is fiscal, so this rule set has no third-party data
        // behind it — which makes it the one worth stating outright.
        let texts = vec![fiscal(1, "100.000"), fiscal(2, "129.500")];
        let report = validate(&parse_all(&texts));
        assert_eq!(report.kind(), SequenceKind::Fiscal);
        assert!(report.is_clean(), "{:?}", report.findings());

        // And the quantity is still reported — first to last, because a fiscal
        // reading carries no marker to find.
        assert_eq!(report.totals().len(), 1);
        assert_eq!(report.totals()[0].delta.to_string(), "29.500");
    }

    #[test]
    fn a_fiscal_sequence_is_still_held_to_every_other_rule() {
        let texts = vec![fiscal(1, "100.000"), fiscal(3, "129.500")];
        let report = validate(&parse_all(&texts));
        assert!(report.findings().contains(&Finding::PaginationBroken {
            from: 1,
            to: 3,
            index: 1
        }));

        // …including that a meter does not run backwards.
        let texts = vec![fiscal(1, "129.500"), fiscal(2, "100.000")];
        assert!(
            validate(&parse_all(&texts))
                .findings()
                .iter()
                .any(|f| matches!(f, Finding::MeterWentBackwards { .. }))
        );
    }

    #[test]
    fn a_transaction_sequence_is_still_judged_as_one() {
        let texts = vec![record(1, "B", "10.000", ""), record(2, "E", "12.500", "")];
        assert_eq!(
            validate(&parse_all(&texts)).kind(),
            SequenceKind::Transaction
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn a_report_serialises_and_the_quantities_stay_exact() {
        let texts = vec![record(1, "B", "10.000", ""), record(2, "E", "12.500", "")];
        let json = serde_json::to_string(&validate(&parse_all(&texts))).unwrap();
        // Strings, so no consumer's `f64` can round a kilowatt-hour.
        assert!(json.contains(r#""delta":"2.500""#), "{json}");
        assert!(json.contains(r#""kind":"Transaction""#), "{json}");
        assert!(json.contains(r#""worst_clock":"S""#), "{json}");

        let texts = vec![record(1, "B", "10.000", ""), record(3, "E", "12.500", "")];
        let json = serde_json::to_string(&validate(&parse_all(&texts))).unwrap();
        // …and a finding names itself in a way another tool can match on.
        assert!(json.contains(r#""finding":"PaginationBroken""#), "{json}");
    }

    #[test]
    fn an_empty_sequence_says_so() {
        assert_eq!(validate(&[]).findings(), &[Finding::Empty]);
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn the_verified_entry_point_runs_the_same_rules() {
        use crate as ocmf_self;
        use ocmf_self::sign::{ReadingSpec, RecordBuilder, Secp256r1Signer, Signer};

        let signer = Secp256r1Signer::from_bytes(&[3u8; 32]).unwrap();
        let key = signer.public_key().unwrap();
        let at =
            |s: &str| crate::OcmfTime::parse(s, &crate::Location::at(0), &mut Vec::new()).unwrap();
        let one = |page: u64, marker: TransactionMarker, value: &str| {
            RecordBuilder::new()
                .gateway("ocmf", "GW-1", "0.1.0")
                .pagination(crate::Pagination::transaction(page))
                .meter_serial("METER-1")
                .identification(
                    true,
                    crate::IdentificationLevel::Verified,
                    Vec::new(),
                    crate::IdentificationType::None,
                    "",
                )
                .reading(
                    ReadingSpec::new(
                        at("2024-03-01T08:00:00,000+0100 S"),
                        Decimal::from_str_exact(value).unwrap(),
                        "01-00:B1.08.00*FF",
                        crate::Unit::KWh,
                    )
                    .transaction(marker),
                )
                .sign(&signer)
                .unwrap()
        };
        let bufs = [
            one(1, TransactionMarker::Begin, "10.000"),
            one(2, TransactionMarker::End, "12.500"),
        ];
        let records: Vec<_> = bufs.iter().map(|b| b.record().unwrap()).collect();
        let verified: Vec<_> = records
            .iter()
            .map(|r| crate::verify(r, &key).expect("this crate signed it"))
            .collect();

        let report = validate_verified(&verified);
        assert!(report.is_clean(), "{:?}", report.findings());
        assert_eq!(report.totals()[0].delta.to_string(), "2.500");
        assert_eq!(
            report.findings(),
            validate(&records).findings(),
            "the same rules, whatever the caller holds"
        );
    }
}
