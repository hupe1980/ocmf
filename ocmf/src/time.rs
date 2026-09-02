//! `TM`: a timestamp and a synchronisation state, welded into one field.
//!
//! `[OCMF Tab. 7]` prescribes
//! `<Year>-<Month>-<Day>T<Hours>:<Minutes>:<Seconds>,<Milliseconds><Time Zone>`
//! followed by a space and one letter from `[OCMF Tab. 19]`:
//!
//! ```text
//! 2018-07-24T13:22:04,000+0200 S
//! ```
//!
//! The weld is a known wart — S.A.F.E. issue #6 asks for two fields — and until
//! it is split, it is parsed as written. The letter is not decoration: it is
//! the difference between a duration that may be billed and one that may not.
//!
//! # No clock, no calendar dependency
//!
//! This module computes a Unix instant from the civil fields itself, so the
//! crate has no date-library dependency and works on `no_std`. Conversions to
//! `time::OffsetDateTime` live behind a feature for callers who want them.
//!
//! # Example
//!
//! ```
//! use ocmf::{Location, OcmfTime, TimeStatus};
//!
//! let mut deviations = Vec::new();
//! let t = OcmfTime::parse(
//!     "2018-07-24T13:22:04,000+0200 S",
//!     &Location::at(0),
//!     &mut deviations,
//! )
//! .expect("a `TM` value");
//!
//! assert_eq!(t.status, Some(TimeStatus::Synchronized));
//! assert_eq!(t.unix_millis(), 1_532_431_324_000);
//! assert_eq!(t.to_string(), "2018-07-24T13:22:04,000+0200 S");
//!
//! // The letter decides what may be billed against this reading.
//! assert!(t.status.unwrap().instant_is_billable());
//! assert!(TimeStatus::Relative.duration_is_billable());
//! assert!(!TimeStatus::Relative.instant_is_billable());
//! ```

use crate::deviation::{Deviation, DeviationKind, Location};
use alloc::vec::Vec;

/// Synchronisation state of the clock that stamped a reading `[OCMF Tab. 19]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimeStatus {
    /// `U` — unknown, unsynchronised.
    Unknown,
    /// `I` — informative (info clock).
    Informative,
    /// `S` — synchronized.
    Synchronized,
    /// `R` — relative accounting on a calibration-law-accurate duration that
    /// started from an informative clock.
    Relative,
}

impl TimeStatus {
    /// Parses the single letter.
    #[must_use]
    pub const fn from_letter(c: u8) -> Option<Self> {
        Some(match c {
            b'U' => Self::Unknown,
            b'I' => Self::Informative,
            b'S' => Self::Synchronized,
            b'R' => Self::Relative,
            _ => return None,
        })
    }

    /// The letter as written in `TM`.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Unknown => 'U',
            Self::Informative => 'I',
            Self::Synchronized => 'S',
            Self::Relative => 'R',
        }
    }

    /// Whether a *point in time* from this clock is fit to bill against.
    ///
    /// Only `S`. An informative clock may be minutes out, and `R` states
    /// precisely that the start instant was *not* trustworthy even though the
    /// elapsed duration is.
    #[must_use]
    pub const fn instant_is_billable(self) -> bool {
        matches!(self, Self::Synchronized)
    }

    /// Whether a *duration* between two readings from this clock is fit to
    /// bill against.
    ///
    /// `S` and `R`: the whole point of `R` is that the duration was recorded
    /// to calibration-law requirements even though the wall-clock start was
    /// only informative.
    #[must_use]
    pub const fn duration_is_billable(self) -> bool {
        matches!(self, Self::Synchronized | Self::Relative)
    }

    /// How much this clock is worth as evidence, ascending.
    ///
    /// `U < I < R < S`. There is no such ordering in `[OCMF Tab. 19]`; it is
    /// this crate's reading of what each letter *permits*, and it exists so a
    /// sequence of records can be judged by its **weakest** clock rather than
    /// its best one — see [`crate::session`].
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Informative => 1,
            Self::Relative => 2,
            Self::Synchronized => 3,
        }
    }

    /// The weaker of two clock states.
    #[must_use]
    pub const fn min(self, other: Self) -> Self {
        if other.rank() < self.rank() {
            other
        } else {
            self
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TimeStatus {
    /// The letter, as `[OCMF Tab. 19]` writes it.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&alloc::string::String::from(self.letter()))
    }
}

/// A parsed `TM`: civil fields, UTC offset, and clock state.
///
/// The civil fields are kept as written rather than normalised to UTC, because
/// the local time a station stamped is itself evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcmfTime {
    /// Year, four digits.
    pub year: i32,
    /// Month, 1–12.
    pub month: u8,
    /// Day, 1–31.
    pub day: u8,
    /// Hour, 0–23.
    pub hour: u8,
    /// Minute, 0–59.
    pub minute: u8,
    /// Second, 0–60 (a leap second is accepted rather than rejected).
    pub second: u8,
    /// Millisecond, 0–999.
    pub millisecond: u16,
    /// UTC offset in minutes, e.g. `+0200` is `120`.
    pub offset_minutes: i16,
    /// The synchronisation state, when the field carried one.
    pub status: Option<TimeStatus>,
}

impl OcmfTime {
    /// Milliseconds since the Unix epoch.
    ///
    /// Computed from the civil fields with the offset applied; no calendar
    /// library and no clock are involved.
    #[must_use]
    pub const fn unix_millis(&self) -> i64 {
        let days = days_from_civil(self.year, self.month as i32, self.day as i32);
        let secs =
            days * 86_400 + self.hour as i64 * 3600 + self.minute as i64 * 60 + self.second as i64
                - self.offset_minutes as i64 * 60;
        secs * 1000 + self.millisecond as i64
    }

    /// Seconds since the Unix epoch, rounded towards negative infinity.
    #[must_use]
    pub const fn unix_seconds(&self) -> i64 {
        self.unix_millis().div_euclid(1000)
    }

    /// Parses a `TM` value, recording any deviation in spelling.
    ///
    /// `None` when the value is not a timestamp at all — which is a fact about
    /// one reading's clock, not a reason to refuse the record it sits in. The
    /// caller reports [`DeviationKind::TimeMalformed`] and carries on.
    #[must_use]
    pub fn parse(s: &str, at: &Location, dev: &mut Vec<Deviation>) -> Option<Self> {
        parse_tm(s, at, dev)
    }

    /// Whether the civil fields describe a real date and time.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.month >= 1
            && self.month <= 12
            && self.day >= 1
            && self.day <= days_in_month(self.year, self.month)
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 60
            && self.millisecond <= 999
            // A UTC offset is `±hh:mm` with `hh <= 23` and `mm <= 59`, so it
            // lies strictly inside ±24 hours. (`+0099` never gets this far:
            // the parser refuses a minutes field above 59 before composing
            // the total, so this is the invariant rather than the check.)
            && self.offset_minutes > -1440
            && self.offset_minutes < 1440
    }
}

impl core::fmt::Display for OcmfTime {
    /// Writes the canonical `[OCMF Tab. 7]` spelling.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (sign, off) = if self.offset_minutes < 0 {
            ('-', -i32::from(self.offset_minutes))
        } else {
            ('+', i32::from(self.offset_minutes))
        };
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02},{:03}{sign}{:02}{:02}",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.millisecond,
            off / 60,
            off % 60,
        )?;
        if let Some(st) = self.status {
            write!(f, " {}", st.letter())?;
        }
        Ok(())
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "a date format is a sequence of fixed-width fields"
)]
fn parse_tm(s: &str, at: &Location, dev: &mut Vec<Deviation>) -> Option<OcmfTime> {
    let (stamp, status) = match s.rsplit_once(' ') {
        Some((head, tail)) if tail.len() == 1 => {
            let st = TimeStatus::from_letter(tail.as_bytes()[0])?;
            (head.trim_end(), Some(st))
        }
        _ => {
            dev.push(Deviation::new(DeviationKind::TimeStatusMissing, at.clone()));
            (s.trim_end(), None)
        }
    };

    let b = stamp.as_bytes();
    // `YYYY-MM-DDThh:mm:ss` is 19 bytes and everything before the fraction and
    // the offset is fixed width.
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't') {
        return None;
    }
    let year = num4(&b[0..4])?;
    let month = num2(&b[5..7])?;
    let day = num2(&b[8..10])?;
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let hour = num2(&b[11..13])?;
    let minute = num2(&b[14..16])?;
    let second = num2(&b[17..19])?;

    let mut i = 19;
    let mut millisecond = 0u16;
    if i < b.len() && (b[i] == b',' || b[i] == b'.') {
        if b[i] == b'.' {
            dev.push(Deviation::new(
                DeviationKind::TimeDotMilliseconds,
                at.clone(),
            ));
        }
        i += 1;
        let frac_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = &stamp[frac_start..i];
        if digits.is_empty() {
            return None;
        }
        // `[OCMF Tab. 7]` writes `<Milliseconds>`: three digits. Fewer is
        // under-specified, and more is sub-millisecond precision the format
        // does not define — which is **truncated** below, so a reader that said
        // nothing would be dropping digits a station wrote.
        if digits.len() != 3 {
            dev.push(Deviation::with_value(
                DeviationKind::TimeSubSecondDigits,
                at.clone(),
                digits,
            ));
        }
        let mut ms = 0u16;
        for ch in digits.bytes().take(3) {
            ms = ms * 10 + u16::from(ch - b'0');
        }
        for _ in digits.len()..3 {
            ms *= 10;
        }
        millisecond = ms;
    }

    // Offset: `Z`, `±hhmm` or (deviation) `±hh:mm`.
    let offset_minutes = if i >= b.len() {
        return None;
    } else if b[i] == b'Z' || b[i] == b'z' {
        i += 1;
        0
    } else {
        let sign: i16 = match b[i] {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        i += 1;
        if i + 2 > b.len() {
            return None;
        }
        let oh = i16::from(num2(&b[i..i + 2])?);
        i += 2;
        if i < b.len() && b[i] == b':' {
            dev.push(Deviation::new(
                DeviationKind::TimeOffsetWithColon,
                at.clone(),
            ));
            i += 1;
        }
        if i + 2 > b.len() {
            return None;
        }
        let om = i16::from(num2(&b[i..i + 2])?);
        i += 2;
        if oh > 23 || om > 59 {
            return None;
        }
        sign * (oh * 60 + om)
    };
    if i != b.len() {
        return None;
    }

    let t = OcmfTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        millisecond,
        offset_minutes,
        status,
    };
    if !t.is_valid() {
        return None;
    }
    Some(t)
}

fn num2(b: &[u8]) -> Option<u8> {
    if b.len() != 2 || !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return None;
    }
    Some((b[0] - b'0') * 10 + (b[1] - b'0'))
}

fn num4(b: &[u8]) -> Option<i32> {
    if b.len() != 4 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(b.iter().fold(0i32, |a, c| a * 10 + i32::from(c - b'0')))
}

/// Days since 1970-01-01 from a civil date (Howard Hinnant's algorithm).
const fn days_from_civil(y: i32, m: i32, d: i32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146_097 + doe - 719_468
}

const fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

const fn days_in_month(y: i32, m: u8) -> u8 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn parse(s: &str) -> (OcmfTime, Vec<Deviation>) {
        let mut dev = vec![];
        let t = OcmfTime::parse(s, &Location::at(0), &mut dev).expect("parses");
        (t, dev)
    }

    #[test]
    fn the_specification_example_round_trips() {
        let (t, dev) = parse("2018-07-24T13:22:04,000+0200 S");
        assert!(dev.is_empty());
        assert_eq!(t.status, Some(TimeStatus::Synchronized));
        assert_eq!(t.to_string(), "2018-07-24T13:22:04,000+0200 S");
    }

    #[test]
    fn the_instant_is_computed_without_a_calendar_crate() {
        let (t, _) = parse("1970-01-01T01:00:00,000+0100 S");
        assert_eq!(t.unix_millis(), 0);
        let (t, _) = parse("2018-07-24T13:22:04,500+0200 S");
        assert_eq!(t.unix_millis(), 1_532_431_324_500);
    }

    #[test]
    fn the_widest_real_offsets_are_still_accepted() {
        // UTC−12:00 through UTC+14:00 are all in use.
        for s in [
            "2018-07-24T13:22:04,000+1400 S",
            "2018-07-24T13:22:04,000-1200 S",
            "2018-07-24T13:22:04,000+0545 S",
            "2018-07-24T13:22:04,000Z S",
        ] {
            let (t, _) = parse(s);
            assert!(t.is_valid(), "{s}");
        }
    }

    #[test]
    fn a_negative_offset_and_a_leap_day() {
        let (t, _) = parse("2020-02-29T23:59:59,999-0530 U");
        assert!(t.is_valid());
        assert_eq!(t.to_string(), "2020-02-29T23:59:59,999-0530 U");
    }

    #[test]
    fn deviant_spellings_parse_and_are_reported() {
        let (_, dev) = parse("2021-08-25T10:01:04.000+02:00 I");
        let kinds: Vec<_> = dev.iter().map(|d| d.kind).collect();
        assert!(kinds.contains(&DeviationKind::TimeDotMilliseconds));
        assert!(kinds.contains(&DeviationKind::TimeOffsetWithColon));
    }

    #[test]
    fn a_missing_status_letter_is_a_deviation_not_an_error() {
        let (t, dev) = parse("2021-08-25T10:01:04,000+0200");
        assert_eq!(t.status, None);
        assert_eq!(dev[0].kind, DeviationKind::TimeStatusMissing);
    }

    #[test]
    fn billability_follows_the_letter() {
        assert!(TimeStatus::Synchronized.instant_is_billable());
        assert!(!TimeStatus::Relative.instant_is_billable());
        assert!(TimeStatus::Relative.duration_is_billable());
        assert!(!TimeStatus::Informative.duration_is_billable());
        assert!(!TimeStatus::Unknown.duration_is_billable());
    }

    #[test]
    fn the_weaker_clock_wins_when_two_are_compared() {
        use TimeStatus::{Informative, Relative, Synchronized, Unknown};
        assert_eq!(Synchronized.min(Unknown), Unknown);
        assert_eq!(Unknown.min(Synchronized), Unknown);
        assert_eq!(Relative.min(Informative), Informative);
        assert_eq!(Synchronized.min(Relative), Relative);
        assert_eq!(Synchronized.min(Synchronized), Synchronized);
        // And the ordering is exactly the one the two predicates imply.
        for s in [Unknown, Informative, Relative, Synchronized] {
            assert_eq!(s.duration_is_billable(), s.rank() >= Relative.rank());
            assert_eq!(s.instant_is_billable(), s.rank() >= Synchronized.rank());
        }
    }

    #[test]
    fn nonsense_is_refused() {
        let mut dev = vec![];
        for s in [
            "not a time",
            "2018-13-24T13:22:04,000+0200 S",
            "2018-07-32T13:22:04,000+0200 S",
            "2018-07-24T25:22:04,000+0200 S",
            "2018-07-24T13:22:04,000+0200 Q",
            "2018-07-24T13:22:04,000",
            // A UTC offset is `±hh:mm`, so neither field may run past its own
            // range — `+0099` is not a time zone, and `+2400` is not one either.
            "2018-07-24T13:22:04,000+0099 S",
            "2018-07-24T13:22:04,000+2400 S",
            "2018-07-24T13:22:04,000-9999 S",
        ] {
            assert!(
                OcmfTime::parse(s, &Location::at(0), &mut dev).is_none(),
                "{s} should not parse"
            );
        }
    }
}
