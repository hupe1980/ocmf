//! `RI`: OBIS codes, as they are written rather than as they are specified.
//!
//! `[OCMF Tab. 25]` defines a range of billing-relevant codes in the form
//! `01-00:B1.08.00*FF`. **Not one OBIS code in the reference corpus is written
//! that way.** What 705 real readings actually contain:
//!
//! | Form | Readings |
//! |---|---|
//! | `1-b:1.8.0` | 462 |
//! | `1-b:1.9.0` | 200 |
//! | `1-b:1.8.e` | 14 |
//! | `01-00:01.08.00.FF` | 6 |
//! | `1-0:1.8.0`, `1-0:1.8.0*198`, `1-0:1.8.1` | 4 each |
//! | `1-b:2.8.e` | 3 |
//! | `1-0:2.8.0`, `1-0:2.8.0.FF`, `1-0:98.8.0.FF`, `01-00:00.08.06.FF` | 2 each |
//!
//! Lower-case medium letters, one- and two-digit groups, and three different
//! spellings of the tariff separator (`*`, `.`, and nothing at all). A parser
//! that insists on the table's form rejects every real record.
//!
//! # The radix the specification does not settle
//!
//! `[OCMF Tab. 25]` says the codes are hexadecimal, and `B1` can only be hex.
//! But `1-0:98.8.0.FF` is a decimal-flavoured code from IEC 62056-6-1, and
//! `*198` cannot be a hex byte at all. There is no rule in the specification
//! that tells the two apart, so this type does not invent one: groups are kept
//! as text, compared case-insensitively without leading zeros, and semantic
//! questions are answered from the set of codes OCMF and IEC actually define.
//!
//! # Example
//!
//! ```
//! use ocmf::{ObisCode, Register};
//!
//! // The form 462 of 705 corpus readings use — and not the one the table gives.
//! let code = ObisCode::parse("1-b:1.8.0").expect("an OBIS code");
//! assert!(!code.is_canonical());
//! assert_eq!(code.canonical(), "01-0B:01.08.00");
//! assert_eq!(code.register(), Register::ActiveEnergyImport);
//! assert_eq!(code.register().is_import(), Some(true));
//!
//! // Two spellings of one register share a canonical form, which is how
//! // `Payload::by_register` tells them apart.
//! assert_eq!(
//!     ObisCode::parse("1-0:1.8.0").unwrap().canonical(),
//!     ObisCode::parse("01-00:01.08.00").unwrap().canonical(),
//! );
//!
//! // The table's own form says more: mains or device, total or transaction.
//! let unified = ObisCode::parse("01-00:B3.08.00*FF").unwrap();
//! assert_eq!(unified.register(), Register::TransactionImportDevice);
//! assert_eq!(unified.register().is_device_side(), Some(true));
//! assert_eq!(unified.register().is_transaction_scoped(), Some(true));
//! ```

use alloc::borrow::Cow;
use alloc::string::String;
use core::fmt;
use core::ops::Range;

/// What a register measures, as far as the defined code sets say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Register {
    /// `C = 1` — active energy, import (+A). The classic `1.8.x`.
    ActiveEnergyImport,
    /// `C = 2` — active energy, export (−A).
    ActiveEnergyExport,
    /// `C = B0` — total import mains energy `[OCMF Tab. 25]`.
    TotalImportMains,
    /// `C = B1` — total import device energy `[OCMF Tab. 25]`.
    TotalImportDevice,
    /// `C = B2` — transaction import mains energy `[OCMF Tab. 25]`.
    TransactionImportMains,
    /// `C = B3` — transaction import device energy `[OCMF Tab. 25]`.
    TransactionImportDevice,
    /// `C = C0` — total export mains energy `[OCMF Tab. 25]`.
    TotalExportMains,
    /// `C = C1` — total export device energy `[OCMF Tab. 25]`.
    TotalExportDevice,
    /// `C = C2` — transaction export mains energy `[OCMF Tab. 25]`.
    TransactionExportMains,
    /// `C = C3` — transaction export device energy `[OCMF Tab. 25]`.
    TransactionExportDevice,
    /// Reserved for future use by `[OCMF Tab. 25]` (`B4`–`BF`, `C4`–`C7`).
    Reserved,
    /// Anything else — a manufacturer register, or a code from another part of
    /// IEC 62056-6-1.
    Other,
}

impl Register {
    /// Whether energy flows into the vehicle.
    #[must_use]
    pub const fn is_import(self) -> Option<bool> {
        Some(match self {
            Self::ActiveEnergyImport
            | Self::TotalImportMains
            | Self::TotalImportDevice
            | Self::TransactionImportMains
            | Self::TransactionImportDevice => true,
            Self::ActiveEnergyExport
            | Self::TotalExportMains
            | Self::TotalExportDevice
            | Self::TransactionExportMains
            | Self::TransactionExportDevice => false,
            Self::Reserved | Self::Other => return None,
        })
    }

    /// Whether the register is measured at the consuming device rather than at
    /// the mains — that is, after cable-loss compensation.
    ///
    /// `None` where the code set does not say, which includes the classic
    /// `1.8.0`: for those, `LC`/`CL` in the record is the only evidence.
    #[must_use]
    pub const fn is_device_side(self) -> Option<bool> {
        Some(match self {
            Self::TotalImportDevice
            | Self::TransactionImportDevice
            | Self::TotalExportDevice
            | Self::TransactionExportDevice => true,
            Self::TotalImportMains
            | Self::TransactionImportMains
            | Self::TotalExportMains
            | Self::TransactionExportMains => false,
            Self::ActiveEnergyImport | Self::ActiveEnergyExport | Self::Reserved | Self::Other => {
                return None;
            }
        })
    }

    /// Whether the register counts only this transaction rather than the
    /// meter's lifetime total.
    #[must_use]
    pub const fn is_transaction_scoped(self) -> Option<bool> {
        Some(match self {
            Self::TransactionImportMains
            | Self::TransactionImportDevice
            | Self::TransactionExportMains
            | Self::TransactionExportDevice => true,
            Self::TotalImportMains
            | Self::TotalImportDevice
            | Self::TotalExportMains
            | Self::TotalExportDevice => false,
            Self::ActiveEnergyImport | Self::ActiveEnergyExport | Self::Reserved | Self::Other => {
                return None;
            }
        })
    }
}

/// An OBIS code from `RI`, keeping its original spelling.
///
/// Borrows the record's own bytes in the ordinary case. It holds a
/// [`Cow`] rather than a `&str` for one reason: `RI` is a
/// JSON string like any other, so `"1-b:1.8.\u0030"` is a lawful spelling of
/// `"1-b:1.8.0"` — and a decoded escape is longer than what it denotes, so it
/// can never be a subslice of the source. Refusing such a record would throw
/// away an intact signed payload over a spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObisCode<'a> {
    raw: Cow<'a, str>,
    /// Byte ranges into `raw`, in `A-B:C.D.E[*F]` order.
    groups: [Range<usize>; 5],
    period: Option<Range<usize>>,
}

impl<'a> ObisCode<'a> {
    /// The code exactly as the station wrote it — decoded, when the source
    /// spelled a character as an escape.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The `A` group (medium).
    #[must_use]
    pub fn medium(&self) -> &str {
        &self.raw[self.groups[0].clone()]
    }
    /// The `B` group (channel).
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.raw[self.groups[1].clone()]
    }
    /// The `C` group (physical quantity).
    #[must_use]
    pub fn quantity(&self) -> &str {
        &self.raw[self.groups[2].clone()]
    }
    /// The `D` group (processing).
    #[must_use]
    pub fn processing(&self) -> &str {
        &self.raw[self.groups[3].clone()]
    }
    /// The `E` group (tariff).
    #[must_use]
    pub fn tariff(&self) -> &str {
        &self.raw[self.groups[4].clone()]
    }
    /// The `F` group (billing period), when written.
    #[must_use]
    pub fn billing_period(&self) -> Option<&str> {
        self.period.clone().map(|r| &self.raw[r])
    }

    /// What this register measures.
    #[must_use]
    pub fn register(&self) -> Register {
        let c = trimmed_upper(self.quantity());
        match &*c {
            "1" => Register::ActiveEnergyImport,
            "2" => Register::ActiveEnergyExport,
            "B0" => Register::TotalImportMains,
            "B1" => Register::TotalImportDevice,
            "B2" => Register::TransactionImportMains,
            "B3" => Register::TransactionImportDevice,
            "C0" => Register::TotalExportMains,
            "C1" => Register::TotalExportDevice,
            "C2" => Register::TransactionExportMains,
            "C3" => Register::TransactionExportDevice,
            "B4" | "B5" | "B6" | "B7" | "B8" | "B9" | "BA" | "BB" | "BC" | "BD" | "BE" | "BF"
            | "C4" | "C5" | "C6" | "C7" => Register::Reserved,
            _ => Register::Other,
        }
    }

    /// Whether `D` marks this as a time-integral register (`8`) — the reading
    /// a bill is computed from, as opposed to an instantaneous value.
    #[must_use]
    pub fn is_register(&self) -> bool {
        trimmed_upper(self.processing()) == "8"
    }

    /// The canonical `[OCMF Tab. 25]` spelling: two-digit upper-case groups,
    /// `*` before the billing period.
    ///
    /// Two codes are the same register exactly when their canonical forms are
    /// equal, which is the comparison `by_register` uses.
    #[must_use]
    pub fn canonical(&self) -> String {
        let mut s = String::with_capacity(20);
        push_group(&mut s, self.medium());
        s.push('-');
        push_group(&mut s, self.channel());
        s.push(':');
        push_group(&mut s, self.quantity());
        s.push('.');
        push_group(&mut s, self.processing());
        s.push('.');
        push_group(&mut s, self.tariff());
        if let Some(period) = self.billing_period() {
            s.push('*');
            push_group(&mut s, period);
        }
        s
    }

    /// Whether the code is already written in the `[OCMF Tab. 25]` form:
    /// `AA-BB:CC.DD.EE` with two upper-case digits per group, and `*` before
    /// the billing period when there is one.
    ///
    /// Answered without building the canonical string, because this runs once
    /// per reading and the answer is "no" for every OBIS code in the reference
    /// corpus.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        fn group(g: &str) -> bool {
            // Two characters, upper case. Canonical form pads a single digit
            // with a leading zero, so `01` and `00` are both canonical and
            // there is nothing further to reject.
            g.len() == 2
                && g.bytes()
                    .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
        }
        [
            self.medium(),
            self.channel(),
            self.quantity(),
            self.processing(),
            self.tariff(),
        ]
        .iter()
        .all(|g| group(g))
            && match self.billing_period() {
                None => true,
                Some(period) => group(period) && self.raw.contains('*'),
            }
    }

    /// Parses a plain string. `None` when the text has no OBIS shape at all.
    #[must_use]
    pub fn parse(raw: &'a str) -> Option<Self> {
        Self::parse_cow(Cow::Borrowed(raw))
    }

    /// Parses text that may have had to be decoded from a JSON escape.
    ///
    /// `RI` is a JSON string like any other, so `"1-b:1.8.\u0030"` is a lawful
    /// spelling of `"1-b:1.8.0"` — and a decoded escape is *longer* than what
    /// it denotes, so the result can never be a subslice of the record. That is
    /// why this type holds a [`Cow`]: borrowed in every real case, owned when
    /// it has to be. Refusing such a record instead would throw away an intact
    /// signed payload over a spelling.
    #[must_use]
    pub fn parse_cow(raw: Cow<'a, str>) -> Option<Self> {
        let (groups, period) = locate(&raw)?;
        Some(Self {
            raw,
            groups,
            period,
        })
    }
}

/// The five mandatory groups of an OBIS code and, when written, its billing
/// period — as byte ranges into the text they were read from.
type Groups = ([Range<usize>; 5], Option<Range<usize>>);

/// Locates the six groups of `A-B:C.D.E[*F]`, and rejects anything that is not
/// one.
///
/// Ranges rather than slices, because the text they index may be an owned
/// decode of the source rather than the source itself.
fn locate(s: &str) -> Option<Groups> {
    let dash = s.find('-')?;
    let colon = s[dash + 1..].find(':')? + dash + 1;
    let rest_at = colon + 1;
    let rest = &s[rest_at..];

    // The billing period may be introduced by `*`, or by a fourth `.`, or be
    // absent — all three occur in the corpus.
    let (body_end, period) = if let Some(star) = rest.find('*') {
        (rest_at + star, Some(rest_at + star + 1..s.len()))
    } else if rest.match_indices('.').count() == 3 {
        let dot = rest.rfind('.')?;
        (rest_at + dot, Some(rest_at + dot + 1..s.len()))
    } else {
        (s.len(), None)
    };

    let body = &s[rest_at..body_end];
    let first = body.find('.')?;
    let second = body[first + 1..].find('.')? + first + 1;
    if body[second + 1..].contains('.') {
        return None;
    }

    let groups = [
        0..dash,
        dash + 1..colon,
        rest_at..rest_at + first,
        rest_at + first + 1..rest_at + second,
        rest_at + second + 1..body_end,
    ];
    if groups.iter().any(|g| !is_group(&s[g.clone()])) {
        return None;
    }
    if period.clone().is_some_and(|p| !is_group(&s[p])) {
        return None;
    }
    Some((groups, period))
}

impl fmt::Display for ObisCode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

fn is_group(g: &str) -> bool {
    !g.is_empty() && g.len() <= 4 && g.bytes().all(|c| c.is_ascii_alphanumeric())
}

/// The group with leading zeros stripped, upper-cased — borrowed when it
/// already is, which is the common case.
fn trimmed_upper(g: &str) -> alloc::borrow::Cow<'_, str> {
    let t = g.trim_start_matches('0');
    let t = if t.is_empty() { "0" } else { t };
    if t.bytes().any(|c| c.is_ascii_lowercase()) {
        alloc::borrow::Cow::Owned(t.to_ascii_uppercase())
    } else {
        alloc::borrow::Cow::Borrowed(t)
    }
}

/// Writes a group in canonical form straight into the buffer.
fn push_group(s: &mut String, g: &str) {
    let t = g.trim_start_matches('0');
    let t = if t.is_empty() { "0" } else { t };
    if t.len() == 1 {
        s.push('0');
    }
    for c in t.bytes() {
        s.push(c.to_ascii_uppercase() as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(s: &str) -> ObisCode<'_> {
        ObisCode::parse(s).expect("parses")
    }

    #[test]
    fn the_form_every_real_record_uses() {
        let c = code("1-b:1.8.0");
        assert_eq!(c.medium(), "1");
        assert_eq!(c.channel(), "b");
        assert_eq!(c.register(), Register::ActiveEnergyImport);
        assert!(c.is_register());
        assert_eq!(c.canonical(), "01-0B:01.08.00");
        assert!(
            !c.is_canonical(),
            "no real record is written the table's way"
        );
    }

    #[test]
    fn the_form_the_table_specifies() {
        let c = code("01-00:B1.08.00*FF");
        assert_eq!(c.register(), Register::TotalImportDevice);
        assert_eq!(c.register().is_device_side(), Some(true));
        assert_eq!(c.register().is_import(), Some(true));
        assert_eq!(c.register().is_transaction_scoped(), Some(false));
        assert_eq!(c.canonical(), "01-00:B1.08.00*FF");
        assert!(c.is_canonical());
    }

    #[test]
    fn all_three_billing_period_spellings() {
        assert_eq!(code("1-0:2.8.0*198").billing_period(), Some("198"));
        assert_eq!(code("1-0:2.8.0.FF").billing_period(), Some("FF"));
        assert_eq!(code("1-0:2.8.0").billing_period(), None);
    }

    #[test]
    fn codes_that_differ_only_in_spelling_share_a_canonical_form() {
        assert_eq!(
            code("1-0:1.8.0").canonical(),
            code("01-00:01.08.00").canonical()
        );
        assert_eq!(
            code("1-b:1.8.E").canonical(),
            code("01-0B:01.08.0e").canonical()
        );
    }

    #[test]
    fn transaction_and_total_are_distinguished() {
        assert_eq!(
            code("01-00:B3.08.00*FF").register(),
            Register::TransactionImportDevice
        );
        assert_eq!(
            code("01-00:C2.08.00*FF").register(),
            Register::TransactionExportMains
        );
        assert_eq!(code("01-00:B7.08.00*FF").register(), Register::Reserved);
    }

    #[test]
    fn an_escaped_obis_code_is_read_rather_than_refused() {
        // `\u0030` is `0`. A decoded escape is longer than what it denotes, so
        // the code cannot be a subslice of the record — which is why this type
        // holds a `Cow`. Refusing the record instead would throw away an intact
        // signed payload over a spelling.
        let c = ObisCode::parse_cow(Cow::Owned(alloc::string::String::from("1-b:1.8.0")))
            .expect("parses");
        assert_eq!(c.as_str(), "1-b:1.8.0");
        assert_eq!(c.tariff(), "0");
        assert_eq!(c.canonical(), "01-0B:01.08.00");
        assert_eq!(c.register(), Register::ActiveEnergyImport);
        assert_eq!(c, code("1-b:1.8.0"), "the same register, either spelling");
    }

    #[test]
    fn nonsense_is_refused() {
        for s in ["", "1.8.0", "1-b:1.8", "1-b:1.8.0.0.0", "1-b:1.8.z z"] {
            assert!(ObisCode::parse(s).is_none(), "{s} should not parse");
        }
    }
}
