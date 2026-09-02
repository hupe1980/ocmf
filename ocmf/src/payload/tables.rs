//! The closed value sets of the specification, one type per table.
//!
//! Every one of these carries an escape variant for a value the tables do not
//! define. That is not laxity: a station that writes an unknown meter state has
//! written *something*, and the only safe reading of "something" is "not
//! `OK`". Throwing the record away instead would lose the evidence; mapping the
//! unknown value onto a known one would invent it. So the unknown value is kept
//! verbatim, and every predicate that could authorise money answers `false` for
//! it.

use alloc::borrow::Cow;
use core::fmt;

use crate::json::RawStr;

/// Matches a table value against the string's **decoded** form, keeping the
/// borrowed source text for the escape variant.
///
/// `"\u006bWh"` is a lawful spelling of `"kWh"` and must match the table; a
/// value the table does not define must survive verbatim. Two different
/// strings, and this is the one place both are in hand.
fn decoded_or_raw<'a, T>(
    decoded: &str,
    raw: &'a str,
    table: impl Fn(&str) -> Option<T>,
    other: fn(&'a str) -> T,
) -> T {
    table(decoded).unwrap_or_else(|| other(raw))
}

/// State of the meter at the moment of a reading `[OCMF Tab. 10]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MeterState {
    /// `N` — meter not present or not found.
    NotPresent,
    /// `G` — working correctly (Good). The only state that is not a fault.
    Ok,
    /// `T` — timeout controlling the meter.
    Timeout,
    /// `D` — meter was disconnected from the signature component.
    Disconnected,
    /// `R` — meter no longer found, having been found before (Removed).
    NotFound,
    /// `M` — manipulation detected.
    Manipulated,
    /// `X` — meter exchanged; the serial no longer matches.
    Exchanged,
    /// `I` — meter or its API incompatible with the signature component.
    Incompatible,
    /// `O` — read value outside the value range.
    OutOfRange,
    /// `S` — a substitute value was formed.
    Substitute,
    /// `E` — other, unknown error.
    OtherError,
    /// `F` — register not read correctly; the value is not valid.
    ReadError,
    /// A letter `[OCMF Tab. 10]` does not define. Never [`Self::is_ok`].
    Undefined(char),
}

impl MeterState {
    /// Parses the single-letter code.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        let mut chars = s.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => match c {
                'N' => Self::NotPresent,
                'G' => Self::Ok,
                'T' => Self::Timeout,
                'D' => Self::Disconnected,
                'R' => Self::NotFound,
                'M' => Self::Manipulated,
                'X' => Self::Exchanged,
                'I' => Self::Incompatible,
                'O' => Self::OutOfRange,
                'S' => Self::Substitute,
                'E' => Self::OtherError,
                'F' => Self::ReadError,
                other => Self::Undefined(other),
            },
            _ => Self::Undefined('?'),
        }
    }

    /// Whether `[OCMF Tab. 10]` defines this letter.
    #[must_use]
    pub const fn is_defined(self) -> bool {
        !matches!(self, Self::Undefined(_))
    }

    /// The letter as written in `ST`.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::NotPresent => 'N',
            Self::Ok => 'G',
            Self::Timeout => 'T',
            Self::Disconnected => 'D',
            Self::NotFound => 'R',
            Self::Manipulated => 'M',
            Self::Exchanged => 'X',
            Self::Incompatible => 'I',
            Self::OutOfRange => 'O',
            Self::Substitute => 'S',
            Self::OtherError => 'E',
            Self::ReadError => 'F',
            Self::Undefined(c) => c,
        }
    }

    /// Whether the meter was working correctly.
    ///
    /// The reference verifier refuses a transaction whose start or stop reading
    /// is in any other state, and so should anything that bills.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// A human-readable identifier, as `[OCMF Tab. 10]` names it.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::NotPresent => "NOT_PRESENT",
            Self::Ok => "OK",
            Self::Timeout => "TIMEOUT",
            Self::Disconnected => "DISCONNECTED",
            Self::NotFound => "NOT_FOUND",
            Self::Manipulated => "MANIPULATED",
            Self::Exchanged => "EXCHANGED",
            Self::Incompatible => "INCOMPATIBLE",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Substitute => "SUBSTITUTE",
            Self::OtherError => "OTHER_ERROR",
            Self::ReadError => "READ_ERROR",
            Self::Undefined(_) => "UNDEFINED",
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MeterState {
    /// The letter, as `ST` writes it — a stable one-character string rather
    /// than a variant name a refactor could rename out from under a consumer.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&alloc::string::String::from(self.letter()))
    }
}

impl fmt::Display for MeterState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.letter())
    }
}

/// Why a reading was taken, and where it sits in a transaction
/// `[OCMF Tab. 7, TX]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransactionMarker {
    /// `B` — begin of transaction.
    Begin,
    /// `C` — charging (optional intermediate).
    Charging,
    /// `X` — exception: time and/or energy are unusable from here on.
    Exception,
    /// `E` — end of transaction.
    End,
    /// `L` — ended locally.
    EndedLocally,
    /// `R` — ended remotely.
    EndedRemotely,
    /// `A` — aborted by an error.
    Aborted,
    /// `P` — ended by a power failure.
    PowerFailure,
    /// `S` — suspended: transaction active, not charging.
    Suspended,
    /// `T` — tariff change.
    TariffChange,
    /// A letter the table does not define. Neither a begin nor an end.
    Undefined(char),
}

impl TransactionMarker {
    /// Parses the single-letter code.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        let mut chars = s.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => match c {
                'B' => Self::Begin,
                'C' => Self::Charging,
                'X' => Self::Exception,
                'E' => Self::End,
                'L' => Self::EndedLocally,
                'R' => Self::EndedRemotely,
                'A' => Self::Aborted,
                'P' => Self::PowerFailure,
                'S' => Self::Suspended,
                'T' => Self::TariffChange,
                other => Self::Undefined(other),
            },
            _ => Self::Undefined('?'),
        }
    }

    /// Whether `[OCMF Tab. 7]` defines this letter.
    #[must_use]
    pub const fn is_defined(self) -> bool {
        !matches!(self, Self::Undefined(_))
    }

    /// The letter as written in `TX`.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Begin => 'B',
            Self::Charging => 'C',
            Self::Exception => 'X',
            Self::End => 'E',
            Self::EndedLocally => 'L',
            Self::EndedRemotely => 'R',
            Self::Aborted => 'A',
            Self::PowerFailure => 'P',
            Self::Suspended => 'S',
            Self::TariffChange => 'T',
            Self::Undefined(c) => c,
        }
    }

    /// Whether this marks the start of a transaction.
    #[must_use]
    pub const fn is_begin(self) -> bool {
        matches!(self, Self::Begin)
    }

    /// Whether this marks the end of a transaction, in any of its five
    /// spellings.
    #[must_use]
    pub const fn is_end(self) -> bool {
        matches!(
            self,
            Self::End
                | Self::EndedLocally
                | Self::EndedRemotely
                | Self::Aborted
                | Self::PowerFailure
        )
    }

    /// Whether the transaction ended in a way that makes the readings after it
    /// suspect: an abort, a power failure, or an exception.
    #[must_use]
    pub const fn is_fault(self) -> bool {
        matches!(self, Self::Aborted | Self::PowerFailure | Self::Exception)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TransactionMarker {
    /// The letter, as `TX` writes it.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&alloc::string::String::from(self.letter()))
    }
}

impl fmt::Display for TransactionMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.letter())
    }
}

/// Which quantities an error has made unusable for billing
/// `[OCMF Tab. 7, EF]`.
///
/// Carrying the value matters twice over. An undefined flag character is still
/// a statement that *something* is wrong, and this type refuses to lose it; and
/// the value is the **decoded** one, because `"\u0045"` is a lawful JSON
/// spelling of `"E"` and a reader that compared source bytes would report a
/// station's own energy fault as an unknown flag character.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorFlags<'a> {
    raw: Cow<'a, str>,
}

impl<'a> ErrorFlags<'a> {
    /// Reads the flag string.
    #[must_use]
    pub const fn new(raw: Cow<'a, str>) -> Self {
        Self { raw }
    }

    /// Reads a flag string that is already plain text.
    #[must_use]
    pub const fn borrowed(raw: &'a str) -> Self {
        Self {
            raw: Cow::Borrowed(raw),
        }
    }

    /// The flags as the record means them, escapes resolved.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// `E` — energy is no longer usable for billing.
    #[must_use]
    pub fn energy_unusable(&self) -> bool {
        self.raw.contains('E')
    }

    /// `t` — time is no longer usable for billing.
    #[must_use]
    pub fn time_unusable(&self) -> bool {
        self.raw.contains('t')
    }

    /// Whether any flag at all is set, including one the table does not define.
    #[must_use]
    pub fn any(&self) -> bool {
        !self.raw.is_empty()
    }

    /// Flag characters outside `[OCMF Tab. 7]`'s `E` and `t`.
    pub fn undefined(&self) -> impl Iterator<Item = char> + '_ {
        self.raw.chars().filter(|c| !matches!(c, 'E' | 't'))
    }
}

impl fmt::Display for ErrorFlags<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Unit of a reading `[OCMF Tab. 20]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unit<'a> {
    /// `kWh`.
    KWh,
    /// `Wh`.
    Wh,
    /// `mOhm` — cable resistance, not energy.
    MilliOhm,
    /// `uOhm` — cable resistance, not energy.
    MicroOhm,
    /// A unit the table does not define, kept verbatim.
    Other(&'a str),
}

impl<'a> Unit<'a> {
    /// Reads a unit.
    #[must_use]
    pub const fn parse(s: &'a str) -> Self {
        // `match` on strings is not const; a small chain is.
        if str_eq(s, "kWh") {
            Self::KWh
        } else if str_eq(s, "Wh") {
            Self::Wh
        } else if str_eq(s, "mOhm") {
            Self::MilliOhm
        } else if str_eq(s, "uOhm") {
            Self::MicroOhm
        } else {
            Self::Other(s)
        }
    }

    /// Reads a unit from a JSON string, matching the table on its decoded
    /// value.
    #[must_use]
    pub fn parse_decoded(s: &RawStr<'a>) -> Self {
        Self::from_parts(&s.decode(), s.as_raw())
    }

    /// Reads a value whose decoded form and source text are already in hand.
    ///
    /// The two differ when the source used a `\uXXXX` escape, and — for a
    /// field a real record wrote as a JSON *number* — when there was no string
    /// to decode at all.
    #[must_use]
    pub fn from_parts(decoded: &str, raw: &'a str) -> Self {
        decoded_or_raw(
            decoded,
            raw,
            |d| match d {
                "kWh" => Some(Self::KWh),
                "Wh" => Some(Self::Wh),
                "mOhm" => Some(Self::MilliOhm),
                "uOhm" => Some(Self::MicroOhm),
                _ => None,
            },
            Self::Other,
        )
    }

    /// Whether `[OCMF Tab. 20]` defines this unit.
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// The unit as written.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::KWh => "kWh",
            Self::Wh => "Wh",
            Self::MilliOhm => "mOhm",
            Self::MicroOhm => "uOhm",
            Self::Other(s) => s,
        }
    }

    /// Whether this unit measures energy — the question a bill asks.
    ///
    /// `false` for an unknown unit: a quantity whose unit is not understood is
    /// not energy, whatever else it might be.
    #[must_use]
    pub const fn is_energy(&self) -> bool {
        matches!(self, Self::KWh | Self::Wh)
    }

    /// Watt-hours per unit, for converting between `kWh` and `Wh` exactly.
    #[must_use]
    pub const fn watt_hours_scale(&self) -> Option<u32> {
        match self {
            Self::KWh => Some(1000),
            Self::Wh => Some(1),
            _ => None,
        }
    }
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

impl fmt::Display for Unit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Kind of current measured `[OCMF Tab. 21]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CurrentType<'a> {
    /// `AC`.
    Ac,
    /// `DC`.
    Dc,
    /// Something else, kept verbatim.
    Other(&'a str),
}

impl<'a> CurrentType<'a> {
    /// Reads a current type.
    #[must_use]
    pub const fn parse(s: &'a str) -> Self {
        if str_eq(s, "AC") {
            Self::Ac
        } else if str_eq(s, "DC") {
            Self::Dc
        } else {
            Self::Other(s)
        }
    }

    /// Reads a current type from a JSON string, matching the table on its
    /// decoded value.
    #[must_use]
    pub fn parse_decoded(s: &RawStr<'a>) -> Self {
        Self::from_parts(&s.decode(), s.as_raw())
    }

    /// Reads a value whose decoded form and source text are already in hand.
    ///
    /// The two differ when the source used a `\uXXXX` escape, and — for a
    /// field a real record wrote as a JSON *number* — when there was no string
    /// to decode at all.
    #[must_use]
    pub fn from_parts(decoded: &str, raw: &'a str) -> Self {
        decoded_or_raw(
            decoded,
            raw,
            |d| match d {
                "AC" => Some(Self::Ac),
                "DC" => Some(Self::Dc),
                _ => None,
            },
            Self::Other,
        )
    }

    /// Whether `[OCMF Tab. 21]` defines this value.
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// The value as written.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::Ac => "AC",
            Self::Dc => "DC",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for CurrentType<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Overall status of the user assignment `[OCMF Tab. 11]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentificationLevel<'a> {
    /// `NONE` — no user assignment; the other user fields mean nothing.
    None,
    /// `HEARSAY` — unsecured, e.g. a plain RFID UID.
    Hearsay,
    /// `TRUSTED` — trustworthy but not absolutely reliable, e.g. backend
    /// authorisation.
    Trusted,
    /// `VERIFIED` — verified by the signature component and special measures.
    Verified,
    /// `CERTIFIED` — verified by a cryptographic signature certifying the
    /// assignment.
    Certified,
    /// `SECURE` — established by a secure feature, e.g. Plug & Charge.
    Secure,
    /// `MISMATCH` — error: UIDs do not match.
    Mismatch,
    /// `INVALID` — error: certificate check negative.
    Invalid,
    /// `OUTDATED` — error: referenced trust certificate expired.
    Outdated,
    /// `UNKNOWN` — no matching trust certificate found.
    Unknown,
    /// A value the table does not define.
    Other(&'a str),
}

impl<'a> IdentificationLevel<'a> {
    /// Reads a level.
    #[must_use]
    pub fn parse(s: &'a str) -> Self {
        match s {
            "NONE" => Self::None,
            "HEARSAY" => Self::Hearsay,
            "TRUSTED" => Self::Trusted,
            "VERIFIED" => Self::Verified,
            "CERTIFIED" => Self::Certified,
            "SECURE" => Self::Secure,
            "MISMATCH" => Self::Mismatch,
            "INVALID" => Self::Invalid,
            "OUTDATED" => Self::Outdated,
            "UNKNOWN" => Self::Unknown,
            other => Self::Other(other),
        }
    }

    /// Reads a level from a JSON string, matching the table on its decoded
    /// value.
    #[must_use]
    pub fn parse_decoded(s: &RawStr<'a>) -> Self {
        Self::from_parts(&s.decode(), s.as_raw())
    }

    /// Reads a value whose decoded form and source text are already in hand.
    ///
    /// The two differ when the source used a `\uXXXX` escape, and — for a
    /// field a real record wrote as a JSON *number* — when there was no string
    /// to decode at all.
    #[must_use]
    pub fn from_parts(decoded: &str, raw: &'a str) -> Self {
        decoded_or_raw(
            decoded,
            raw,
            |d| {
                Some(match d {
                    "NONE" => Self::None,
                    "HEARSAY" => Self::Hearsay,
                    "TRUSTED" => Self::Trusted,
                    "VERIFIED" => Self::Verified,
                    "CERTIFIED" => Self::Certified,
                    "SECURE" => Self::Secure,
                    "MISMATCH" => Self::Mismatch,
                    "INVALID" => Self::Invalid,
                    "OUTDATED" => Self::Outdated,
                    "UNKNOWN" => Self::Unknown,
                    _ => return None,
                })
            },
            Self::Other,
        )
    }

    /// Whether `[OCMF Tab. 11]` defines this level.
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// The value as written.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::None => "NONE",
            Self::Hearsay => "HEARSAY",
            Self::Trusted => "TRUSTED",
            Self::Verified => "VERIFIED",
            Self::Certified => "CERTIFIED",
            Self::Secure => "SECURE",
            Self::Mismatch => "MISMATCH",
            Self::Invalid => "INVALID",
            Self::Outdated => "OUTDATED",
            Self::Unknown => "UNKNOWN",
            Self::Other(s) => s,
        }
    }

    /// Whether this level reports an *error* in the assignment.
    ///
    /// The reference verifier refuses a transaction whose level is one of
    /// `MISMATCH`, `INVALID`, `OUTDATED` or `UNKNOWN`, and so does
    /// [`crate::session`].
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(
            self,
            Self::Mismatch | Self::Invalid | Self::Outdated | Self::Unknown
        )
    }
}

impl fmt::Display for IdentificationLevel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Type of the identification data in `ID` `[OCMF Tab. 17]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentificationType<'a> {
    /// `NONE` — no assignment available.
    None,
    /// `DENIED` — assignment withheld (two-factor authorisation).
    Denied,
    /// `UNDEFINED` — type not specified.
    Undefined,
    /// `ISO14443` — RFID UID, 4 or 7 bytes hex.
    Iso14443,
    /// `ISO15693` — RFID UID, 8 bytes hex.
    Iso15693,
    /// `EMAID` — e-mobility account ID (ISO 15118), 14 or 15 characters.
    Emaid,
    /// `EVCCID` — vehicle ID (ISO 15118).
    Evccid,
    /// `EVCOID` — EV contract ID (DIN 91286).
    Evcoid,
    /// `ISO7812` — payment card number.
    Iso7812,
    /// `CARD_TXN_NR` — terminal card transaction number.
    CardTxnNr,
    /// `CENTRAL` — centrally generated ID (OCPP 2.0).
    Central,
    /// `CENTRAL_1` — centrally generated, e.g. start by SMS (to OCPP 1.6).
    Central1,
    /// `CENTRAL_2` — centrally generated, e.g. operator start (to OCPP 1.6).
    Central2,
    /// `LOCAL` — locally generated ID (OCPP 2.0).
    Local,
    /// `LOCAL_1` — locally generated by the charge point (to OCPP 1.6).
    Local1,
    /// `LOCAL_2` — locally generated, other cases (to OCPP 1.6).
    Local2,
    /// `PHONE_NUMBER` — international number with a leading `+`.
    PhoneNumber,
    /// `KEY_CODE` — user-related private key code.
    KeyCode,
    /// A value the table does not define.
    Other(&'a str),
}

impl<'a> IdentificationType<'a> {
    /// Reads a type.
    #[must_use]
    pub fn parse(s: &'a str) -> Self {
        match s {
            "NONE" => Self::None,
            "DENIED" => Self::Denied,
            "UNDEFINED" => Self::Undefined,
            "ISO14443" => Self::Iso14443,
            "ISO15693" => Self::Iso15693,
            "EMAID" => Self::Emaid,
            "EVCCID" => Self::Evccid,
            "EVCOID" => Self::Evcoid,
            "ISO7812" => Self::Iso7812,
            "CARD_TXN_NR" => Self::CardTxnNr,
            "CENTRAL" => Self::Central,
            "CENTRAL_1" => Self::Central1,
            "CENTRAL_2" => Self::Central2,
            "LOCAL" => Self::Local,
            "LOCAL_1" => Self::Local1,
            "LOCAL_2" => Self::Local2,
            "PHONE_NUMBER" => Self::PhoneNumber,
            "KEY_CODE" => Self::KeyCode,
            other => Self::Other(other),
        }
    }

    /// Reads a type from a JSON string, matching the table on its decoded
    /// value.
    #[must_use]
    pub fn parse_decoded(s: &RawStr<'a>) -> Self {
        Self::from_parts(&s.decode(), s.as_raw())
    }

    /// Reads a value whose decoded form and source text are already in hand.
    ///
    /// The two differ when the source used a `\uXXXX` escape, and — for a
    /// field a real record wrote as a JSON *number* — when there was no string
    /// to decode at all.
    #[must_use]
    pub fn from_parts(decoded: &str, raw: &'a str) -> Self {
        decoded_or_raw(
            decoded,
            raw,
            |d| {
                Some(match d {
                    "NONE" => Self::None,
                    "DENIED" => Self::Denied,
                    "UNDEFINED" => Self::Undefined,
                    "ISO14443" => Self::Iso14443,
                    "ISO15693" => Self::Iso15693,
                    "EMAID" => Self::Emaid,
                    "EVCCID" => Self::Evccid,
                    "EVCOID" => Self::Evcoid,
                    "ISO7812" => Self::Iso7812,
                    "CARD_TXN_NR" => Self::CardTxnNr,
                    "CENTRAL" => Self::Central,
                    "CENTRAL_1" => Self::Central1,
                    "CENTRAL_2" => Self::Central2,
                    "LOCAL" => Self::Local,
                    "LOCAL_1" => Self::Local1,
                    "LOCAL_2" => Self::Local2,
                    "PHONE_NUMBER" => Self::PhoneNumber,
                    "KEY_CODE" => Self::KeyCode,
                    _ => return None,
                })
            },
            Self::Other,
        )
    }

    /// Whether `[OCMF Tab. 17]` defines this type.
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// Whether `data` has the shape this type prescribes for `ID`
    /// `[OCMF Tab. 17]`.
    ///
    /// `None` for the thirteen types the table describes as having "no exact
    /// format defined" — there is nothing to check, and inventing a rule would
    /// report a deviation from something nobody wrote. Five of the eighteen
    /// rows state a format, and those five are checked.
    #[must_use]
    pub fn data_is_well_formed(&self, data: &str) -> Option<bool> {
        let hex =
            |n: [usize; 2]| n.contains(&data.len()) && data.bytes().all(|c| c.is_ascii_hexdigit());
        Some(match self {
            // "Represented as 4 or 7 bytes in hexadecimal notation."
            Self::Iso14443 => hex([8, 14]),
            // "Represented as 8 bytes in hexadecimal notation."
            Self::Iso15693 => hex([16, 16]),
            // "string with length 14 or 15"
            Self::Emaid => matches!(data.chars().count(), 14 | 15),
            // "maximum length 6 characters"
            Self::Evccid => data.chars().count() <= 6,
            // "International phone number with leading \"+\"."
            Self::PhoneNumber => data.starts_with('+'),
            _ => return None,
        })
    }

    /// The value as written.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::None => "NONE",
            Self::Denied => "DENIED",
            Self::Undefined => "UNDEFINED",
            Self::Iso14443 => "ISO14443",
            Self::Iso15693 => "ISO15693",
            Self::Emaid => "EMAID",
            Self::Evccid => "EVCCID",
            Self::Evcoid => "EVCOID",
            Self::Iso7812 => "ISO7812",
            Self::CardTxnNr => "CARD_TXN_NR",
            Self::Central => "CENTRAL",
            Self::Central1 => "CENTRAL_1",
            Self::Central2 => "CENTRAL_2",
            Self::Local => "LOCAL",
            Self::Local1 => "LOCAL_1",
            Self::Local2 => "LOCAL_2",
            Self::PhoneNumber => "PHONE_NUMBER",
            Self::KeyCode => "KEY_CODE",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for IdentificationType<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One detail flag of the user assignment `[OCMF Tab. 13–16]`.
///
/// The four tables are four independent groups — RFID, OCPP, ISO 15118 and
/// PLMN — and `IF` carries at most one flag from each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentificationFlag<'a> {
    /// A flag from `[OCMF Tab. 13]` (`RFID_*`).
    Rfid(&'a str),
    /// A flag from `[OCMF Tab. 14]` (`OCPP_*`).
    Ocpp(&'a str),
    /// A flag from `[OCMF Tab. 15]` (`ISO15118_*`).
    Iso15118(&'a str),
    /// A flag from `[OCMF Tab. 16]` (`PLMN_*`).
    Plmn(&'a str),
    /// A flag none of the four tables defines.
    Other(&'a str),
}

impl<'a> IdentificationFlag<'a> {
    /// All flags `[OCMF Tab. 13–16]` define.
    pub const DEFINED: [&'static str; 17] = [
        "RFID_NONE",
        "RFID_PLAIN",
        "RFID_RELATED",
        "RFID_PSK",
        "OCPP_NONE",
        "OCPP_RS",
        "OCPP_AUTH",
        "OCPP_RS_TLS",
        "OCPP_AUTH_TLS",
        "OCPP_CACHE",
        "OCPP_WHITELIST",
        "OCPP_CERTIFIED",
        "ISO15118_NONE",
        "ISO15118_PNC",
        "PLMN_NONE",
        "PLMN_RING",
        "PLMN_SMS",
    ];

    /// Classifies a flag by its group.
    #[must_use]
    pub fn parse(s: &'a str) -> Self {
        if !Self::DEFINED.contains(&s) {
            return Self::Other(s);
        }
        if s.starts_with("RFID_") {
            Self::Rfid(s)
        } else if s.starts_with("OCPP_") {
            Self::Ocpp(s)
        } else if s.starts_with("ISO15118_") {
            Self::Iso15118(s)
        } else {
            Self::Plmn(s)
        }
    }

    /// Classifies a flag from a JSON string, matching the tables on its
    /// decoded value.
    ///
    /// A flag the tables define keeps its **raw** text, because the four
    /// variants borrow: an escaped `RFID_PLAIN` is still an RFID flag, and the
    /// text a caller reads back is the one the record wrote.
    #[must_use]
    pub fn parse_decoded(s: &RawStr<'a>) -> Self {
        let raw = s.as_raw();
        let decoded = s.decode();
        let group = match IdentificationFlag::parse(decoded.as_ref()) {
            IdentificationFlag::Rfid(_) => 0u8,
            IdentificationFlag::Ocpp(_) => 1,
            IdentificationFlag::Iso15118(_) => 2,
            IdentificationFlag::Plmn(_) => 3,
            IdentificationFlag::Other(_) => 4,
        };
        match group {
            0 => Self::Rfid(raw),
            1 => Self::Ocpp(raw),
            2 => Self::Iso15118(raw),
            3 => Self::Plmn(raw),
            _ => Self::Other(raw),
        }
    }

    /// Which of the four tables this flag belongs to, as a small index —
    /// `None` for a flag none of them defines.
    ///
    /// `[OCMF Tab. 4]` gives `IF` a cardinality of `0..4` because there are
    /// four groups and a user assignment has one statement to make about each.
    #[must_use]
    pub const fn group(&self) -> Option<u8> {
        Some(match self {
            Self::Rfid(_) => 0,
            Self::Ocpp(_) => 1,
            Self::Iso15118(_) => 2,
            Self::Plmn(_) => 3,
            Self::Other(_) => return None,
        })
    }

    /// Whether `[OCMF Tab. 13–16]` define this flag.
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// The flag as written.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::Rfid(s) | Self::Ocpp(s) | Self::Iso15118(s) | Self::Plmn(s) | Self::Other(s) => s,
        }
    }
}

impl fmt::Display for IdentificationFlag<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a charge point is identified `[OCMF Tab. 18]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChargePointIdType<'a> {
    /// `EVSEID`.
    EvseId,
    /// `CBIDC` — charge box ID and connector ID, space separated.
    ChargeBoxAndConnector,
    /// A value the table does not define.
    Other(&'a str),
}

impl<'a> ChargePointIdType<'a> {
    /// Reads a type.
    #[must_use]
    pub fn parse(s: &'a str) -> Self {
        match s {
            "EVSEID" => Self::EvseId,
            "CBIDC" => Self::ChargeBoxAndConnector,
            other => Self::Other(other),
        }
    }

    /// Reads a type from a JSON string, matching the table on its decoded
    /// value.
    #[must_use]
    pub fn parse_decoded(s: &RawStr<'a>) -> Self {
        Self::from_parts(&s.decode(), s.as_raw())
    }

    /// Reads a value whose decoded form and source text are already in hand.
    ///
    /// The two differ when the source used a `\uXXXX` escape, and — for a
    /// field a real record wrote as a JSON *number* — when there was no string
    /// to decode at all.
    #[must_use]
    pub fn from_parts(decoded: &str, raw: &'a str) -> Self {
        decoded_or_raw(
            decoded,
            raw,
            |d| match d {
                "EVSEID" => Some(Self::EvseId),
                "CBIDC" => Some(Self::ChargeBoxAndConnector),
                _ => None,
            },
            Self::Other,
        )
    }

    /// Whether `[OCMF Tab. 18]` defines this type.
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// Whether `id` has the shape this type prescribes for `CI`
    /// `[OCMF Tab. 18]`.
    ///
    /// `None` for `EVSEID`, whose format the table leaves to the EVSE ID
    /// specification rather than stating.
    #[must_use]
    pub fn id_is_well_formed(&self, id: &str) -> Option<bool> {
        match self {
            // "Charge box ID and connector ID …, a space is used as field
            // separator, e.g. \"STEVE_01 1\"."
            Self::ChargeBoxAndConnector => {
                Some(id.split_once(' ').is_some_and(|(box_id, connector)| {
                    !box_id.is_empty() && !connector.is_empty() && !connector.contains(' ')
                }))
            }
            _ => None,
        }
    }

    /// The value as written.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::EvseId => "EVSEID",
            Self::ChargeBoxAndConnector => "CBIDC",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for ChargePointIdType<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn every_meter_state_letter_round_trips() {
        for c in "NGTDRMXIOSEF".chars() {
            let st = MeterState::parse(&c.to_string());
            assert_eq!(st.letter(), c);
            assert_eq!(st.is_ok(), c == 'G');
        }
    }

    #[test]
    fn an_undefined_meter_state_is_never_ok() {
        let st = MeterState::parse("Q");
        assert_eq!(st, MeterState::Undefined('Q'));
        assert!(!st.is_ok());
        assert_eq!(st.letter(), 'Q');
    }

    #[test]
    fn all_five_spellings_of_an_ending_are_endings() {
        for c in "ELRAP".chars() {
            assert!(TransactionMarker::parse(&c.to_string()).is_end(), "{c}");
        }
        for c in "BCXST".chars() {
            assert!(!TransactionMarker::parse(&c.to_string()).is_end(), "{c}");
        }
        assert!(TransactionMarker::parse("B").is_begin());
        assert!(!TransactionMarker::parse("Q").is_begin());
    }

    #[test]
    fn error_flags_keep_what_they_cannot_interpret() {
        let f = ErrorFlags::borrowed("Et");
        assert!(f.energy_unusable() && f.time_unusable() && f.any());
        let f = ErrorFlags::borrowed("");
        assert!(!f.any());
        let f = ErrorFlags::borrowed("Q");
        assert!(f.any(), "an undefined flag is still a fault");
        assert!(!f.energy_unusable());
        assert_eq!(f.undefined().collect::<alloc::vec::Vec<_>>(), ['Q']);
    }

    #[test]
    fn an_unknown_unit_is_not_energy() {
        assert!(Unit::parse("kWh").is_energy());
        assert!(Unit::parse("Wh").is_energy());
        assert!(!Unit::parse("mOhm").is_energy());
        assert!(!Unit::parse("MWh").is_energy());
        assert_eq!(Unit::parse("MWh"), Unit::Other("MWh"));
    }

    #[test]
    fn the_four_error_levels_are_the_ones_the_reference_refuses() {
        for s in ["MISMATCH", "INVALID", "OUTDATED", "UNKNOWN"] {
            assert!(IdentificationLevel::parse(s).is_error(), "{s}");
        }
        for s in [
            "NONE",
            "HEARSAY",
            "TRUSTED",
            "VERIFIED",
            "CERTIFIED",
            "SECURE",
        ] {
            assert!(!IdentificationLevel::parse(s).is_error(), "{s}");
        }
    }

    #[test]
    fn identification_flags_are_grouped_by_their_table() {
        assert!(matches!(
            IdentificationFlag::parse("RFID_PLAIN"),
            IdentificationFlag::Rfid(_)
        ));
        assert!(matches!(
            IdentificationFlag::parse("OCPP_RS_TLS"),
            IdentificationFlag::Ocpp(_)
        ));
        assert!(matches!(
            IdentificationFlag::parse("ISO15118_PNC"),
            IdentificationFlag::Iso15118(_)
        ));
        assert!(matches!(
            IdentificationFlag::parse("PLMN_SMS"),
            IdentificationFlag::Plmn(_)
        ));
        assert!(matches!(
            IdentificationFlag::parse("VENDOR_X"),
            IdentificationFlag::Other(_)
        ));
    }

    #[test]
    fn an_escaped_table_value_still_matches_its_table() {
        // `"\u006bWh"` is a lawful JSON spelling of `"kWh"`. Comparing raw
        // text would read it as an unknown unit — and an unknown unit is not
        // energy, so a lawful record would silently stop being billable.
        let raw = crate::json::parse_value(
            r#"{"RU":"kWh","IT":"ISO14443","IL":"VERIFIED","CT":"EVSEID","IF":"RFID_PLAIN"}"#,
            0,
            &crate::Limits::DEFAULT,
            &mut alloc::vec::Vec::new(),
        )
        .unwrap();
        let o = raw.as_object().unwrap();
        let f = |k: &str| o.get(k).unwrap().as_str().unwrap();

        assert_eq!(Unit::parse_decoded(f("RU")), Unit::KWh);
        assert!(Unit::parse_decoded(f("RU")).is_energy());
        assert_eq!(
            IdentificationType::parse_decoded(f("IT")),
            IdentificationType::Iso14443
        );
        assert_eq!(
            IdentificationLevel::parse_decoded(f("IL")),
            IdentificationLevel::Verified
        );
        assert_eq!(
            ChargePointIdType::parse_decoded(f("CT")),
            ChargePointIdType::EvseId
        );
        assert!(matches!(
            IdentificationFlag::parse_decoded(f("IF")),
            IdentificationFlag::Rfid(_)
        ));

        // …and a value the table does not define keeps the record's own text.
        let raw = crate::json::parse_value(
            r#"{"RU":"MWh"}"#,
            0,
            &crate::Limits::DEFAULT,
            &mut alloc::vec::Vec::new(),
        )
        .unwrap();
        let u = Unit::parse_decoded(
            raw.as_object()
                .unwrap()
                .get("RU")
                .unwrap()
                .as_str()
                .unwrap(),
        );
        assert_eq!(u, Unit::Other("MWh"));
    }

    #[test]
    fn all_eighteen_identification_types_round_trip() {
        let all = [
            "NONE",
            "DENIED",
            "UNDEFINED",
            "ISO14443",
            "ISO15693",
            "EMAID",
            "EVCCID",
            "EVCOID",
            "ISO7812",
            "CARD_TXN_NR",
            "CENTRAL",
            "CENTRAL_1",
            "CENTRAL_2",
            "LOCAL",
            "LOCAL_1",
            "LOCAL_2",
            "PHONE_NUMBER",
            "KEY_CODE",
        ];
        assert_eq!(all.len(), 18, "[OCMF Tab. 17] has 18 rows");
        for s in all {
            assert_eq!(IdentificationType::parse(s).as_str(), s);
            assert!(!matches!(
                IdentificationType::parse(s),
                IdentificationType::Other(_)
            ));
        }
    }
}
