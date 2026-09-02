//! Departures from the specification, reported rather than swallowed.
//!
//! Two failure modes are equally bad. A strict parser rejects nine real
//! records in ten — 89 % of the reference corpus omits `MS`, which
//! `[OCMF Tab. 3]` marks `1..1` — and a lawful charging session becomes
//! unbillable for a schema reason. A lenient parser accepts everything, and an
//! operator never learns that their fleet emits records the official
//! Transparenzsoftware will reject.
//!
//! So parsing runs in a [`Profile`], every departure becomes a [`Deviation`]
//! with a spec citation, and the profile decides whether the collection is
//! fatal or informative. Nobody has to choose between working and knowing.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use ocmf::{Departure, DeviationKind, Limits, Profile, Record};
//!
//! let text = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
//! let record = Record::parse(text)?;
//!
//! // Every finding says where it is, what it breaks, and what says so.
//! for d in record.deviations() {
//!     println!("{} — {} [{}]", d.at, d.kind, d.spec());
//! }
//!
//! // A breach and a note are different sentences to put in front of a
//! // notified body, so they are different answers here.
//! let breaches = record.deviations().iter().filter(|d| d.is_breach()).count();
//! assert!(breaches > 0);
//! assert_eq!(
//!     DeviationKind::PrettyPrintedPayload.departure(),
//!     Departure::Advisory,
//!     "whitespace inside the payload is explicitly permitted",
//! );
//!
//! // `Strict` refuses the breaches; `Interop` reports everything and refuses
//! // nothing, which is why it is the default.
//! assert!(Record::parse_with(text, Profile::Strict, &Limits::DEFAULT).is_err());
//! # Ok(()) }
//! ```

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

/// How strictly to read a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Profile {
    /// The specification as written. Any [`Deviation`] is an error.
    ///
    /// Useful for a manufacturer checking their own output before a notified
    /// body does, and close to useless for reading a fleet.
    Strict,

    /// The specification as the reference verifier applies it.
    ///
    /// Bug-for-bug with S.A.F.E. Transparenzsoftware: `FV` is required even
    /// though `[OCMF Tab. 1]` marks it `0..1`, `MS` is optional even though
    /// `[OCMF Tab. 3]` marks it `1..1`. This is the profile to use when the
    /// question is "will the official tool accept this?".
    Reference,

    /// Read what the meters of the world actually emit.
    ///
    /// Accepts every deviation catalogued in [`DeviationKind`], reports all of
    /// them, and refuses only what cannot be read at all. The default,
    /// because the alternative is discarding evidence.
    #[default]
    Interop,
}

impl Profile {
    /// Whether a deviation of this kind is fatal under this profile.
    #[must_use]
    pub const fn rejects(self, kind: DeviationKind) -> bool {
        match self {
            Self::Strict => kind.departure().is_from_specification(),
            Self::Interop => false,
            Self::Reference => kind.rejected_by_reference_verifier(),
        }
    }
}

/// What a [`DeviationKind`] actually departs from.
///
/// Not every finding is a fault. Whitespace inside the payload is *explicitly
/// permitted* `[OCMF §JSON based OCMF Format]` and is still worth reporting,
/// because re-serialising such a record destroys it; carry-forward is the rule
/// `[OCMF Tab. 7]` states rather than a breach of it. A profile that refuses
/// those is not "the specification as written", it is "everything this crate
/// happens to notice" — which is a different and much less useful thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Departure {
    /// The record does something the specification does not permit.
    Specification,
    /// The record does something lawful that a reader still needs to know —
    /// because it is load-bearing, because it is a hazard, or because another
    /// implementation will trip over it.
    Advisory,
}

impl Departure {
    /// Whether this is a breach of the specification rather than a note.
    #[must_use]
    pub const fn is_from_specification(self) -> bool {
        matches!(self, Self::Specification)
    }
}

/// Where in the record a deviation was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// Byte offset into the record text.
    pub offset: usize,
    /// The field or path, when there is one.
    pub path: Option<String>,
}

impl Location {
    /// A location with only an offset.
    #[must_use]
    pub const fn at(offset: usize) -> Self {
        Self { offset, path: None }
    }

    /// A location naming a field.
    #[must_use]
    pub fn named(offset: usize, path: &str) -> Self {
        Self {
            offset,
            path: Some(path.to_owned()),
        }
    }

    /// A location naming the `n`-th reading's field.
    #[must_use]
    pub fn reading(offset: usize, index: usize, field: &str) -> Self {
        Self {
            offset,
            path: Some(alloc::format!("RD[{index}].{field}")),
        }
    }
}

impl core::fmt::Display for Location {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.path {
            Some(p) => write!(f, "{p} (byte {})", self.offset),
            None => write!(f, "byte {}", self.offset),
        }
    }
}

/// One departure from the specification, with the citation that makes it one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deviation {
    /// What was found.
    pub kind: DeviationKind,
    /// Where.
    pub at: Location,
    /// The offending value, quoted and bounded, where the kind has one.
    ///
    /// "A value the table does not define" is half a sentence; *which* value is
    /// the half a manufacturer can act on. Always quoted and escaped, and never
    /// longer than 48 characters, because every field in a record is
    /// attacker-influenced text that ends up in somebody's log — the reference
    /// corpus ships JNDI payloads inside a public-key field.
    pub value: Option<String>,
}

impl Deviation {
    /// A deviation of this kind, at this location.
    #[must_use]
    pub const fn new(kind: DeviationKind, at: Location) -> Self {
        Self {
            kind,
            at,
            value: None,
        }
    }

    /// A deviation that carries the value that caused it.
    #[must_use]
    pub fn with_value(kind: DeviationKind, at: Location, value: &str) -> Self {
        Self {
            kind,
            at,
            value: Some(crate::quote_bounded(value)),
        }
    }

    /// The specification reference this deviation is measured against.
    #[must_use]
    pub const fn spec(&self) -> &'static str {
        self.kind.spec()
    }

    /// What this departs from — see [`DeviationKind::departure`].
    #[must_use]
    pub const fn departure(&self) -> Departure {
        self.kind.departure()
    }

    /// Whether this is a breach of the specification rather than a note.
    ///
    /// The distinction a report should lead with: nine of the ten most common
    /// findings in the reference corpus are breaches, and the other one —
    /// carry-forward — is the rule `[OCMF Tab. 7]` states.
    #[must_use]
    pub const fn is_breach(&self) -> bool {
        self.kind.departure().is_from_specification()
    }
}

impl core::fmt::Display for Deviation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(v) = &self.value {
            write!(f, ": {v}")?;
        }
        write!(f, " at {} [{}]", self.at, self.kind.spec())
    }
}

// The variant, its stable name, its citation, whether it breaches the
// specification and its message are declared **together** here, and
// `DeviationKind::ALL` is generated from the same list. Five parallel `match`
// arms is five chances for a new kind to be catalogued in four of them, and a
// deviation nothing reports is the failure this whole module exists to prevent.
macro_rules! deviation_kinds {
    ($(
        $(#[doc = $doc:expr])*
        $name:ident => {
            spec: $spec:expr,
            departure: $departure:ident,
            reference_rejects: $refused:literal,
            message: $message:expr,
        }
    )*) => {
        /// The catalogue of things real records do that the specification
        /// does not say they may.
        ///
        /// Every variant here was either measured in the S.A.F.E. reference
        /// corpus or is a documented ambiguity in the specification; the doc
        /// comment says which. Each carries a citation ([`Self::spec`]), a
        /// stable name other implementations match on ([`Self::name`]), and
        /// whether it is a breach or a note ([`Self::departure`]).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum DeviationKind {
            $($(#[doc = $doc])* $name,)*
        }

        impl DeviationKind {
            /// Every kind this crate can report, for a caller enumerating them.
            ///
            /// Generated from the same list as the enum, so it cannot fall
            /// behind it.
            pub const ALL: &'static [Self] = &[$(Self::$name,)*];

            /// The stable machine-readable name, e.g. `MeterSerialMissing`.
            ///
            /// This is what the conformance suite and
            /// [`RecordSummary`](crate::RecordSummary) carry, so it is a
            /// written-down mapping rather than `{:?}` — a `Debug` rendering is
            /// a debugging aid the compiler is free to change, and other
            /// implementations match on these.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $(Self::$name => stringify!($name),)* }
            }

            /// The specification reference this deviation is measured against.
            #[must_use]
            pub const fn spec(self) -> &'static str {
                match self { $(Self::$name => $spec,)* }
            }

            /// What this kind departs from — the specification, or nothing at
            /// all.
            ///
            /// The [`Departure::Advisory`] kinds are the ones the specification
            /// (or the JSON reference it cites) *permits*: the payload's
            /// whitespace, carry-forward, an absent `FV`, a duplicate key, a
            /// high-`s` signature, and a record that is ahead of the reference
            /// verifier rather than of the document. Everything else is a
            /// breach.
            #[must_use]
            pub const fn departure(self) -> Departure {
                match self { $(Self::$name => Departure::$departure,)* }
            }

            /// Whether the S.A.F.E. reference verifier refuses a record for
            /// this.
            ///
            /// Derived from reading its source, not from guessing: it requires
            /// `FV`, dispatches on the version, splits sections on every `|`,
            /// and reads `SD` strictly as DER through `BouncyCastle`'s
            /// `ASN1InputStream`.
            #[must_use]
            pub const fn rejected_by_reference_verifier(self) -> bool {
                match self { $(Self::$name => $refused,)* }
            }
        }

        impl core::fmt::Display for DeviationKind {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(match self { $(Self::$name => $message,)* })
            }
        }
    };
}

deviation_kinds! {
    // ── Structure ───────────────────────────────────────────────────────────
    /// The payload section is pretty-printed. Lawful, and a standing trap:
    /// 9 of 256 corpus records are, and any re-serialisation breaks them.
    PrettyPrintedPayload => {
        spec: "OCMF §JSON based OCMF Format",
        departure: Advisory,
        reference_rejects: false,
        message: "payload section is pretty-printed",
    }

    /// A fourth `|`-separated section carrying a public key. Withdrawn from the
    /// specification (S.A.F.E. issue #16); the reference parser still reads it.
    FourthSectionPublicKey => {
        spec: "S.A.F.E. issue #16",
        departure: Specification,
        reference_rejects: false,
        message: "record carries the withdrawn fourth (public key) section",
    }

    /// The same key appears twice in one JSON object. Undefined by the
    /// specification's JSON reference; the last value is used.
    DuplicateKey => {
        spec: "OCMF §JSON based OCMF Format",
        departure: Advisory,
        reference_rejects: false,
        message: "duplicate JSON key",
    }

    /// A raw control character inside a JSON string (RFC 8259 forbids it).
    ControlCharacterInString => {
        spec: "RFC 8259",
        departure: Specification,
        reference_rejects: false,
        message: "raw control character inside a JSON string",
    }

    /// A number with a leading zero, or otherwise not in RFC 8259 form.
    NonCanonicalNumber => {
        spec: "RFC 8259",
        departure: Specification,
        reference_rejects: false,
        message: "number is not in RFC 8259 form",
    }

    /// A backslash escape inside a JSON string that RFC 8259 does not define
    /// (`\\q`), a `\\u` that is not followed by four hexadecimal digits, or an
    /// unpaired surrogate.
    ///
    /// json.org — the JSON reference the specification actually cites — is no
    /// clearer about these than RFC 8259 is generous, and implementations
    /// disagree: `serde_json` refuses the record, Gson takes the character
    /// after the backslash. This reader takes the character *and says so*,
    /// because a record two conforming parsers read differently is the exact
    /// shape of a billing dispute. An unpaired surrogate cannot be represented
    /// in a Rust `str` at all and decodes to U+FFFD; the original bytes are
    /// still reachable through the raw text.
    InvalidStringEscape => {
        spec: "RFC 8259",
        departure: Specification,
        reference_rejects: false,
        message: "invalid escape sequence inside a JSON string",
    }

    // ── Payload fields ──────────────────────────────────────────────────────
    /// `FV` is absent. `[OCMF Tab. 1]` allows it; the reference verifier does
    /// not, and rejects the record outright.
    FormatVersionMissing => {
        spec: "OCMF Tab. 1",
        departure: Advisory,
        reference_rejects: true,
        message: "`FV` is absent",
    }

    /// A field the table types as `String` arrived as a JSON number or
    /// boolean, and was read as the literal text it was written with.
    ///
    /// Two corpus records do this — `"FV":1.0` and `"CT":0` — and refusing
    /// either would throw away an intact signed payload over a pair of quotes.
    /// The [`Location`] names the field.
    ScalarFieldNotAString => {
        spec: "OCMF Tab. 1-8",
        departure: Specification,
        reference_rejects: false,
        message: "field is a JSON number or boolean, not a string",
    }

    /// `MS` is absent although `[OCMF Tab. 3]` marks it `1..1`
    /// (229 of 256 corpus records; S.A.F.E. issue #41).
    MeterSerialMissing => {
        spec: "OCMF Tab. 3, S.A.F.E. issue #41",
        departure: Specification,
        reference_rejects: false,
        message: "`MS` is absent although it is mandatory",
    }

    /// `IF` is absent although the text says one or no element must still be
    /// noted as an array (S.A.F.E. issue #31).
    IdentificationFlagsMissing => {
        spec: "OCMF Tab. 4, S.A.F.E. issue #31",
        departure: Specification,
        reference_rejects: false,
        message: "`IF` is absent",
    }

    /// `IT` is absent although `[OCMF Tab. 4]` marks it `1..1`.
    IdentificationTypeMissing => {
        spec: "OCMF Tab. 4",
        departure: Specification,
        reference_rejects: false,
        message: "`IT` is absent although it is mandatory",
    }

    /// `IS` is absent from a record that refers to a transaction, although
    /// `[OCMF Tab. 4]` marks it `1..1` there — "present iff there is a
    /// transaction reference, even when nobody could be assigned".
    IdentificationStatusMissing => {
        spec: "OCMF Tab. 4",
        departure: Specification,
        reference_rejects: false,
        message: "`IS` is absent although the record refers to a transaction",
    }

    /// `IF` carries more than the four elements `[OCMF Tab. 4]` allows.
    ///
    /// The cardinality is `0..4` because there are four flag groups — RFID
    /// `[Tab. 13]`, OCPP `[Tab. 14]`, ISO 15118 `[Tab. 15]` and PLMN
    /// `[Tab. 16]` — and a user assignment has one statement to make about
    /// each.
    IdentificationFlagsCardinality => {
        spec: "OCMF Tab. 4",
        departure: Specification,
        reference_rejects: false,
        message: "`IF` has more than the four elements the table allows",
    }

    /// `IF` carries two flags from the same group, so the record makes two
    /// statements about one thing.
    ///
    /// `[OCMF Tab. 4]` gives `IF` a cardinality of `0..4` over four groups and
    /// does not spell out "at most one from each" — which is why this is
    /// [`Departure::Advisory`] rather than a breach. It is still worth saying:
    /// `["RFID_NONE","RFID_PLAIN"]` claims the RFID assignment was both absent
    /// and unsecured, and nothing downstream can choose between them.
    IdentificationFlagsDuplicateGroup => {
        spec: "OCMF Tab. 4, 13-16",
        departure: Advisory,
        reference_rejects: false,
        message: "`IF` carries two flags from the same group",
    }

    /// The record names no serial number and no charge point, so nothing ties
    /// it to a signature component.
    ///
    /// `[OCMF §Relation of Serial Numbers, Charge Point and Public Key]` marks
    /// `GS` and `MS` *conditionally* mandatory and then says what the condition
    /// is: the meter's serial, or the gateway's, or — "alternatively, a direct
    /// identification of the charge point can be made" — `CT` with `CI`. A
    /// record with none of the three cannot be bound to a key by any route the
    /// specification describes, which is the one question a signature does not
    /// answer on its own.
    SourceUnidentifiable => {
        spec: "OCMF §Relation of Serial Numbers, Charge Point and Public Key",
        departure: Specification,
        reference_rejects: false,
        message: "no `MS`, no `GS` and no `CT`/`CI`: nothing identifies the source",
    }

    /// `PG` has a leading zero, which `[OCMF Tab. 2]` forbids.
    PaginationLeadingZero => {
        spec: "OCMF Tab. 2",
        departure: Specification,
        reference_rejects: false,
        message: "`PG` counter has a leading zero",
    }

    /// A string field is longer than its table permits.
    FieldTooLong => {
        spec: "OCMF Tab. 4-5",
        departure: Specification,
        reference_rejects: false,
        message: "field exceeds its documented maximum length",
    }

    /// An unknown key outside the reserved extension initials `U`–`Z`
    /// (and `A`–`F` in the signature section) `[OCMF §Extension Points]`.
    UnknownKey => {
        spec: "OCMF §Extension Points",
        departure: Specification,
        reference_rejects: false,
        message: "unknown key outside the reserved extension initials",
    }

    /// A field carries a value the closed table for that field does not
    /// define — an `ST` letter outside `[OCMF Tab. 10]`, an `RU` outside
    /// `[OCMF Tab. 20]`, a `CT` outside `[OCMF Tab. 18]`, and so on.
    ///
    /// The value is kept verbatim and every predicate that could authorise
    /// money answers `false` for it (D22). Saying so is the other half: a
    /// station that writes `"RU":"sec"` — two readings in the reference corpus
    /// do — has emitted a record no conformant reader can price, and the
    /// manufacturer should hear it from `ocmf explain` rather than from a
    /// notified body.
    UndefinedTableValue => {
        spec: "OCMF Tab. 8, 10-11, 17-22",
        departure: Specification,
        reference_rejects: false,
        message: "value is not one the table defines",
    }

    /// A field's JSON type is not the one its table states, and no leniency
    /// covers it: an `RD` that is not an array, an `IS` that is not a boolean,
    /// an `LC` that is not an object, a scalar field holding a structure.
    ///
    /// The value cannot be used, so the typed view does not carry it — but the
    /// *record* survives, because the payload is the evidence a dispute turns
    /// on and one bad field is not a reason to lose it. Distinct from
    /// [`Self::ScalarFieldNotAString`], which is the case where the value was
    /// usable as text and was used. The [`Deviation::value`] carries the JSON
    /// kind that was found.
    FieldTypeMismatch => {
        spec: "OCMF Tab. 1-8",
        departure: Specification,
        reference_rejects: false,
        message: "field has a JSON type its table does not allow",
    }

    /// `PG` is absent although `[OCMF Tab. 2]` marks it `1..1`.
    PaginationMissing => {
        spec: "OCMF Tab. 2",
        departure: Specification,
        reference_rejects: false,
        message: "`PG` is absent although it is mandatory",
    }

    /// `PG` is present and is not `<context letter><digits>` `[OCMF Tab. 2]`.
    PaginationMalformed => {
        spec: "OCMF Tab. 2",
        departure: Specification,
        reference_rejects: false,
        message: "`PG` is not a context letter followed by digits",
    }

    /// `RD` held more readings than [`Limits::readings`](crate::Limits) allows
    /// and the surplus was dropped.
    ///
    /// The one place in this crate where something is truncated rather than
    /// reported and kept — because the point of a bound is to bound the work.
    /// The record, its text and its signature are untouched; the typed view is
    /// short, and says so. The largest real record carries six readings.
    ReadingsTruncated => {
        spec: "OCMF §Readings",
        departure: Advisory,
        reference_rejects: false,
        message: "`RD` holds more readings than the configured limit allows",
    }

    /// `LC` is present and omits `LR` or `LU`, which `[OCMF Tab. 24]` marks
    /// mandatory inside the block.
    ///
    /// A cable-loss compensation with no resistance or no unit describes no
    /// compensation, and a `CL` on a reading is then a number with nothing
    /// behind it.
    LossCompensationIncomplete => {
        spec: "OCMF Tab. 24",
        departure: Specification,
        reference_rejects: false,
        message: "`LC` omits a field Tab. 24 marks mandatory",
    }

    /// `RD` is absent: the record carries no readings at all.
    ///
    /// "One or more readings can be stored in a record"
    /// `[OCMF §Readings]` — no table in the specification gives `RD` a
    /// cardinality, which is `[S.A.F.E. #44]`'s neighbourhood, but a record
    /// with no reading states nothing about any meter.
    ReadingsMissing => {
        spec: "OCMF §Readings",
        departure: Specification,
        reference_rejects: false,
        message: "`RD` is absent: the record carries no readings",
    }

    /// `FV` is not `<major>.<minor>` `[OCMF Tab. 1]`.
    FormatVersionMalformed => {
        spec: "OCMF Tab. 1",
        departure: Specification,
        reference_rejects: false,
        message: "`FV` is not `<major>.<minor>`",
    }

    /// `FV` names a format version the reference verifier will not dispatch on.
    ///
    /// Not a departure from anything: the specification is at 1.4 and a record
    /// may say so. It is a departure from the **legally recognised
    /// implementation**, whose version dispatch reads `version <= 1.3` after a
    /// `MAX_VERSION = 1.5` check and answers "not compatible" (checked against
    /// `def928b`). A station shipping `FV: "1.4"` today will have its records
    /// refused by the tool a driver runs, and that is worth hearing before the
    /// driver finds out.
    FormatVersionAheadOfReference => {
        spec: "S.A.F.E. Transparenzsoftware def928b",
        departure: Advisory,
        reference_rejects: true,
        message: "`FV` is newer than the reference verifier dispatches on (1.3)",
    }

    /// `ID` does not have the shape `IT` prescribes for it `[OCMF Tab. 17]` —
    /// an `ISO14443` UID that is not 4 or 7 bytes of hex, an `EMAID` that is
    /// not 14 or 15 characters, a `PHONE_NUMBER` without its leading `+`.
    ///
    /// Only the six types whose format the table actually states are checked.
    /// The other twelve say "no exact format defined", and inventing one would
    /// report a deviation from a rule nobody wrote.
    IdentificationDataFormat => {
        spec: "OCMF Tab. 17",
        departure: Specification,
        reference_rejects: false,
        message: "`ID` does not have the shape `IT` prescribes",
    }

    /// `CI` does not have the shape `CT` prescribes `[OCMF Tab. 18]` — `CBIDC`
    /// is a charge box ID and a connector ID with a space between them.
    ChargePointIdFormat => {
        spec: "OCMF Tab. 18",
        departure: Specification,
        reference_rejects: false,
        message: "`CI` does not have the shape `CT` prescribes",
    }

    /// A vendor extension inside an `RD` reading object. The specification
    /// reserves extension initials only at the payload's top level, yet this is
    /// where extensions actually occur in the field.
    ExtensionInsideReading => {
        spec: "OCMF §Extension Points",
        departure: Specification,
        reference_rejects: false,
        message: "vendor extension inside a reading object",
    }

    // ── Readings ────────────────────────────────────────────────────────────
    /// `RV` arrived as a JSON string rather than a number
    /// (23 corpus readings, e.g. `"00000000.000"`).
    RvIsString => {
        spec: "OCMF Tab. 7",
        departure: Specification,
        reference_rejects: false,
        message: "`RV` is a JSON string, not a number",
    }

    /// A reading has no value for a field `[OCMF Tab. 7]` marks `1..1`, and no
    /// earlier reading in the record supplies one.
    ///
    /// Distinct from [`Self::CarriedForwardMandatoryField`], which is the
    /// *lawful* case. `TM` and `ST` are required on every reading; `RU` is
    /// required wherever there is an `RV`, because the exemption the table
    /// grants — "can be omitted if only the occurrence of an error condition
    /// (event) of the meter is to be indicated" — is an exemption for readings
    /// that report no value at all.
    MandatoryReadingFieldMissing => {
        spec: "OCMF Tab. 7",
        departure: Specification,
        reference_rejects: false,
        message: "reading has no value for a mandatory field, and none to carry",
    }

    /// A field marked `1..1` was omitted and taken from the previous reading
    /// `[OCMF Tab. 7 preamble]` — lawful, and worth surfacing because it means
    /// the record's readings cannot be read independently of one another.
    CarriedForwardMandatoryField => {
        spec: "OCMF Tab. 7",
        departure: Advisory,
        reference_rejects: false,
        message: "mandatory field carried forward from the previous reading",
    }

    /// `TM` uses `±hh:mm` rather than the `±hhmm` of `[OCMF Tab. 7]`.
    TimeOffsetWithColon => {
        spec: "OCMF Tab. 7",
        departure: Specification,
        reference_rejects: false,
        message: "`TM` offset is written `±hh:mm`",
    }

    /// `TM` separates milliseconds with `.` rather than the specified `,`.
    TimeDotMilliseconds => {
        spec: "OCMF Tab. 7",
        departure: Specification,
        reference_rejects: false,
        message: "`TM` separates milliseconds with `.`",
    }

    /// `TM` carries no synchronisation letter `[OCMF Tab. 19]`.
    TimeStatusMissing => {
        spec: "OCMF Tab. 19",
        departure: Specification,
        reference_rejects: false,
        message: "`TM` has no synchronisation letter",
    }

    /// `TM` is not a timestamp at all, so the reading has no time.
    ///
    /// The reading, the record and the signature all survive: an unreadable
    /// clock stamp costs the instant, not the evidence.
    TimeMalformed => {
        spec: "OCMF Tab. 7",
        departure: Specification,
        reference_rejects: false,
        message: "`TM` is not a timestamp",
    }

    /// `TM`'s fractional second is not the three digits `[OCMF Tab. 7]` states.
    ///
    /// Fewer is under-specified; more is sub-millisecond precision the format
    /// does not define, and it is **truncated** — so a reader that silently
    /// accepted it would be dropping digits a station wrote.
    TimeSubSecondDigits => {
        spec: "OCMF Tab. 7",
        departure: Specification,
        reference_rejects: false,
        message: "`TM` fractional second is not three digits",
    }

    /// `RI` is present and has no OBIS shape at all, so the reading names no
    /// register `[OCMF Tab. 25]`.
    ObisMalformed => {
        spec: "OCMF Tab. 25",
        departure: Specification,
        reference_rejects: false,
        message: "`RI` is not an OBIS code",
    }

    /// A numeric field is not a decimal this crate can represent exactly —
    /// malformed, or outside the range of a 96-bit decimal.
    ///
    /// The field is dropped rather than approximated: `RV` is money, and a
    /// number nobody can hold exactly is not a meter reading. Everything else
    /// about the record, including its signature, is unaffected.
    NumberUnrepresentable => {
        spec: "OCMF Tab. 7",
        departure: Specification,
        reference_rejects: false,
        message: "value is not a decimal that can be represented exactly",
    }

    /// An OBIS code not in the form `[OCMF Tab. 25]` gives — which is every
    /// OBIS code in the reference corpus.
    ObisNonCanonical => {
        spec: "OCMF Tab. 25",
        departure: Specification,
        reference_rejects: false,
        message: "OBIS code is not in the canonical form",
    }

    // ── Signature section ───────────────────────────────────────────────────
    /// `SD` is a bare `r‖s` although `SM` says (or defaults to)
    /// `application/x-der`. Isabellenhütte records do this.
    RawSignatureNotDer => {
        spec: "OCMF Tab. 8",
        departure: Specification,
        reference_rejects: true,
        message: "`SD` is a bare r||s, not DER",
    }

    /// The DER of `SD` is accepted by `BouncyCastle` but is not canonical
    /// (non-minimal length, padding, or a trailing byte).
    NonCanonicalDer => {
        spec: "OCMF Tab. 8",
        departure: Specification,
        reference_rejects: false,
        message: "`SD` is DER but not canonical",
    }

    /// `SA` is spelled differently from `[OCMF Tab. 22]` — most often
    /// `brainpoolP256r1` where the table says `brainpool256r1`.
    AlgorithmIdentifierSpelling => {
        spec: "OCMF Tab. 22",
        departure: Specification,
        reference_rejects: false,
        message: "`SA` is spelled differently from the table",
    }

    /// `SD` does not decode with the encoding `SE` names, so the record
    /// carries no checkable signature at all. The payload is still intact and
    /// still evidence, so this costs the signature and not the record.
    SignatureDataUndecodable => {
        spec: "OCMF Tab. 8",
        departure: Specification,
        reference_rejects: true,
        message: "`SD` does not decode with the encoding `SE` names",
    }

    /// `SD` is absent although `[OCMF Tab. 8]` marks it `1..1`: the record
    /// carries no signature to check.
    SignatureDataMissing => {
        spec: "OCMF Tab. 8",
        departure: Specification,
        reference_rejects: true,
        message: "`SD` is absent: the record carries no signature",
    }

    /// The signature's `s` is above `n/2`. Both forms verify; the pair is a
    /// malleability of the same statement, which is why record identity is the
    /// payload digest and not the record text.
    HighSSignature => {
        spec: "OCMF Tab. 8",
        departure: Advisory,
        reference_rejects: false,
        message: "signature `s` is above n/2",
    }

}

/// Applies a profile to a collection of deviations.
///
/// Returns the subset the profile refuses, which is empty when the record is
/// acceptable.
pub(crate) fn rejected(profile: Profile, deviations: &[Deviation]) -> Vec<Deviation> {
    deviations
        .iter()
        .filter(|d| profile.rejects(d.kind))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interop_rejects_nothing_and_strict_rejects_a_breach() {
        let d = Deviation::new(DeviationKind::MeterSerialMissing, Location::at(0));
        assert!(rejected(Profile::Interop, core::slice::from_ref(&d)).is_empty());
        assert_eq!(
            rejected(Profile::Strict, core::slice::from_ref(&d)).len(),
            1
        );
    }

    #[test]
    fn reference_accepts_a_missing_meter_serial_and_refuses_a_missing_fv() {
        let ms = Deviation::new(DeviationKind::MeterSerialMissing, Location::at(0));
        let fv = Deviation::new(DeviationKind::FormatVersionMissing, Location::at(0));
        assert!(rejected(Profile::Reference, &[ms]).is_empty());
        assert_eq!(rejected(Profile::Reference, &[fv]).len(), 1);
    }

    #[test]
    fn strict_refuses_breaches_and_keeps_what_the_specification_permits() {
        // The whole point of the split: whitespace inside the payload, an
        // absent `FV`, carry-forward and a duplicate key are all things the
        // specification (or the JSON reference it cites) *permits*. A profile
        // that calls itself "the specification as written" and refuses them is
        // refusing its own reading.
        for lawful in [
            DeviationKind::PrettyPrintedPayload,
            DeviationKind::CarriedForwardMandatoryField,
            DeviationKind::DuplicateKey,
            DeviationKind::FormatVersionMissing,
            DeviationKind::FormatVersionAheadOfReference,
            DeviationKind::HighSSignature,
        ] {
            assert_eq!(lawful.departure(), Departure::Advisory, "{lawful}");
            assert!(!Profile::Strict.rejects(lawful), "{lawful}");
        }
        for breach in [
            DeviationKind::MeterSerialMissing,
            DeviationKind::UndefinedTableValue,
            DeviationKind::RvIsString,
            DeviationKind::ObisNonCanonical,
            DeviationKind::ScalarFieldNotAString,
            DeviationKind::ChargePointIdFormat,
        ] {
            assert_eq!(breach.departure(), Departure::Specification, "{breach}");
            assert!(Profile::Strict.rejects(breach), "{breach}");
        }
        // And `Interop` still refuses nothing at all.
        for k in DeviationKind::ALL {
            assert!(!Profile::Interop.rejects(*k), "{k}");
        }
    }

    #[test]
    fn the_reference_profile_refuses_exactly_what_the_official_tool_refuses() {
        let refused: alloc::vec::Vec<&str> = DeviationKind::ALL
            .iter()
            .filter(|k| Profile::Reference.rejects(**k))
            .map(|k| k.name())
            .collect();
        assert_eq!(
            refused,
            [
                "FormatVersionMissing",
                "FormatVersionAheadOfReference",
                "RawSignatureNotDer",
                "SignatureDataUndecodable",
                "SignatureDataMissing",
            ],
            "read out of the Java, not guessed: it requires `FV`, dispatches on \
             `version <= 1.3`, and reads `SD` strictly as DER"
        );
    }

    /// The numbers the documentation quotes. Prose is not a test — so these
    /// are, and a kind added without deciding what it departs from moves one.
    #[test]
    fn the_catalogue_is_the_size_the_documentation_says_it_is() {
        assert_eq!(DeviationKind::ALL.len(), 47, "kinds in the catalogue");
        assert_eq!(
            DeviationKind::ALL
                .iter()
                .filter(|k| k.departure() == Departure::Advisory)
                .count(),
            8,
            "lawful findings a reader still needs to know"
        );
        assert_eq!(
            DeviationKind::ALL
                .iter()
                .filter(|k| k.rejected_by_reference_verifier())
                .count(),
            5,
            "what the S.A.F.E. Transparenzsoftware actually refuses"
        );
    }

    #[test]
    fn every_kind_cites_a_specification_reference_and_has_a_stable_name() {
        use alloc::collections::BTreeSet;
        let mut names = BTreeSet::new();
        for &k in DeviationKind::ALL {
            assert!(!k.spec().is_empty(), "{k} has no citation");
            assert!(!alloc::format!("{k}").is_empty(), "{k} has no message");
            assert!(names.insert(k.name()), "{} is not a unique name", k.name());
            assert_eq!(
                k.name(),
                alloc::format!("{k:?}"),
                "the written-down name must track the variant"
            );
        }
        assert_eq!(names.len(), DeviationKind::ALL.len());
    }
}
