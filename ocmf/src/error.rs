//! Errors, one enum per phase.
//!
//! Never one enum for everything: a caller holding a record and a caller
//! holding a key ask different questions, and a match arm that can only be
//! reached by the other caller's mistake is noise. Every variant that names a
//! rule cites the table it comes from, and no message ever interpolates
//! unescaped input — every field in an OCMF record is attacker-influenced text.

use alloc::string::String;

use crate::deviation::Deviation;

/// Something went wrong reading a record.
///
/// Every variant here is **structural**: the bytes are not
/// `OCMF|<JSON object>|<JSON object>`, or they exceed a
/// [`Limits`](crate::Limits) bound, or a [`Profile`](crate::Profile) refused
/// what was found. Nothing about the *value* of a field is in this enum —
/// those are [`Deviation`]s, because the payload is the evidence a dispute
/// turns on and one unreadable field is not a reason to throw it away.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The record does not begin with the `OCMF` header `[OCMF §Header]`.
    #[error("not an OCMF record: expected the header `OCMF`")]
    NotOcmf,

    /// The header is present but no `|` follows it.
    #[error("truncated record: the header is not followed by `|`")]
    MissingDelimiter,

    /// The payload section is not followed by `|` and a signature section.
    #[error("truncated record: the payload section is not followed by `|`")]
    MissingSignatureSection,

    /// Bytes appear between the end of a section's JSON value and the
    /// delimiter that should follow it.
    #[error("unexpected input at byte {offset} between the end of a section and `|`")]
    TrailingSectionBytes {
        /// Byte offset of the first unexpected byte.
        offset: usize,
    },

    /// More `|`-separated sections than OCMF defines (three, or four with the
    /// withdrawn public-key section).
    #[error("too many sections: OCMF defines at most four")]
    TooManySections,

    /// The JSON of one of the sections could not be read.
    #[error("invalid JSON at byte {offset}: expected {expected}")]
    Json {
        /// Byte offset in the record.
        offset: usize,
        /// What the reader wanted to see there.
        expected: &'static str,
    },

    /// A section is not a JSON object.
    #[error("the {section} section is a JSON {found}, not an object")]
    SectionNotAnObject {
        /// `payload` or `signature`.
        section: &'static str,
        /// The kind that was found instead.
        found: &'static str,
    },

    /// The record is well-formed but departs from the specification, and the
    /// profile in force does not permit that.
    ///
    /// The full list is carried along: a strict caller usually wants to log
    /// every reason, not just the first.
    #[error("record deviates from the specification: {}", .0.first().map_or_else(|| String::from("(none)"), |d| alloc::format!("{d}")))]
    Deviates(alloc::vec::Vec<Deviation>),

    /// A [`Limits`](crate::Limits) bound was reached.
    #[error("input exceeds the {limit} limit of {allowed}")]
    LimitExceeded {
        /// Which bound.
        limit: &'static str,
        /// Its value.
        allowed: usize,
    },
}

/// Something went wrong reading a public key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The bytes are not any recognised key shape.
    #[error("unrecognised public key encoding ({len} bytes)")]
    Unrecognised {
        /// How many bytes were offered.
        len: usize,
    },

    /// A DER structure was malformed.
    #[error("malformed DER in the public key: {0}")]
    Der(&'static str),

    /// The `SubjectPublicKeyInfo` names an algorithm that is not ECDSA.
    #[error("public key algorithm is not id-ecPublicKey")]
    NotEcdsa,

    /// The curve OID is not one of the seven in `[OCMF Tab. 23]`.
    #[error("unknown curve OID `{0}` [OCMF Tab. 23]")]
    UnknownCurve(String),

    /// A textual key was not valid hex or Base64.
    #[error("public key text is neither hexadecimal nor Base64")]
    NotEncoded,

    /// An OCA composite key string (`oca:<encoding>:<content-type>:<key>`) was
    /// malformed.
    #[error("malformed OCA public key composition: {0}")]
    OcaComposition(&'static str),

    /// The bytes are not a SEC1 point of the right width for the curve.
    ///
    /// This is a *shape* check, not a curve-membership one: whether the point
    /// actually lies on the curve needs field arithmetic, which lives behind
    /// the `verify` feature and reports
    /// [`VerifyError::KeyNotOnCurve`].
    #[error("public key is not a {curve} point: wrong length")]
    InvalidPoint {
        /// The curve it was measured against.
        curve: &'static str,
    },
}

/// Something went wrong checking a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// `SA` names an algorithm outside `[OCMF Tab. 22]`.
    #[error("unknown signature algorithm `{algorithm}` [OCMF Tab. 22]")]
    UnknownAlgorithm {
        /// The identifier as written.
        algorithm: String,
    },

    /// The algorithm is in the table, but this build cannot check it.
    ///
    /// Never reported as "does not verify": a missing curve and a bad
    /// signature are different facts, and only one of them is the station's
    /// fault.
    #[error("{algorithm} is not supported by this build ({reason})")]
    Unsupported {
        /// The algorithm named in `SA`.
        algorithm: &'static str,
        /// Why it is unavailable — a missing feature, or no implementation.
        reason: &'static str,
    },

    /// The key is on a different curve than `SA` names.
    #[error("key is on {key_curve} but the record is signed {algorithm} [OCMF Tab. 22-23]")]
    AlgorithmKeyMismatch {
        /// The curve read from the key itself.
        key_curve: &'static str,
        /// The algorithm named in the record.
        algorithm: &'static str,
    },

    /// `SD` is absent, or could not be decoded with the encoding `SE` names.
    #[error("signature data is not valid {encoding}")]
    SignatureEncoding {
        /// `hex`, `base64`, or the quoted value `SE` named that neither
        /// `[OCMF Tab. 8]` nor this crate defines.
        encoding: String,
    },

    /// The signature bytes are neither DER nor a raw `r‖s` of the right size.
    #[error("signature is neither DER nor a {expected}-byte raw r||s ({len} bytes)")]
    SignatureShape {
        /// Bytes offered.
        len: usize,
        /// Bytes a raw signature would have needed.
        expected: usize,
    },

    /// `r` or `s` is not in `[1, n)`: zero, or at or beyond the group order.
    ///
    /// A scalar outside that interval is not a signature anything produced —
    /// distinct from [`Self::HighSSignature`], where the scalars are in range
    /// and the caller asked for the other half of the malleable pair.
    #[error("signature scalars are out of range [1, n)")]
    SignatureScalars,

    /// The signature is the high half of ECDSA's malleable pair, and
    /// [`Malleability::RejectHighS`](crate::Malleability::RejectHighS) is in
    /// force.
    ///
    /// Not an authenticity failure: `(r, s)` and `(r, n − s)` are the same
    /// statement and OCMF permits either. The reference verifier accepts both,
    /// so this is only ever a policy answer — the deduplication hazard it
    /// exists for is handled by keying on
    /// [`Record::payload_digest`](crate::Record::payload_digest).
    #[error("signature `s` is above n/2 on {curve} and the low form was required")]
    HighSSignature {
        /// The curve whose order decided it.
        curve: &'static str,
    },

    /// The key is the right length for the curve but is not a point on it.
    ///
    /// Distinct from [`Self::NotVerified`] on purpose: a key that is not a
    /// point is a broken registry entry or a transcription error, and the
    /// station's record may be perfectly good. Only the curve backend can tell,
    /// because deciding it needs field arithmetic.
    #[error("public key is not a point on {curve}")]
    KeyNotOnCurve {
        /// The curve the point was checked against.
        curve: &'static str,
    },

    /// The signature is well-formed and does not match.
    ///
    /// This is the only variant that means *the record is not authentic*.
    #[error("signature does not verify against this key")]
    NotVerified,

    /// The key material could not be read at all.
    ///
    /// Only produced by the convenience entry points that take raw key bytes
    /// or text; [`crate::verify()`] itself takes a key that has already parsed.
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// Something went wrong building a record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// A field value contains `|`, which would make the record unreadable
    /// `[OCMF §JSON based OCMF Format]`.
    #[error("field `{field}` contains `|`, which is not allowed within a section")]
    PipeInField {
        /// The OCMF key.
        field: &'static str,
    },

    /// A required field was not set.
    #[error("field `{field}` is required [{spec}]")]
    MissingField {
        /// The OCMF key.
        field: &'static str,
        /// The table that requires it.
        spec: &'static str,
    },

    /// A field was set to a value outside the set its table defines.
    #[error("field `{field}` is not one of the values [{spec}] defines")]
    FieldValue {
        /// The OCMF key.
        field: &'static str,
        /// The table that defines the permitted set.
        spec: &'static str,
    },

    /// `SA` was suppressed while signing on a curve that is not the default.
    ///
    /// An absent `SA` means `ECDSA-secp256r1-SHA256` `[OCMF Tab. 22]`, so a
    /// record signed on another curve without it is a record that misstates
    /// its own algorithm.
    #[error("`SA` must be written: the default algorithm is secp256r1, not {curve} [OCMF Tab. 22]")]
    AlgorithmMustBeWritten {
        /// The curve the signer actually uses.
        curve: &'static str,
    },

    /// `RD` would be empty.
    #[error("a record needs at least one reading [OCMF §Readings]")]
    NoReadings,

    /// The transaction markers do not form a coherent record.
    #[error("incoherent transaction markers: {reason} [OCMF Tab. 7]")]
    TransactionMarkers {
        /// What is wrong.
        reason: &'static str,
    },

    /// A string field is longer than its table allows.
    #[error("field `{field}` is {len} characters, the maximum is {max} [{spec}]")]
    TooLong {
        /// The OCMF key.
        field: &'static str,
        /// Its length.
        len: usize,
        /// The permitted maximum.
        max: usize,
        /// The table that sets it.
        spec: &'static str,
    },

    /// Signing failed inside the signer.
    #[error("the signer failed")]
    Signer,

    /// The record this builder produced could not be read back, or did not
    /// verify against its own key.
    ///
    /// A signing path that can emit an unverifiable record is worse than none,
    /// so every signature is checked before it is returned.
    #[error("internal: the signed record failed its own verification ({0})")]
    SelfCheck(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn messages_name_the_rule_they_enforce() {
        let e = ParseError::SectionNotAnObject {
            section: "payload",
            found: "array",
        };
        assert_eq!(
            e.to_string(),
            "the payload section is a JSON array, not an object"
        );
    }

    #[test]
    fn unsupported_is_not_not_verified() {
        let e = VerifyError::Unsupported {
            algorithm: "ECDSA-brainpool256r1-SHA256",
            reason: "no pure-Rust implementation; enable `backend-openssl`",
        };
        assert!(e.to_string().contains("not supported"));
        assert_ne!(e, VerifyError::NotVerified);
    }
}
