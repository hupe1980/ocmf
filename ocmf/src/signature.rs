//! The signature section: `SA`, `SE`, `SM`, `SD` `[OCMF Tab. 8]`.
//!
//! Three of the four fields are optional and, in the field, almost always
//! absent: of 256 records in the reference corpus, 23 carry `SA`, exactly one
//! carries `SE`, and none carries `SM`. **The defaults are what verification
//! actually runs on**, so they are constants with citations rather than
//! literals scattered through the code.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use ocmf::{Curve, SignatureAlgorithm, SignatureEncoding};
//!
//! let text = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
//! let record = ocmf::Record::parse(text)?;
//! let section = record.signature();
//!
//! // This record writes no `SA` at all — 233 of 256 real ones do not — so the
//! // algorithm is the default `[OCMF Tab. 22]` states, and the section says so.
//! assert!(!section.algorithm_was_written());
//! assert_eq!(
//!     section.algorithm(),
//!     Some(SignatureAlgorithm::EcdsaSecp256r1Sha256),
//! );
//! assert_eq!(section.curve(), Some(Curve::Secp256r1));
//! assert_eq!(section.encoding(), Some(SignatureEncoding::Hex));
//! assert_eq!(section.data().unwrap().len(), 71);
//! # Ok(()) }
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::deviation::{Deviation, DeviationKind, Location};
use crate::encoding::{base64_decode, hex_decode};
use crate::json::{Object, RawStr, Value};

/// An elliptic curve named by `[OCMF Tab. 23]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Curve {
    /// secp192k1 — 192 bit, Koblitz.
    Secp192k1,
    /// secp192r1, NIST P-192, prime192v1.
    Secp192r1,
    /// secp256k1 — 256 bit, Koblitz.
    Secp256k1,
    /// secp256r1, NIST P-256, prime256v1. The default since OCMF 0.4.
    Secp256r1,
    /// brainpoolP256r1.
    BrainpoolP256r1,
    /// secp384r1, NIST P-384.
    Secp384r1,
    /// brainpoolP384r1.
    BrainpoolP384r1,
}

impl Curve {
    /// Every curve in `[OCMF Tab. 23]`, in table order.
    pub const ALL: [Self; 7] = [
        Self::Secp192k1,
        Self::Secp256k1,
        Self::Secp192r1,
        Self::Secp256r1,
        Self::BrainpoolP256r1,
        Self::Secp384r1,
        Self::BrainpoolP384r1,
    ];

    /// The curve's name as `[OCMF Tab. 23]` writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Secp192k1 => "secp192k1",
            Self::Secp192r1 => "secp192r1",
            Self::Secp256k1 => "secp256k1",
            Self::Secp256r1 => "secp256r1",
            Self::BrainpoolP256r1 => "brainpoolP256r1",
            Self::Secp384r1 => "secp384r1",
            Self::BrainpoolP384r1 => "brainpoolP384r1",
        }
    }

    /// The named-curve object identifier used in a `SubjectPublicKeyInfo`.
    #[must_use]
    pub const fn oid(self) -> &'static [u8] {
        match self {
            // 1.2.840.10045.3.1.1
            Self::Secp192r1 => &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01],
            // 1.2.840.10045.3.1.7
            Self::Secp256r1 => &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            // 1.3.132.0.31
            Self::Secp192k1 => &[0x2b, 0x81, 0x04, 0x00, 0x1f],
            // 1.3.132.0.10
            Self::Secp256k1 => &[0x2b, 0x81, 0x04, 0x00, 0x0a],
            // 1.3.132.0.34
            Self::Secp384r1 => &[0x2b, 0x81, 0x04, 0x00, 0x22],
            // 1.3.36.3.3.2.8.1.1.7
            Self::BrainpoolP256r1 => &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
            // 1.3.36.3.3.2.8.1.1.11
            Self::BrainpoolP384r1 => &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b],
        }
    }

    /// The curve for a named-curve OID.
    #[must_use]
    pub fn from_oid(oid: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.oid() == oid)
    }

    /// The order `n` of the curve's base point, big-endian, exactly
    /// [`Self::field_bytes`] long.
    ///
    /// A signature scalar is only meaningful in `[1, n)`, and `(r, s)` and
    /// `(r, n − s)` are the same statement — so this one constant answers both
    /// "is this scalar in range?" and "is this the high half of a malleable
    /// pair?". Deriving the second question from `n` rather than storing a
    /// separate half-order is deliberate: two constants per curve can disagree,
    /// and a wrong group order looks exactly as plausible as a right one.
    ///
    /// Values from SEC 2 v2.0 (the `secp*` curves) and RFC 5639 §3 (brainpool),
    /// cross-checked in the tests against `RustCrypto`'s own constants and,
    /// where the `backend-openssl` feature is on, against `OpenSSL`.
    #[must_use]
    pub const fn order(self) -> &'static [u8] {
        match self {
            Self::Secp192k1 => &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x26, 0xf2,
                0xfc, 0x17, 0x0f, 0x69, 0x46, 0x6a, 0x74, 0xde, 0xfd, 0x8d,
            ],
            Self::Secp192r1 => &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x99, 0xde,
                0xf8, 0x36, 0x14, 0x6b, 0xc9, 0xb1, 0xb4, 0xd2, 0x28, 0x31,
            ],
            Self::Secp256k1 => &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
                0xd0, 0x36, 0x41, 0x41,
            ],
            Self::Secp256r1 => &[
                0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
                0xfc, 0x63, 0x25, 0x51,
            ],
            Self::BrainpoolP256r1 => &[
                0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83,
                0x8d, 0x71, 0x8c, 0x39, 0x7a, 0xa3, 0xb5, 0x61, 0xa6, 0xf7, 0x90, 0x1e, 0x0e, 0x82,
                0x97, 0x48, 0x56, 0xa7,
            ],
            Self::Secp384r1 => &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81,
                0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec,
                0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
            ],
            Self::BrainpoolP384r1 => &[
                0x8c, 0xb9, 0x1e, 0x82, 0xa3, 0x38, 0x6d, 0x28, 0x0f, 0x5d, 0x6f, 0x7e, 0x50, 0xe6,
                0x41, 0xdf, 0x15, 0x2f, 0x71, 0x09, 0xed, 0x54, 0x56, 0xb3, 0x1f, 0x16, 0x6e, 0x6c,
                0xac, 0x04, 0x25, 0xa7, 0xcf, 0x3a, 0xb6, 0xaf, 0x6b, 0x7f, 0xc3, 0x10, 0x3b, 0x88,
                0x32, 0x02, 0xe9, 0x04, 0x65, 0x65,
            ],
        }
    }

    /// Bytes in one field element, and so in `r`, in `s`, and in each
    /// coordinate of an uncompressed point.
    #[must_use]
    pub const fn field_bytes(self) -> usize {
        match self {
            Self::Secp192k1 | Self::Secp192r1 => 24,
            Self::Secp256k1 | Self::Secp256r1 | Self::BrainpoolP256r1 => 32,
            Self::Secp384r1 | Self::BrainpoolP384r1 => 48,
        }
    }

    /// Length of a raw `r‖s` signature on this curve — the "block length"
    /// column of `[OCMF Tab. 22]`.
    #[must_use]
    pub const fn signature_bytes(self) -> usize {
        self.field_bytes() * 2
    }

    /// The signature algorithm that pairs with this curve `[OCMF Tab. 22]`.
    #[must_use]
    pub const fn algorithm(self) -> SignatureAlgorithm {
        match self {
            Self::Secp192k1 => SignatureAlgorithm::EcdsaSecp192k1Sha256,
            Self::Secp192r1 => SignatureAlgorithm::EcdsaSecp192r1Sha256,
            Self::Secp256k1 => SignatureAlgorithm::EcdsaSecp256k1Sha256,
            Self::Secp256r1 => SignatureAlgorithm::EcdsaSecp256r1Sha256,
            Self::BrainpoolP256r1 => SignatureAlgorithm::EcdsaBrainpool256r1Sha256,
            Self::Secp384r1 => SignatureAlgorithm::EcdsaSecp384r1Sha256,
            Self::BrainpoolP384r1 => SignatureAlgorithm::EcdsaBrainpool384r1Sha256,
        }
    }
}

impl core::fmt::Display for Curve {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// A signature algorithm from `[OCMF Tab. 22]`. All seven, all ECDSA/SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// `ECDSA-secp192k1-SHA256`.
    EcdsaSecp192k1Sha256,
    /// `ECDSA-secp256k1-SHA256`.
    EcdsaSecp256k1Sha256,
    /// `ECDSA-secp192r1-SHA256`.
    EcdsaSecp192r1Sha256,
    /// `ECDSA-secp256r1-SHA256` — the default since OCMF 0.4.
    EcdsaSecp256r1Sha256,
    /// `ECDSA-brainpool256r1-SHA256`.
    EcdsaBrainpool256r1Sha256,
    /// `ECDSA-secp384r1-SHA256`.
    EcdsaSecp384r1Sha256,
    /// `ECDSA-brainpool384r1-SHA256`.
    EcdsaBrainpool384r1Sha256,
}

impl SignatureAlgorithm {
    /// The identifier as `[OCMF Tab. 22]` spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaSecp192k1Sha256 => "ECDSA-secp192k1-SHA256",
            Self::EcdsaSecp256k1Sha256 => "ECDSA-secp256k1-SHA256",
            Self::EcdsaSecp192r1Sha256 => "ECDSA-secp192r1-SHA256",
            Self::EcdsaSecp256r1Sha256 => "ECDSA-secp256r1-SHA256",
            Self::EcdsaBrainpool256r1Sha256 => "ECDSA-brainpool256r1-SHA256",
            Self::EcdsaSecp384r1Sha256 => "ECDSA-secp384r1-SHA256",
            Self::EcdsaBrainpool384r1Sha256 => "ECDSA-brainpool384r1-SHA256",
        }
    }

    /// The curve this algorithm signs on.
    #[must_use]
    pub const fn curve(self) -> Curve {
        match self {
            Self::EcdsaSecp192k1Sha256 => Curve::Secp192k1,
            Self::EcdsaSecp256k1Sha256 => Curve::Secp256k1,
            Self::EcdsaSecp192r1Sha256 => Curve::Secp192r1,
            Self::EcdsaSecp256r1Sha256 => Curve::Secp256r1,
            Self::EcdsaBrainpool256r1Sha256 => Curve::BrainpoolP256r1,
            Self::EcdsaSecp384r1Sha256 => Curve::Secp384r1,
            Self::EcdsaBrainpool384r1Sha256 => Curve::BrainpoolP384r1,
        }
    }

    /// Parses an `SA` identifier, tolerating the spellings that occur.
    ///
    /// `brainpoolP256r1` (what stations write, and what the OCPP application
    /// note's own table writes for the curve) and `brainpool256r1` (what
    /// `[OCMF Tab. 22]` writes) are the same algorithm; the curve token is
    /// matched case-insensitively. Any spelling other than the table's is
    /// reported as [`DeviationKind::AlgorithmIdentifierSpelling`].
    ///
    /// `None` for an identifier outside the table — which is reported by the
    /// caller and refused at verification time, never by losing the record.
    #[must_use]
    pub fn parse(raw: &str, at: Location, dev: &mut Vec<Deviation>) -> Option<Self> {
        let alg = Self::parse_quiet(raw)?;
        if raw != alg.as_str() {
            dev.push(Deviation::with_value(
                DeviationKind::AlgorithmIdentifierSpelling,
                at,
                raw,
            ));
        }
        Some(alg)
    }

    /// Parses without reporting.
    #[must_use]
    pub fn parse_quiet(raw: &str) -> Option<Self> {
        let mut parts = raw.split('-');
        let (scheme, curve, hash) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        if !scheme.eq_ignore_ascii_case("ECDSA") || !hash.eq_ignore_ascii_case("SHA256") {
            return None;
        }
        // `brainpool256r1` (the table) and `brainpoolP256r1` (what stations
        // write) name the same curve. Fold the optional `P` away rather than
        // listing every spelling twice.
        let lower = curve.to_ascii_lowercase();
        let c: &str = match lower.strip_prefix("brainpoolp") {
            Some(rest) => &alloc::format!("brainpool{rest}"),
            None => &lower,
        };
        Some(match c {
            "secp192k1" => Self::EcdsaSecp192k1Sha256,
            "secp256k1" => Self::EcdsaSecp256k1Sha256,
            "secp192r1" | "prime192v1" => Self::EcdsaSecp192r1Sha256,
            "secp256r1" | "prime256v1" => Self::EcdsaSecp256r1Sha256,
            "brainpool256r1" => Self::EcdsaBrainpool256r1Sha256,
            "secp384r1" | "prime384v1" => Self::EcdsaSecp384r1Sha256,
            "brainpool384r1" => Self::EcdsaBrainpool384r1Sha256,
            _ => return None,
        })
    }
}

impl core::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How `SD` is encoded into the JSON string `[OCMF Tab. 8]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum SignatureEncoding {
    /// `hex` — the default.
    #[default]
    Hex,
    /// `base64`.
    Base64,
}

impl SignatureEncoding {
    /// The value as written in `SE`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Base64 => "base64",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "hex" => Some(Self::Hex),
            "base64" => Some(Self::Base64),
            _ => None,
        }
    }

    fn decode(self, s: &str) -> Option<Vec<u8>> {
        match self {
            Self::Hex => hex_decode(s),
            Self::Base64 => base64_decode(s),
        }
    }
}

/// The parsed signature section.
///
/// Every field here is optional in the type as well as in the table, and that
/// is deliberate: an unreadable `SA`, an `SE` naming an encoding nobody
/// defined, an `SD` that is not hex — none of them is a reason to refuse the
/// *record*. The payload is the evidence a dispute turns on and the signature
/// is one claim about it, so a broken claim costs the claim.
#[derive(Debug, Clone)]
pub struct SignatureSection<'a> {
    algorithm: Option<SignatureAlgorithm>,
    algorithm_text: Option<&'a str>,
    encoding: Option<SignatureEncoding>,
    encoding_text: Option<&'a str>,
    mime: &'a str,
    mime_written: bool,
    data: Option<Vec<u8>>,
    object: Object<'a>,
}

impl<'a> SignatureSection<'a> {
    /// The default algorithm when `SA` is absent `[OCMF Tab. 22]`.
    pub const DEFAULT_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::EcdsaSecp256r1Sha256;
    /// The default encoding when `SE` is absent `[OCMF Tab. 8]`.
    pub const DEFAULT_ENCODING: SignatureEncoding = SignatureEncoding::Hex;
    /// The default MIME type when `SM` is absent `[OCMF Tab. 8]`.
    pub const DEFAULT_MIME: &'static str = "application/x-der";

    /// The algorithm in force — from `SA`, or the default when it is absent.
    ///
    /// `None` when `SA` **was** written and names something outside
    /// `[OCMF Tab. 22]`. That is not the same as "secp256r1 by default": a
    /// record that claims an algorithm nobody defined must not be checked
    /// against a different one, so verification answers
    /// [`VerifyError::UnknownAlgorithm`](crate::VerifyError::UnknownAlgorithm)
    /// and [`Self::algorithm_text`] says what it claimed.
    #[must_use]
    pub const fn algorithm(&self) -> Option<SignatureAlgorithm> {
        self.algorithm
    }

    /// The curve the record claims to be signed on.
    ///
    /// The hint a key that names no curve of its own needs — a bare `X‖Y`
    /// point, or the `oca:` composite from a meter's label. `None` on the same
    /// terms as [`Self::algorithm`].
    #[must_use]
    pub fn curve(&self) -> Option<Curve> {
        self.algorithm.map(SignatureAlgorithm::curve)
    }

    /// `SA` exactly as written, when the record wrote one.
    #[must_use]
    pub const fn algorithm_text(&self) -> Option<&'a str> {
        self.algorithm_text
    }

    /// Whether `SA` was actually present.
    ///
    /// Only 23 of 256 reference-corpus records write it, so
    /// [`Self::algorithm`] is a defaulted answer far more often than not.
    #[must_use]
    pub const fn algorithm_was_written(&self) -> bool {
        self.algorithm_text.is_some()
    }

    /// The encoding in force — from `SE`, or the default when it is absent.
    ///
    /// `None` when `SE` was written and is neither `hex` nor `base64`, in which
    /// case there is no way to read `SD` and [`Self::data`] is `None` too.
    #[must_use]
    pub const fn encoding(&self) -> Option<SignatureEncoding> {
        self.encoding
    }

    /// `SE` exactly as written, when the record wrote one.
    #[must_use]
    pub const fn encoding_text(&self) -> Option<&'a str> {
        self.encoding_text
    }

    /// Whether `SE` was actually present. Exactly one corpus record writes it.
    #[must_use]
    pub const fn encoding_was_written(&self) -> bool {
        self.encoding_text.is_some()
    }

    /// The MIME type in force — from `SM`, or the default.
    #[must_use]
    pub const fn mime_type(&self) -> &'a str {
        self.mime
    }

    /// Whether `SM` was actually present. No corpus record writes it.
    #[must_use]
    pub const fn mime_was_written(&self) -> bool {
        self.mime_written
    }

    /// The decoded signature bytes, exactly as they were carried — DER or raw.
    ///
    /// `None` when `SD` is absent, or did not decode with the encoding `SE`
    /// names. That is not fatal to the record: the payload is intact and is
    /// still the evidence a dispute turns on. It is fatal to *verification*.
    #[must_use]
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// The `SD` text exactly as written, whether or not it decoded.
    #[must_use]
    pub fn data_text(&self) -> Option<&'a str> {
        self.object
            .get("SD")
            .and_then(Value::as_str)
            .map(RawStr::as_raw)
    }

    /// The section's raw JSON, for reproduction and for vendor extensions.
    #[must_use]
    pub const fn object(&self) -> &Object<'a> {
        &self.object
    }

    /// Keys the specification defines for this section.
    pub const KNOWN_KEYS: [&'static str; 4] = ["SA", "SE", "SM", "SD"];

    pub(crate) fn from_object(obj: Object<'a>, dev: &mut Vec<Deviation>) -> Self {
        // Every field is read the same way: take the text however it was
        // written, report anything the table does not define, and carry on.
        let scalar =
            |key: &'static str, dev: &mut Vec<Deviation>| -> Option<(String, &'a str, usize)> {
                match obj.get(key)? {
                    Value::Str(s) => Some((s.decode().into_owned(), s.as_raw(), s.span().start)),
                    Value::Number(n) => {
                        dev.push(Deviation::new(
                            DeviationKind::ScalarFieldNotAString,
                            Location::named(n.span().start, key),
                        ));
                        Some((String::from(n.as_str()), n.as_str(), n.span().start))
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

        let sa = scalar("SA", dev);
        let (algorithm, algorithm_text) = match &sa {
            None => (Some(Self::DEFAULT_ALGORITHM), None),
            Some((decoded, raw, at)) => {
                let alg = SignatureAlgorithm::parse(decoded, Location::named(*at, "SA"), dev);
                if alg.is_none() {
                    dev.push(Deviation::with_value(
                        DeviationKind::UndefinedTableValue,
                        Location::named(*at, "SA"),
                        decoded,
                    ));
                }
                (alg, Some(*raw))
            }
        };

        let se = scalar("SE", dev);
        let (encoding, encoding_text) = match &se {
            None => (Some(Self::DEFAULT_ENCODING), None),
            Some((decoded, raw, at)) => {
                let enc = SignatureEncoding::parse(decoded);
                if enc.is_none() {
                    dev.push(Deviation::with_value(
                        DeviationKind::UndefinedTableValue,
                        Location::named(*at, "SE"),
                        decoded,
                    ));
                }
                (enc, Some(*raw))
            }
        };

        let sm = scalar("SM", dev);
        let (mime, mime_written) = match &sm {
            None => (Self::DEFAULT_MIME, false),
            Some((_, raw, _)) => (*raw, true),
        };

        let data = match scalar("SD", dev) {
            None => {
                if !obj.contains("SD") {
                    dev.push(Deviation::new(
                        DeviationKind::SignatureDataMissing,
                        Location::named(obj.span().start, "SD"),
                    ));
                }
                None
            }
            Some((decoded, _, at)) => {
                let bytes = encoding.and_then(|e| e.decode(&decoded));
                if bytes.is_none() && encoding.is_some() {
                    dev.push(Deviation::new(
                        DeviationKind::SignatureDataUndecodable,
                        Location::named(at, "SD"),
                    ));
                }
                bytes
            }
        };

        // The signature section's reserved initials are U-Z for vendors and
        // A-F for downstream processing components.
        for (k, _) in obj.extras(&Self::KNOWN_KEYS) {
            let name = k.decode();
            let initial = name.as_bytes().first().copied().unwrap_or(b'?');
            if !matches!(initial, b'U'..=b'Z' | b'A'..=b'F') {
                dev.push(Deviation::with_value(
                    DeviationKind::UnknownKey,
                    Location::named(k.span().start, &name),
                    &name,
                ));
            }
        }

        Self {
            algorithm,
            algorithm_text,
            encoding,
            encoding_text,
            mime,
            mime_written,
            data,
            object: obj,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn every_table_22_identifier_parses_to_its_own_curve() {
        for c in Curve::ALL {
            let alg = c.algorithm();
            assert_eq!(SignatureAlgorithm::parse_quiet(alg.as_str()), Some(alg));
            assert_eq!(alg.curve(), c);
        }
    }

    #[test]
    fn the_spelling_stations_actually_use_is_accepted_and_reported() {
        let mut dev = vec![];
        let alg =
            SignatureAlgorithm::parse("ECDSA-brainpoolP256r1-SHA256", Location::at(0), &mut dev)
                .unwrap();
        assert_eq!(alg, SignatureAlgorithm::EcdsaBrainpool256r1Sha256);
        assert_eq!(dev[0].kind, DeviationKind::AlgorithmIdentifierSpelling);

        let mut dev = vec![];
        SignatureAlgorithm::parse("ECDSA-brainpool256r1-SHA256", Location::at(0), &mut dev)
            .unwrap();
        assert!(
            dev.is_empty(),
            "the table's own spelling is not a deviation"
        );
    }

    #[test]
    fn nonsense_algorithms_are_refused_by_name() {
        for s in [
            "",
            "ECDSA",
            "RSA-2048-SHA256",
            "ECDSA-secp256r1-SHA512",
            "ECDSA-p256-SHA256",
        ] {
            assert!(SignatureAlgorithm::parse_quiet(s).is_none(), "{s}");
        }
    }

    #[test]
    fn curve_oids_round_trip() {
        for c in Curve::ALL {
            assert_eq!(Curve::from_oid(c.oid()), Some(c));
        }
        assert_eq!(Curve::Secp256r1.signature_bytes(), 64);
        assert_eq!(Curve::Secp192r1.signature_bytes(), 48);
        assert_eq!(Curve::Secp384r1.signature_bytes(), 96);
    }

    #[test]
    fn every_order_is_the_width_of_its_field_and_plausibly_a_group_order() {
        for c in Curve::ALL {
            let n = c.order();
            assert_eq!(n.len(), c.field_bytes(), "{c}");
            assert_ne!(n[0], 0, "{c}: an order is not written with a leading zero");
            assert_eq!(n[n.len() - 1] & 1, 1, "{c}: every one of these is odd");
        }
    }

    /// The constants above are the one place in this crate where a
    /// transcription error is invisible: a wrong order still *looks* like a
    /// 256-bit number, and every check derived from it agrees with it. So they
    /// are checked against somebody else's copy — `RustCrypto`'s for the four
    /// pure-Rust curves, `OpenSSL`'s for all seven — rather than against this
    /// crate's own arithmetic.
    #[test]
    #[cfg(any(
        feature = "curve-p192",
        feature = "curve-p256",
        feature = "curve-p384",
        feature = "curve-k256"
    ))]
    fn the_orders_agree_with_rustcryptos_own_constants() {
        // `elliptic-curve` 0.13 exposes the order as the curve's `ORDER`
        // constant, a `Uint` whose big-endian bytes are what this crate stores.
        // The trait import is scoped per arm: each curve crate re-exports its
        // own copy of `ArrayEncoding`, and two of them in one scope collide.
        macro_rules! same_order {
            ($krate:ident, $curve_ty:ty, $ours:expr) => {{
                use $krate::elliptic_curve::Curve as _;
                use $krate::elliptic_curve::bigint::ArrayEncoding as _;
                let theirs = <$curve_ty>::ORDER.to_be_byte_array();
                assert_eq!($ours.order(), &theirs[..], "{}", $ours);
            }};
        }
        #[cfg(feature = "curve-p192")]
        same_order!(p192, p192::NistP192, Curve::Secp192r1);
        #[cfg(feature = "curve-p256")]
        same_order!(p256, p256::NistP256, Curve::Secp256r1);
        #[cfg(feature = "curve-p384")]
        same_order!(p384, p384::NistP384, Curve::Secp384r1);
        #[cfg(feature = "curve-k256")]
        same_order!(k256, k256::Secp256k1, Curve::Secp256k1);
    }

    #[test]
    #[cfg(feature = "backend-openssl")]
    fn the_orders_agree_with_openssl_including_brainpool() {
        use openssl::bn::BigNumContext;
        use openssl::ec::EcGroup;
        for c in Curve::ALL {
            let nid = match c {
                Curve::Secp192k1 => openssl::nid::Nid::SECP192K1,
                Curve::Secp192r1 => openssl::nid::Nid::X9_62_PRIME192V1,
                Curve::Secp256k1 => openssl::nid::Nid::SECP256K1,
                Curve::Secp256r1 => openssl::nid::Nid::X9_62_PRIME256V1,
                Curve::Secp384r1 => openssl::nid::Nid::SECP384R1,
                Curve::BrainpoolP256r1 => openssl::nid::Nid::BRAINPOOL_P256R1,
                Curve::BrainpoolP384r1 => openssl::nid::Nid::BRAINPOOL_P384R1,
            };
            let group = EcGroup::from_curve_name(nid).expect("openssl provides the curve");
            let mut order = openssl::bn::BigNum::new().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            group.order(&mut order, &mut ctx).unwrap();
            assert_eq!(
                order
                    .to_vec_padded(i32::try_from(c.field_bytes()).unwrap())
                    .unwrap(),
                c.order(),
                "{c}"
            );
        }
    }
}
