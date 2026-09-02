//! ECDSA verification, across every algorithm `[OCMF Tab. 22]` defines.
//!
//! # What a successful verification proves
//!
//! That the holder of one private key produced *these bytes*. Nothing else.
//! Three things it does **not** prove, each answered elsewhere:
//!
//! - that the key belongs to the charge point the record names — that binding
//!   is out of band by the specification's own design;
//! - that no record was removed from the session — [`crate::session`];
//! - that the values may be billed — that is law, tariffs and a key registry.
//!
//! # SHA-256, on every curve
//!
//! All seven algorithms hash with SHA-256, including the 384-bit curves. That
//! rules out the convenient path through `RustCrypto`'s `Verifier`, whose default
//! digest for secp384r1 is SHA-384: verification here is always *prehashed*
//! with a 32-byte SHA-256 digest, and ECDSA's own `bits2int` handles the width
//! mismatch, exactly as `BouncyCastle` does in the reference verifier.
//!
//! # Backends
//!
//! The default is pure Rust and covers secp192r1, secp256r1, secp384r1 and
//! secp256k1. The remaining three — brainpoolP256r1, brainpoolP384r1 and
//! secp192k1 — have no audited pure-Rust implementation on a stable release,
//! and **all three appear in the reference corpus**, so the `backend-openssl`
//! feature exists to cover them. An algorithm this build cannot check is
//! reported as [`VerifyError::Unsupported`] and never as "does not verify": a
//! missing curve and a bad signature are different facts, and only one of them
//! is the station's fault.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! # #[cfg(feature = "curve-p256")] {
//! use ocmf::{PublicKey, Record, VerifyError};
//!
//! let text = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
//! let record = Record::parse(text)?;
//! let key = PublicKey::from_text("3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE", record.signature().curve())?;
//!
//! let verified = ocmf::verify(&record, &key)?;
//! assert_eq!(verified.payload().readings().len(), 2);
//!
//! // One tenth of a watt-hour, and the signature is gone.
//! let edited = text.replace("0.2596", "0.2597");
//! let tampered = Record::parse(&edited)?;
//! assert_eq!(
//!     ocmf::verify(&tampered, &key).unwrap_err(),
//!     VerifyError::NotVerified,
//! );
//! # }
//! # Ok(()) }
//! ```

use alloc::vec::Vec;

use crate::der;
use crate::deviation::{Deviation, DeviationKind, Location};
use crate::error::VerifyError;
use crate::key::PublicKey;
use crate::record::Record;
use crate::signature::{Curve, SignatureAlgorithm};

/// A checked signature.
///
/// There is no public constructor: the only way to hold one is to have run
/// [`verify`]. That is deliberate — a `-> bool` API invites a caller to check
/// the boolean in one function and act on the record in another, which is how
/// "verified" quietly becomes "parsed".
#[derive(Debug, Clone)]
pub struct Verified<'r, 'a> {
    record: &'r Record<'a>,
    key: PublicKey,
    algorithm: SignatureAlgorithm,
    digest: [u8; 32],
    deviations: Vec<Deviation>,
}

impl<'r, 'a> Verified<'r, 'a> {
    /// The record whose signature was checked.
    #[must_use]
    pub const fn record(&self) -> &'r Record<'a> {
        self.record
    }

    /// The payload, for readings and fields.
    #[must_use]
    pub const fn payload(&self) -> &'r crate::payload::Payload<'a> {
        self.record.payload()
    }

    /// The key the signature was checked against.
    #[must_use]
    pub const fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The algorithm actually used — from `SA`, or its default.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// SHA-256 of the signed bytes: this record's identity.
    #[must_use]
    pub const fn payload_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Deviations found while parsing, plus any found while verifying — a
    /// non-canonical DER encoding, a bare `r‖s`, a high-`s` signature.
    #[must_use]
    pub fn deviations(&self) -> &[Deviation] {
        &self.deviations
    }
}

/// How to treat a signature whose `s` is above `n/2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Malleability {
    /// Accept it, and report [`DeviationKind::HighSSignature`].
    ///
    /// The default, because the reference verifier accepts it and
    /// interoperability wins. The malleability is handled where it actually
    /// matters — record identity is the payload digest, not the record text.
    #[default]
    Accept,
    /// Refuse it.
    RejectHighS,
}

/// Options for verification.
///
/// `#[non_exhaustive]` so that a new option is not a breaking change — which
/// also means a downstream crate cannot write `VerifyOptions { … }`. Start from
/// [`VerifyOptions::new`] and set what you need.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct VerifyOptions {
    /// What to do with a high-`s` signature.
    pub malleability: Malleability,
}

impl VerifyOptions {
    /// The defaults: accept a high-`s` signature, as the reference verifier
    /// does.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            malleability: Malleability::Accept,
        }
    }

    /// Sets what to do with a high-`s` signature.
    #[must_use]
    pub const fn malleability(mut self, m: Malleability) -> Self {
        self.malleability = m;
        self
    }
}

/// Checks a record's signature against a key.
///
/// # Errors
///
/// [`VerifyError::NotVerified`] only when the signature is well-formed and does
/// not match. Everything else — an unsupported curve, a key on the wrong curve,
/// undecodable signature bytes — is its own variant, because an operator needs
/// to know which one they have hit.
pub fn verify<'r, 'a>(
    record: &'r Record<'a>,
    key: &PublicKey,
) -> Result<Verified<'r, 'a>, VerifyError> {
    verify_with(record, key, VerifyOptions::default())
}

/// Checks a record's signature with explicit options.
///
/// # Errors
///
/// As [`verify`].
pub fn verify_with<'r, 'a>(
    record: &'r Record<'a>,
    key: &PublicKey,
    options: VerifyOptions,
) -> Result<Verified<'r, 'a>, VerifyError> {
    // An `SA` the table does not define is refused *by name*. Defaulting to
    // secp256r1 here would check a record against an algorithm it never
    // claimed, and answer "verified" about a statement nobody made.
    let algorithm =
        record
            .signature()
            .algorithm()
            .ok_or_else(|| VerifyError::UnknownAlgorithm {
                algorithm: crate::quote_bounded(
                    record.signature().algorithm_text().unwrap_or_default(),
                ),
            })?;
    let curve = algorithm.curve();

    // The key names its own curve when it arrived as a SubjectPublicKeyInfo.
    // A disagreement is either a misconfigured registry or an attack; it is
    // never resolved by preferring one over the other.
    if key.curve() != curve {
        return Err(VerifyError::AlgorithmKeyMismatch {
            key_curve: key.curve().name(),
            algorithm: algorithm.as_str(),
        });
    }

    let mut deviations = record.deviations().to_vec();
    let sig_bytes = record
        .signature()
        .data()
        .ok_or_else(|| VerifyError::SignatureEncoding {
            encoding: record.signature().encoding().map_or_else(
                || crate::quote_bounded(record.signature().encoding_text().unwrap_or_default()),
                |e| alloc::string::String::from(e.as_str()),
            ),
        })?;
    let (r, s) = split_signature(sig_bytes, curve, &mut deviations)?;

    let digest = sha256(record.signed_bytes());

    if is_high_s(curve, &s) {
        if options.malleability == Malleability::RejectHighS {
            return Err(VerifyError::HighSSignature {
                curve: curve.name(),
            });
        }
        deviations.push(Deviation::new(
            DeviationKind::HighSSignature,
            Location::at(0),
        ));
    }

    let ok = backend_verify(curve, key.sec1_bytes(), &digest, &r, &s)?;
    if !ok {
        return Err(VerifyError::NotVerified);
    }
    Ok(Verified {
        record,
        key: key.clone(),
        algorithm,
        digest,
        deviations,
    })
}

/// Checks a record against key material in whatever shape the key arrived in,
/// using the record's own algorithm to resolve a point that names no curve.
///
/// This is what makes the Isabellenhütte records checkable: their key is 64
/// bare bytes with no SEC1 prefix and no `SubjectPublicKeyInfo`, and the only
/// thing that says which curve it lives on is the record's `SA`.
///
/// # Errors
///
/// [`VerifyError::Key`] when the bytes are not a key this crate can read, and
/// the other variants for everything after that.
pub fn verify_bytes<'r, 'a>(
    record: &'r Record<'a>,
    key_bytes: &[u8],
) -> Result<Verified<'r, 'a>, VerifyError> {
    let hint = record
        .signature()
        .algorithm()
        .map(SignatureAlgorithm::curve);
    let key = PublicKey::from_bytes(key_bytes, hint)?;
    verify(record, &key)
}

/// As [`verify_bytes`], for a key that arrived as text — hex, Base64, or the
/// OCA composite form an OCPP `publicKey` field carries.
///
/// # Errors
///
/// As [`verify_bytes`].
pub fn verify_key_text<'r, 'a>(
    record: &'r Record<'a>,
    key_text: &str,
) -> Result<Verified<'r, 'a>, VerifyError> {
    let hint = record
        .signature()
        .algorithm()
        .map(SignatureAlgorithm::curve);
    let key = PublicKey::from_text(key_text, hint)?;
    verify(record, &key)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Splits `SD` into `r` and `s`, from DER or from a bare `r‖s`.
fn split_signature(
    bytes: &[u8],
    curve: Curve,
    dev: &mut Vec<Deviation>,
) -> Result<(Vec<u8>, Vec<u8>), VerifyError> {
    if let Some(sig) = der::read_ecdsa_signature(bytes) {
        if !sig.canonical {
            dev.push(Deviation::new(
                DeviationKind::NonCanonicalDer,
                Location::at(0),
            ));
        }
        return Ok((sig.r, sig.s));
    }
    let f = curve.field_bytes();
    if bytes.len() == 2 * f {
        dev.push(Deviation::new(
            DeviationKind::RawSignatureNotDer,
            Location::at(0),
        ));
        return Ok((bytes[..f].to_vec(), bytes[f..].to_vec()));
    }
    Err(VerifyError::SignatureShape {
        len: bytes.len(),
        expected: 2 * f,
    })
}

/// Left-pads a scalar to the curve's field width, refusing one that is not a
/// usable ECDSA scalar.
///
/// `[1, n)` is the whole of the condition: `s = 0` is not invertible, and
/// `s >= n` names a different scalar than the one that was signed.
fn pad(scalar: &[u8], curve: Curve) -> Result<Vec<u8>, VerifyError> {
    if !crate::scalar::in_range(scalar, curve.order()) {
        return Err(VerifyError::SignatureScalars);
    }
    crate::scalar::pad_to(scalar, curve.field_bytes()).ok_or(VerifyError::SignatureScalars)
}

/// Whether `s` is the high half of ECDSA's malleable pair, derived from the
/// curve's own order rather than from a second stored constant.
fn is_high_s(curve: Curve, s: &[u8]) -> bool {
    crate::scalar::is_high(s, curve.order())
}

/// Dispatches to whichever backend can check this curve.
fn backend_verify(
    curve: Curve,
    key: &[u8],
    digest: &[u8; 32],
    r: &[u8],
    s: &[u8],
) -> Result<bool, VerifyError> {
    if let Some(result) = pure::verify(curve, key, digest, r, s) {
        return result;
    }
    #[cfg(feature = "backend-openssl")]
    {
        openssl_backend::verify(curve, key, digest, r, s)
    }
    #[cfg(not(feature = "backend-openssl"))]
    Err(VerifyError::Unsupported {
        algorithm: curve.algorithm().as_str(),
        reason: unsupported_reason(curve),
    })
}

#[cfg(not(feature = "backend-openssl"))]
const fn unsupported_reason(curve: Curve) -> &'static str {
    match curve {
        Curve::BrainpoolP256r1 | Curve::BrainpoolP384r1 => {
            "no pure-Rust brainpool arithmetic on a stable release; enable `backend-openssl`"
        }
        Curve::Secp192k1 => {
            "no pure-Rust secp192k1 implementation is published; enable `backend-openssl`"
        }
        _ => "the curve's feature is not enabled in this build",
    }
}

/// Whether this build can check signatures on `curve`.
///
/// Answered from the enabled features, not by running a throwaway
/// verification: "can this build check brainpool?" is a question about the
/// build, and a function that answers it with elliptic-curve arithmetic over a
/// made-up key is a function that can start reporting the wrong thing when the
/// made-up key stops being rejected for the reason it was assumed to be.
#[must_use]
pub const fn is_supported(curve: Curve) -> bool {
    if cfg!(feature = "backend-openssl") {
        // OpenSSL provides all seven; a build of it that has dropped a curve
        // is caught at verification time with its own `Unsupported` reason.
        return true;
    }
    match curve {
        Curve::Secp192r1 => cfg!(feature = "curve-p192"),
        Curve::Secp256r1 => cfg!(feature = "curve-p256"),
        Curve::Secp384r1 => cfg!(feature = "curve-p384"),
        Curve::Secp256k1 => cfg!(feature = "curve-k256"),
        Curve::Secp192k1 | Curve::BrainpoolP256r1 | Curve::BrainpoolP384r1 => false,
    }
}

/// Which curves this build can check, in `[OCMF Tab. 23]` order.
#[must_use]
pub fn supported_curves() -> Vec<Curve> {
    Curve::ALL
        .into_iter()
        .filter(|c| is_supported(*c))
        .collect()
}

/// The pure-Rust backend: `RustCrypto`, four of the seven curves.
mod pure {
    use super::{Curve, VerifyError, pad};

    macro_rules! curve_arm {
        ($krate:ident, $curve:expr, $key:expr, $digest:expr, $r:expr, $s:expr) => {{
            use $krate::ecdsa::signature::hazmat::PrehashVerifier;
            use $krate::ecdsa::{Signature, VerifyingKey};

            let (Ok(r), Ok(s)) = (pad($r, $curve), pad($s, $curve)) else {
                return Some(Err(VerifyError::SignatureScalars));
            };
            let Ok(sig) = Signature::from_slice(&[r, s].concat()) else {
                return Some(Err(VerifyError::SignatureScalars));
            };
            // `(r, s)` and `(r, n − s)` are both valid signatures of the same
            // message — that is ECDSA's malleability, and OCMF says nothing
            // about it. Some RustCrypto curves (k256 above all, by Bitcoin
            // convention) will only *verify* the low-`s` form, while
            // BouncyCastle — and so the legally recognised verifier — accepts
            // either. Two secp256k1 records in the reference corpus are high-`s`
            // and authentic. Normalising here is not laxity: it is the same
            // statement, spelled the other way.
            let sig = sig.normalize_s().unwrap_or(sig);
            // An invalid point is a broken key, not a failed signature. The
            // crate makes that distinction everywhere else; the one place it
            // can actually be *decided* is here, where the field arithmetic is.
            let Ok(vk) = VerifyingKey::from_sec1_bytes($key) else {
                return Some(Err(VerifyError::KeyNotOnCurve {
                    curve: $curve.name(),
                }));
            };
            Some(Ok(vk.verify_prehash($digest, &sig).is_ok()))
        }};
    }

    /// `None` when this build has no implementation for the curve.
    pub(super) fn verify(
        curve: Curve,
        key: &[u8],
        digest: &[u8; 32],
        r: &[u8],
        s: &[u8],
    ) -> Option<Result<bool, VerifyError>> {
        match curve {
            #[cfg(feature = "curve-p192")]
            Curve::Secp192r1 => curve_arm!(p192, Curve::Secp192r1, key, digest, r, s),
            #[cfg(feature = "curve-p256")]
            Curve::Secp256r1 => curve_arm!(p256, Curve::Secp256r1, key, digest, r, s),
            #[cfg(feature = "curve-p384")]
            Curve::Secp384r1 => curve_arm!(p384, Curve::Secp384r1, key, digest, r, s),
            #[cfg(feature = "curve-k256")]
            Curve::Secp256k1 => curve_arm!(k256, Curve::Secp256k1, key, digest, r, s),
            _ => None,
        }
    }
}

#[cfg(feature = "backend-openssl")]
mod openssl_backend {
    use super::{Curve, VerifyError};
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;

    const fn nid(curve: Curve) -> Nid {
        match curve {
            Curve::Secp192k1 => Nid::SECP192K1,
            Curve::Secp192r1 => Nid::X9_62_PRIME192V1,
            Curve::Secp256k1 => Nid::SECP256K1,
            Curve::Secp256r1 => Nid::X9_62_PRIME256V1,
            Curve::Secp384r1 => Nid::SECP384R1,
            Curve::BrainpoolP256r1 => Nid::BRAINPOOL_P256R1,
            Curve::BrainpoolP384r1 => Nid::BRAINPOOL_P384R1,
        }
    }

    pub(super) fn verify(
        curve: Curve,
        key: &[u8],
        digest: &[u8; 32],
        r: &[u8],
        s: &[u8],
    ) -> Result<bool, VerifyError> {
        let fail = || VerifyError::NotVerified;
        let group = EcGroup::from_curve_name(nid(curve)).map_err(|_| VerifyError::Unsupported {
            algorithm: curve.algorithm().as_str(),
            reason: "this OpenSSL build does not provide the curve",
        })?;
        let off_curve = || VerifyError::KeyNotOnCurve {
            curve: curve.name(),
        };
        let mut ctx = openssl::bn::BigNumContext::new().map_err(|_| fail())?;
        let point = EcPoint::from_bytes(&group, key, &mut ctx).map_err(|_| off_curve())?;
        let ec = EcKey::from_public_key(&group, &point).map_err(|_| off_curve())?;
        // `EC_KEY_check_key` is what turns "parsed as a point" into "is on the
        // curve and in the right subgroup".
        ec.check_key().map_err(|_| off_curve())?;
        // The same `[1, n)` check the pure backend applies, so a scalar out
        // of range is refused identically whichever backend answers.
        if !crate::scalar::in_range(r, curve.order()) || !crate::scalar::in_range(s, curve.order())
        {
            return Err(VerifyError::SignatureScalars);
        }
        let r = BigNum::from_slice(r).map_err(|_| VerifyError::SignatureScalars)?;
        let s = BigNum::from_slice(s).map_err(|_| VerifyError::SignatureScalars)?;
        let sig =
            EcdsaSig::from_private_components(r, s).map_err(|_| VerifyError::SignatureScalars)?;
        Ok(sig.verify(digest, &ec).unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_decode;
    use crate::record::Record;

    /// The KEBA KCP30 record and key, verbatim from the reference corpus.
    const KEBA: &str = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
    const KEBA_KEY: &str = "3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE";

    #[test]
    #[cfg(feature = "curve-p256")]
    fn key_bytes_are_resolved_against_the_records_own_algorithm() {
        // The Isabellenhütte shape in miniature: a key that names no curve.
        let r = Record::parse(KEBA).unwrap();
        let full = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let point = &full.sec1_bytes()[1..];
        assert_eq!(point.len(), 64, "bare X||Y, no SEC1 prefix");
        verify_bytes(&r, point).expect("the record says which curve this is");
        assert!(matches!(
            verify_bytes(&r, b"not a key"),
            Err(VerifyError::Key(_))
        ));
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn a_real_record_verifies() {
        let r = Record::parse(KEBA).unwrap();
        let k = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let v = verify(&r, &k).expect("this record is authentic");
        assert_eq!(v.algorithm(), SignatureAlgorithm::EcdsaSecp256r1Sha256);
        assert_eq!(v.payload_digest(), r.payload_digest());
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn one_flipped_byte_anywhere_in_the_payload_breaks_it() {
        let k = PublicKey::from_text(KEBA_KEY, None).unwrap();
        // `0.2596` -> `0.2597`: a tenth of a watt-hour, and the signature dies.
        let tampered = KEBA.replacen("0.2596", "0.2597", 1);
        let r = Record::parse(&tampered).unwrap();
        assert_eq!(verify(&r, &k).unwrap_err(), VerifyError::NotVerified);
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn re_serialising_the_payload_would_break_it_too() {
        // Exactly what a deserialise/re-serialise implementation does: the
        // same JSON, one space added. The signature is over bytes.
        let k = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let spaced = KEBA.replacen(r#"{"FV""#, r#"{ "FV""#, 1);
        let r = Record::parse(&spaced).unwrap();
        assert_eq!(verify(&r, &k).unwrap_err(), VerifyError::NotVerified);
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn a_key_on_another_curve_is_a_mismatch_not_a_failure() {
        let r = Record::parse(KEBA).unwrap();
        let k = PublicKey::from_sec1(Curve::Secp384r1, &[4u8; 97]).unwrap();
        assert!(matches!(
            verify(&r, &k),
            Err(VerifyError::AlgorithmKeyMismatch { .. })
        ));
    }

    #[test]
    fn an_unavailable_curve_is_reported_as_unsupported() {
        // brainpool without the OpenSSL backend: named, not guessed at.
        let out = backend_verify(Curve::BrainpoolP256r1, &[4u8; 65], &[0u8; 32], &[1], &[1]);
        #[cfg(feature = "backend-openssl")]
        assert!(matches!(out, Err(VerifyError::KeyNotOnCurve { .. })));
        #[cfg(not(feature = "backend-openssl"))]
        assert!(matches!(out, Err(VerifyError::Unsupported { .. })));
    }

    #[test]
    fn what_this_build_supports_is_a_property_of_the_build() {
        let listed = supported_curves();
        for c in Curve::ALL {
            assert_eq!(listed.contains(&c), is_supported(c), "{c}");
        }
        #[cfg(feature = "backend-openssl")]
        assert_eq!(listed.len(), 7, "OpenSSL covers every algorithm");
        #[cfg(all(not(feature = "backend-openssl"), feature = "curves-pure"))]
        assert_eq!(
            listed.len(),
            4,
            "four curves have a pure-Rust implementation"
        );
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn a_key_that_is_not_a_point_is_not_a_failed_signature() {
        // The right length for secp256r1, and not on it. A registry that hands
        // out this key has a transcription bug; the station's record may be
        // perfectly good, and the error has to say which is which.
        let r = Record::parse(KEBA).unwrap();
        let bogus = PublicKey::from_sec1(Curve::Secp256r1, &[4u8; 65]).unwrap();
        assert_eq!(
            verify(&r, &bogus).unwrap_err(),
            VerifyError::KeyNotOnCurve { curve: "secp256r1" }
        );
    }

    #[test]
    fn a_signature_of_the_wrong_shape_says_so() {
        let mut dev = Vec::new();
        let err = split_signature(&[0u8; 7], Curve::Secp256r1, &mut dev).unwrap_err();
        assert_eq!(
            err,
            VerifyError::SignatureShape {
                len: 7,
                expected: 64
            }
        );
    }

    #[test]
    fn a_bare_r_s_is_split_and_reported() {
        let mut dev = Vec::new();
        let raw = [7u8; 64];
        let (r, s) = split_signature(&raw, Curve::Secp256r1, &mut dev).unwrap();
        assert_eq!(r.len(), 32);
        assert_eq!(s.len(), 32);
        assert_eq!(dev[0].kind, DeviationKind::RawSignatureNotDer);
    }

    #[test]
    fn high_s_is_detected_on_every_curve() {
        for c in Curve::ALL {
            // `n - 1` is the largest scalar there is, and it is high on every
            // curve; `1` is the smallest, and it never is. Both are derived
            // from the order rather than from a second constant that could
            // disagree with it — see `Curve::order`.
            let top = crate::scalar::negate(&[1], c.order());
            assert!(is_high_s(c, &top), "{c}: n - 1 is above n/2");
            assert!(!is_high_s(c, &[1]), "{c}: 1 is not");
            assert!(
                is_high_s(c, &crate::scalar::negate(&top, c.order())) != is_high_s(c, &top),
                "{c}: exactly one of a malleable pair is high"
            );
        }
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn a_high_s_signature_is_refused_by_name_when_the_policy_says_so() {
        // The KEBA record's own `s` starts `0x88`, above n/2 — a real high-`s`
        // signature from a real meter. It is authentic either way, so the
        // default accepts it and reports the deviation, and a caller who wants
        // the low form gets an error that says *that*, not `SignatureScalars`:
        // the scalars are perfectly in range.
        let r = Record::parse(KEBA).unwrap();
        let k = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let v = verify(&r, &k).expect("authentic");
        assert!(
            v.deviations()
                .iter()
                .any(|d| d.kind == DeviationKind::HighSSignature)
        );
        assert_eq!(
            verify_with(
                &r,
                &k,
                VerifyOptions::new().malleability(Malleability::RejectHighS)
            )
            .unwrap_err(),
            VerifyError::HighSSignature { curve: "secp256r1" }
        );
    }

    #[test]
    fn a_scalar_outside_one_to_n_minus_one_is_refused() {
        let curve = Curve::Secp256r1;
        assert!(pad(&[0u8; 32], curve).is_err(), "zero is not a scalar");
        assert!(pad(curve.order(), curve).is_err(), "n is zero mod n");
        assert!(pad(&[1], curve).is_ok());
    }

    #[test]
    fn verification_options_are_buildable_from_outside_the_crate() {
        let o = VerifyOptions::new().malleability(Malleability::RejectHighS);
        assert_eq!(o.malleability, Malleability::RejectHighS);
        assert_eq!(VerifyOptions::new().malleability, Malleability::Accept);
        assert_eq!(
            VerifyOptions::default().malleability,
            VerifyOptions::new().malleability
        );
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn the_der_encoding_of_a_signature_does_not_change_the_verdict() {
        // Re-encode the DER with a long-form length: BouncyCastle accepts it,
        // so this must too, and the record must still verify.
        let r = Record::parse(KEBA).unwrap();
        let der = r.signature().data().unwrap().to_vec();
        let mut loose = alloc::vec![0x30, 0x81, der[1]];
        loose.extend_from_slice(&der[2..]);
        let relaxed = KEBA.replace(
            &crate::encoding::hex_encode_upper(&der),
            &crate::encoding::hex_encode_upper(&loose),
        );
        let r2 = Record::parse(&relaxed).unwrap();
        let k = PublicKey::from_text(KEBA_KEY, None).unwrap();
        let v = verify(&r2, &k).expect("still authentic");
        assert!(
            v.deviations()
                .iter()
                .any(|d| d.kind == DeviationKind::NonCanonicalDer)
        );
    }

    #[test]
    fn the_corpus_key_parses_as_the_curve_the_record_names() {
        let key = hex_decode(KEBA_KEY).unwrap();
        let k = PublicKey::from_bytes(&key, None).unwrap();
        assert_eq!(k.curve(), Curve::Secp256r1);
    }
}
