//! Public keys, in the five shapes they actually arrive in.
//!
//! OCMF deliberately does not carry the public key: it is bound to the charge
//! point out of band `[OCMF §Relation of Serial Numbers, Charge Point and
//! Public Key]`. So a key reaches a verifier from a transparency XML file, an
//! OCPP `SignedMeterValueType`, a `BNetzA` register entry or a label on the
//! station — and each of those spells it differently:
//!
//! | Shape | Where it comes from |
//! |---|---|
//! | DER `SubjectPublicKeyInfo`, hex | 247 of the 254 corpus keys; the curve is in the structure |
//! | DER `SubjectPublicKeyInfo`, Base64 | 3 more of them |
//! | SEC1 uncompressed point `04‖X‖Y` | OCPP deployments, meter labels |
//! | SEC1 compressed point `02\|03‖X` | rarer, but lawful |
//! | **Bare `X‖Y`, no prefix, no wrapper** | 2 Isabellenhütte records in the reference corpus |
//! | `base64("oca:base16:asn1:…")` | `[OCA Signed Meter Values §3.2.2]`, February 2025 |
//!
//! The last two are why this is a parser and not a `Vec<u8>`. A bare `X‖Y` and
//! a compressed point of a larger curve can have the same length, so where the
//! bytes do not name a curve the record's own `SA` is used as the hint —
//! and when the key *does* name one and the record disagrees, that is
//! [`VerifyError::AlgorithmKeyMismatch`](crate::VerifyError::AlgorithmKeyMismatch),
//! never a silent preference.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use ocmf::{Curve, PublicKey};
//!
//! // A DER `SubjectPublicKeyInfo` as hex: 247 of the 254 corpus keys. The
//! // curve comes from the structure, never from the record's `SA`.
//! let key = PublicKey::from_text("3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE", None)?;
//! assert_eq!(key.curve(), Curve::Secp256r1);
//! assert_eq!(key.sec1_bytes().len(), 65);
//!
//! // The same key with no wrapper at all — the Isabellenhütte shape. Here the
//! // record's own algorithm is the only thing that says which curve it is on.
//! let bare = &key.sec1_bytes()[1..];
//! assert_eq!(
//!     PublicKey::from_sec1(Curve::Secp256r1, bare)?.sec1_bytes(),
//!     key.sec1_bytes(),
//! );
//!
//! // And back out again, in the composition an OCPP `publicKey` field carries.
//! // Base64 of `oca:base16:asn1:<hex SPKI>`, which is what an OCPP
//! // `publicKey` field carries — and what nothing else surveyed reads.
//! let composed = ocmf::encoding::base64_decode(&key.to_oca_base64()).unwrap();
//! let composed = core::str::from_utf8(&composed)?;
//! assert!(composed.starts_with("oca:base16:asn1:"));
//! assert_eq!(PublicKey::from_text(&key.to_oca_base64(), None)?, key);
//! # Ok(()) }
//! ```

use alloc::vec::Vec;

use crate::der;
use crate::encoding::{base64_decode, hex_decode, hex_decode_lossy};
use crate::error::KeyError;
use crate::signature::Curve;

/// A public key on a known curve, held as a SEC1 point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    curve: Curve,
    /// SEC1 encoding: `04‖X‖Y`, or `02`/`03`‖X.
    sec1: Vec<u8>,
}

impl PublicKey {
    /// The curve this key lives on.
    #[must_use]
    pub const fn curve(&self) -> Curve {
        self.curve
    }

    /// The SEC1 point, uncompressed unless the source was compressed.
    #[must_use]
    pub fn sec1_bytes(&self) -> &[u8] {
        &self.sec1
    }

    /// Whether the point is stored in compressed form.
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        matches!(self.sec1.first(), Some(0x02 | 0x03))
    }

    /// Re-encodes as a DER `SubjectPublicKeyInfo`.
    ///
    /// Useful for handing a key to the Transparenzsoftware, whose XML container
    /// expects this shape and nothing else — which is exactly why the two
    /// Isabellenhütte records in its own corpus cannot be checked by it.
    #[must_use]
    pub fn to_spki(&self) -> Vec<u8> {
        der::write_spki(self.curve.oid(), &self.sec1)
    }

    /// Builds a key from a SEC1 point on a known curve.
    ///
    /// A bare `X‖Y` with no SEC1 prefix is accepted and normalised by
    /// prepending `0x04`.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidPoint`] when the length does not match the curve.
    pub fn from_sec1(curve: Curve, bytes: &[u8]) -> Result<Self, KeyError> {
        let f = curve.field_bytes();
        let sec1 = match (bytes.first(), bytes.len()) {
            (Some(0x04), n) if n == 1 + 2 * f => bytes.to_vec(),
            (Some(0x02 | 0x03), n) if n == 1 + f => bytes.to_vec(),
            // The Isabellenhütte shape: the point with its prefix chopped off.
            (Some(_), n) if n == 2 * f => {
                let mut v = Vec::with_capacity(1 + n);
                v.push(0x04);
                v.extend_from_slice(bytes);
                v
            }
            _ => {
                return Err(KeyError::InvalidPoint {
                    curve: curve.name(),
                });
            }
        };
        Ok(Self { curve, sec1 })
    }

    /// Reads a DER `SubjectPublicKeyInfo`; the curve comes from the structure.
    ///
    /// # Errors
    ///
    /// [`KeyError::Der`], [`KeyError::NotEcdsa`] or [`KeyError::UnknownCurve`].
    pub fn from_spki(bytes: &[u8]) -> Result<Self, KeyError> {
        let spki = der::read_spki(bytes)?;
        let curve = Curve::from_oid(spki.curve)
            .ok_or_else(|| KeyError::UnknownCurve(der::oid_to_string(spki.curve)))?;
        Self::from_sec1(curve, spki.key)
    }

    /// Reads a key from bytes in any recognised binary shape.
    ///
    /// `hint` is the curve the record claims. It is needed only for a bare
    /// `X‖Y` or a point without a wrapper, where the bytes carry no curve of
    /// their own; a `SubjectPublicKeyInfo` always wins over the hint, and a
    /// disagreement is reported by the verifier rather than resolved here.
    ///
    /// # Errors
    ///
    /// [`KeyError::Unrecognised`] when nothing matches, or the specific error
    /// from whichever shape it most resembled.
    pub fn from_bytes(bytes: &[u8], hint: Option<Curve>) -> Result<Self, KeyError> {
        // `0x30` is the DER SEQUENCE tag *and* a perfectly ordinary first byte
        // of a bare `X‖Y` point — one coordinate in 256 starts with it. So the
        // leading byte selects which shape to *try first*, never which shape
        // the bytes are.
        if bytes.first() == Some(&0x30) {
            match Self::from_spki(bytes) {
                Ok(key) => return Ok(key),
                Err(spki_err) => {
                    let Some(curve) = hint else {
                        return Err(spki_err);
                    };
                    return Self::from_sec1(curve, bytes).map_err(|_| spki_err);
                }
            }
        }
        if let Some(curve) = hint {
            return Self::from_sec1(curve, bytes);
        }
        // Without a hint, only a length that is unambiguous *within* a
        // prefixed SEC1 point can be resolved — and even then only to a set of
        // curves, so this stays an error rather than a guess.
        Err(KeyError::Unrecognised { len: bytes.len() })
    }

    /// Reads a key from text: hex, Base64, or an OCA composite string.
    ///
    /// Whitespace is ignored everywhere, because real transparency files write
    /// keys as `3059 3013 0607 2A86 …`.
    ///
    /// # Errors
    ///
    /// [`KeyError::NotEncoded`] when the text is neither, or the error from the
    /// decoded bytes.
    pub fn from_text(text: &str, hint: Option<Curve>) -> Result<Self, KeyError> {
        let trimmed = text.trim();
        if trimmed.starts_with("oca:") {
            return Self::from_oca(trimmed, hint);
        }
        if let Some(bytes) = hex_decode(trimmed) {
            return Self::from_bytes(&bytes, hint);
        }
        if let Some(bytes) = base64_decode(trimmed) {
            // An OCPP `publicKey` is Base64 of the OCA composite string.
            if let Ok(s) = core::str::from_utf8(&bytes)
                && s.starts_with("oca:")
            {
                return Self::from_oca(s, hint);
            }
            return Self::from_bytes(&bytes, hint);
        }
        Err(KeyError::NotEncoded)
    }

    /// Reads the OCA composite form `oca:<encoding>:<content-type>:<key>`
    /// `[OCA Signed Meter Values §3.2.2]`.
    ///
    /// `<encoding>` is `base16` (case-insensitive, ignoring non-hex characters
    /// and a `0x` prefix) or `base64`; `<content-type>` is `asn1`.
    ///
    /// # Errors
    ///
    /// [`KeyError::OcaComposition`] when the string is malformed or names a
    /// combination the note does not define.
    pub fn from_oca(text: &str, hint: Option<Curve>) -> Result<Self, KeyError> {
        let rest = text
            .strip_prefix("oca:")
            .ok_or(KeyError::OcaComposition("does not start with `oca:`"))?;
        let (encoding, rest) = rest
            .split_once(':')
            .ok_or(KeyError::OcaComposition("missing <encoding>"))?;
        let (content_type, printed) = rest
            .split_once(':')
            .ok_or(KeyError::OcaComposition("missing <content-type>"))?;
        if !content_type.eq_ignore_ascii_case("asn1") {
            return Err(KeyError::OcaComposition(
                "only the `asn1` content-type is defined",
            ));
        }
        let bytes = if encoding.eq_ignore_ascii_case("base16") {
            hex_decode_lossy(printed)
        } else if encoding.eq_ignore_ascii_case("base64") {
            base64_decode(printed)
        } else {
            return Err(KeyError::OcaComposition(
                "only `base16` and `base64` are defined",
            ));
        }
        .ok_or(KeyError::OcaComposition("the printed key does not decode"))?;
        Self::from_bytes(&bytes, hint)
    }

    /// Writes the OCA composite form, Base64-wrapped for an OCPP `publicKey`
    /// field `[OCA Signed Meter Values §3.2.2]`.
    #[must_use]
    pub fn to_oca_base64(&self) -> alloc::string::String {
        let composed = alloc::format!(
            "oca:base16:asn1:{}",
            crate::encoding::hex_encode(&self.to_spki())
        );
        crate::encoding::base64_encode(composed.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_encode;

    const KEBA_SPKI: &str = "3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE";
    /// The Isabellenhütte shape: 64 bytes, no `0x04`, no wrapper.
    const ISA_BARE: &str = "B27CDB498504606CA3ACA2BA05A61F30D443B36CADD6F00C881F3469FBB08B8C2F498C314A035BDADCC83EA731A8B65CACD0A39A32C88AE444431E990F9E84ED";

    #[test]
    fn a_spki_names_its_own_curve() {
        let k = PublicKey::from_text(KEBA_SPKI, None).unwrap();
        assert_eq!(k.curve(), Curve::Secp256r1);
        assert_eq!(k.sec1_bytes().len(), 65);
        assert!(!k.is_compressed());
    }

    #[test]
    fn transparency_files_write_keys_with_spaces_in_them() {
        let spaced = "3059 3013 0607 2A86 48CE 3D02 0106 082A 8648 CE3D 0301 0703 4200 043A EEB4 5C39 2357 820A 58FD FB08 57BD 77AD A315 85C6 1C43 0531 DFA5 3B44 0AFB FDD9 5AC8 87C6 58EA 5526 0F80 8F55 CA94 8DF2 35C2 108A 0D6D C7D4 AB1A 5E1A 7955 BE";
        assert_eq!(
            PublicKey::from_text(spaced, None).unwrap(),
            PublicKey::from_text(KEBA_SPKI, None).unwrap()
        );
    }

    #[test]
    fn a_bare_point_needs_the_records_own_curve_and_then_works() {
        assert!(matches!(
            PublicKey::from_text(ISA_BARE, None),
            Err(KeyError::Unrecognised { len: 64 })
        ));
        let k = PublicKey::from_text(ISA_BARE, Some(Curve::Secp256r1)).unwrap();
        assert_eq!(
            k.sec1_bytes()[0],
            0x04,
            "normalised to an uncompressed point"
        );
        assert_eq!(k.sec1_bytes().len(), 65);
    }

    #[test]
    fn the_oca_appendix_example_parses_to_its_own_key() {
        // [OCA Signed Meter Values §5.3], verbatim.
        let printed = "3056301006072a8648ce3d020106052b8104000a03420004460a02ba2766d9c44f023ecc0e4e58644a87add1aadd6317e5fe4dccdb29b163a01d8a6297c84bc530f86431e92f8d46ab37830247c05cbd92fac252929e7f61";
        let composed = alloc::format!("oca:base16:asn1:{printed}");
        let b64 = crate::encoding::base64_encode(composed.as_bytes());

        let k = PublicKey::from_text(&b64, None).unwrap();
        assert_eq!(k.curve(), Curve::Secp256k1);
        assert_eq!(hex_encode(&k.to_spki()), printed);
        assert_eq!(k.to_oca_base64(), b64);
    }

    #[test]
    fn the_oca_base16_rule_ignores_decoration_in_a_printed_key() {
        let k = PublicKey::from_oca(
            "oca:base16:asn1:0x30:59:30:13:06:07:2A:86:48:CE:3D:02:01:06:08:2A:86:48:CE:3D:03:01:07:03:42:00:04:3A:EE:B4:5C:39:23:57:82:0A:58:FD:FB:08:57:BD:77:AD:A3:15:85:C6:1C:43:05:31:DF:A5:3B:44:0A:FB:FD:D9:5A:C8:87:C6:58:EA:55:26:0F:80:8F:55:CA:94:8D:F2:35:C2:10:8A:0D:6D:C7:D4:AB:1A:5E:1A:79:55:BE",
            None,
        )
        .unwrap();
        assert_eq!(k.curve(), Curve::Secp256r1);
    }

    #[test]
    fn malformed_composites_say_what_is_wrong() {
        assert!(matches!(
            PublicKey::from_oca("oca:base16", None),
            Err(KeyError::OcaComposition("missing <encoding>"))
        ));
        assert!(matches!(
            PublicKey::from_oca("oca:base16:x509:00", None),
            Err(KeyError::OcaComposition(_))
        ));
        assert!(matches!(
            PublicKey::from_oca("oca:base99:asn1:00", None),
            Err(KeyError::OcaComposition(_))
        ));
    }

    #[test]
    fn a_bare_point_whose_first_byte_is_the_der_sequence_tag_still_reads() {
        // One `X` coordinate in 256 starts with 0x30. Dispatching on the byte
        // alone would refuse those keys as "malformed DER".
        let mut point = alloc::vec![0x30u8];
        point.extend(core::iter::repeat_n(0x11, 63));
        assert_eq!(point.len(), 64);
        let k = PublicKey::from_bytes(&point, Some(Curve::Secp256r1)).unwrap();
        assert_eq!(k.sec1_bytes()[0], 0x04);
        assert_eq!(&k.sec1_bytes()[1..], &point[..]);

        // With no hint there is nothing to fall back to, and the DER error is
        // the honest one to report.
        assert!(matches!(
            PublicKey::from_bytes(&point, None),
            Err(KeyError::Der(_))
        ));
    }

    #[test]
    fn a_key_of_the_wrong_length_for_its_curve_is_refused() {
        assert!(matches!(
            PublicKey::from_sec1(Curve::Secp384r1, &[4u8; 65]),
            Err(KeyError::InvalidPoint { curve: "secp384r1" })
        ));
    }

    #[test]
    fn spki_round_trips_through_every_curve() {
        for c in Curve::ALL {
            let point = {
                let mut v = alloc::vec![0x04u8];
                v.extend(core::iter::repeat_n(0x01, c.field_bytes() * 2));
                v
            };
            let k = PublicKey::from_sec1(c, &point).unwrap();
            let back = PublicKey::from_spki(&k.to_spki()).unwrap();
            assert_eq!(back.curve(), c);
            assert_eq!(back.sec1_bytes(), point);
        }
    }
}
