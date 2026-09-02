//! A deliberately lenient DER reader for the two structures OCMF needs.
//!
//! The legally recognised verifier reads `SD` and public keys through
//! `BouncyCastle`'s `ASN1InputStream`, which accepts things DER forbids:
//! non-minimal length encodings, `INTEGER`s with redundant leading zeros, and
//! trailing bytes after the outermost value. A record that the official tool
//! accepts must not be refused here — so this reader accepts the same set, and
//! **reports** every leniency it used as
//! [`DeviationKind::NonCanonicalDer`](crate::DeviationKind::NonCanonicalDer).
//!
//! Nothing is ever re-encoded. A signature read from a record and written back
//! is the same bytes, canonical or not.
//!
//! # Example
//!
//! ```
//! use ocmf::der;
//! use ocmf::encoding::hex_decode;
//!
//! let sig = hex_decode("3006020180020101").unwrap();
//! // As strict DER `02 01 80` is a *negative* integer: the top bit is set and
//! // there is no `0x00` sign byte. OpenSSL refuses it; BouncyCastle — and so
//! // the legally recognised verifier — reads the magnitude, and so does this.
//! let parsed = der::read_ecdsa_signature(&sig).expect("the reference reads this");
//! assert_eq!(parsed.r, [0x80]);
//! assert!(!parsed.canonical, "and the encoding is reported as it is");
//!
//! // Writing goes the other way: always canonical, never re-encoding a record.
//! assert_eq!(
//!     der::write_ecdsa_signature(&[0x80], &[0x01]),
//!     hex_decode("300702020080020101").unwrap(),
//! );
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::KeyError;

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

/// One tag-length-value, plus whether its encoding was canonical DER.
#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    /// Bytes consumed by tag, length and value together.
    len: usize,
    canonical: bool,
}

fn read_tlv(b: &[u8]) -> Option<Tlv<'_>> {
    let tag = *b.first()?;
    let first_len = *b.get(1)?;
    let (value_len, header) = if first_len < 0x80 {
        (usize::from(first_len), 2)
    } else {
        let n = usize::from(first_len & 0x7f);
        if n == 0 || n > 4 || b.len() < 2 + n {
            return None;
        }
        let mut v = 0usize;
        for &c in &b[2..2 + n] {
            v = (v << 8) | usize::from(c);
        }
        (v, 2 + n)
    };
    let end = header.checked_add(value_len)?;
    if b.len() < end {
        return None;
    }
    // DER requires the shortest possible length encoding.
    let canonical = if first_len < 0x80 {
        true
    } else {
        let n = usize::from(first_len & 0x7f);
        value_len >= 0x80 && minimal_length_octets(value_len) == n
    };
    Some(Tlv {
        tag,
        value: &b[header..end],
        len: end,
        canonical,
    })
}

const fn minimal_length_octets(mut v: usize) -> usize {
    let mut n = 0;
    while v > 0 {
        n += 1;
        v >>= 8;
    }
    n
}

/// An ECDSA signature read out of a `SEQUENCE { INTEGER r, INTEGER s }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerSignature {
    /// `r`, big-endian, with redundant leading zeros removed.
    pub r: Vec<u8>,
    /// `s`, big-endian, with redundant leading zeros removed.
    pub s: Vec<u8>,
    /// Whether the encoding was canonical DER throughout.
    pub canonical: bool,
}

/// Reads an ECDSA signature from DER.
///
/// Returns `None` when the bytes are not a `SEQUENCE` of two `INTEGER`s — which
/// is how a bare `r‖s` signature is told apart from a DER one.
#[must_use]
pub fn read_ecdsa_signature(bytes: &[u8]) -> Option<DerSignature> {
    let seq = read_tlv(bytes)?;
    if seq.tag != TAG_SEQUENCE {
        return None;
    }
    let mut canonical = seq.canonical && seq.len == bytes.len();
    let r = read_tlv(seq.value)?;
    if r.tag != TAG_INTEGER {
        return None;
    }
    let s = read_tlv(&seq.value[r.len..])?;
    if s.tag != TAG_INTEGER {
        return None;
    }
    // Anything after the two integers is not part of a signature.
    if r.len + s.len != seq.value.len() {
        canonical = false;
    }
    let (rv, r_ok) = trim_integer(r.value)?;
    let (sv, s_ok) = trim_integer(s.value)?;
    canonical = canonical && r.canonical && s.canonical && r_ok && s_ok;
    Some(DerSignature {
        r: rv.to_vec(),
        s: sv.to_vec(),
        canonical,
    })
}

/// Strips the sign byte from a DER `INTEGER`, reporting whether it was minimal.
///
/// A DER `INTEGER` is two's-complement, so a scalar whose top bit is set needs
/// a leading `0x00`. Real signers omit it: `test.xml` in the reference corpus
/// carries `02 18 e1 0a …` on secp192r1, which as DER is a *negative* integer
/// and as an ECDSA scalar is obviously not. `BouncyCastle` — and therefore the
/// legally recognised verifier — reads these through `getPositiveValue()`, so
/// this reader takes the unsigned magnitude too, and reports the encoding as
/// non-canonical. Refusing it would mean answering "malformed" where the
/// official tool answers "does not verify", which is a worse kind of wrong.
fn trim_integer(v: &[u8]) -> Option<(&[u8], bool)> {
    let first = *v.first()?;
    let mut i = 0;
    while i + 1 < v.len() && v[i] == 0 {
        i += 1;
    }
    let stripped = i;
    let minimal = if first & 0x80 != 0 {
        false // needed a sign byte and did not have one
    } else {
        match stripped {
            0 => true,
            1 => v[1] & 0x80 != 0,
            _ => false,
        }
    };
    Some((&v[i..], minimal))
}

/// Writes a DER length in the shortest form that can hold it.
///
/// Every scalar and every key this crate writes is small enough for the short
/// form, and every real one for `0x81`. Writing the general encoding anyway is
/// four lines and removes a class of silent corruption: a `u8::try_from(len)`
/// that saturates emits a *different, well-formed* structure, which is the
/// worst way for a serialiser to fail.
fn push_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(u8::try_from(len).expect("len < 0x80"));
        return;
    }
    let octets = minimal_length_octets(len);
    out.push(0x80 | u8::try_from(octets).expect("a usize is at most 8 octets"));
    for i in (0..octets).rev() {
        out.push(u8::try_from((len >> (i * 8)) & 0xff).expect("masked to a byte"));
    }
}

/// Writes one tag-length-value.
fn push_tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    push_length(value.len(), out);
    out.extend_from_slice(value);
}

/// Writes an ECDSA signature as canonical DER, for the signing side.
#[must_use]
pub fn write_ecdsa_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn int(v: &[u8], out: &mut Vec<u8>) {
        let v = {
            let mut i = 0;
            while i + 1 < v.len() && v[i] == 0 {
                i += 1;
            }
            &v[i..]
        };
        out.push(TAG_INTEGER);
        let pad = usize::from(v.first().is_some_and(|b| b & 0x80 != 0));
        push_length(v.len() + pad, out);
        if pad == 1 {
            out.push(0);
        }
        out.extend_from_slice(v);
    }
    let mut body = Vec::with_capacity(r.len() + s.len() + 8);
    int(r, &mut body);
    int(s, &mut body);
    let mut out = Vec::with_capacity(body.len() + 6);
    push_tlv(TAG_SEQUENCE, &body, &mut out);
    out
}

/// The parts of a `SubjectPublicKeyInfo` this crate needs.
#[derive(Debug, Clone)]
pub struct Spki<'a> {
    /// The algorithm OID, which must be `id-ecPublicKey`.
    pub algorithm: &'a [u8],
    /// The named-curve parameter OID.
    pub curve: &'a [u8],
    /// The `BIT STRING` contents: a SEC1 point.
    pub key: &'a [u8],
}

/// `1.2.840.10045.2.1` — `id-ecPublicKey`.
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// Reads a `SubjectPublicKeyInfo`.
///
/// # Errors
///
/// [`KeyError::Der`] when the structure is malformed, [`KeyError::NotEcdsa`]
/// when it is a key of another kind.
pub fn read_spki(bytes: &[u8]) -> Result<Spki<'_>, KeyError> {
    let outer = read_tlv(bytes).ok_or(KeyError::Der("truncated SubjectPublicKeyInfo"))?;
    if outer.tag != TAG_SEQUENCE {
        return Err(KeyError::Der("outer value is not a SEQUENCE"));
    }
    let alg = read_tlv(outer.value).ok_or(KeyError::Der("truncated AlgorithmIdentifier"))?;
    if alg.tag != TAG_SEQUENCE {
        return Err(KeyError::Der("AlgorithmIdentifier is not a SEQUENCE"));
    }
    let alg_oid = read_tlv(alg.value).ok_or(KeyError::Der("missing algorithm OID"))?;
    if alg_oid.tag != TAG_OID {
        return Err(KeyError::Der("algorithm is not an OID"));
    }
    if alg_oid.value != OID_EC_PUBLIC_KEY {
        return Err(KeyError::NotEcdsa);
    }
    let params = read_tlv(&alg.value[alg_oid.len..]).ok_or(KeyError::Der("missing curve OID"))?;
    if params.tag != TAG_OID {
        return Err(KeyError::Der("curve parameter is not a named-curve OID"));
    }
    let bits = read_tlv(&outer.value[alg.len..]).ok_or(KeyError::Der("missing BIT STRING"))?;
    if bits.tag != TAG_BIT_STRING {
        return Err(KeyError::Der("public key is not a BIT STRING"));
    }
    let key = bits
        .value
        .split_first()
        .filter(|(unused, _)| **unused == 0)
        .map(|(_, rest)| rest)
        .ok_or(KeyError::Der("BIT STRING has unused bits"))?;
    Ok(Spki {
        algorithm: alg_oid.value,
        curve: params.value,
        key,
    })
}

/// Writes a `SubjectPublicKeyInfo` around a SEC1 point.
#[must_use]
pub fn write_spki(curve_oid: &[u8], point: &[u8]) -> Vec<u8> {
    let mut alg = Vec::with_capacity(OID_EC_PUBLIC_KEY.len() + curve_oid.len() + 4);
    push_tlv(TAG_OID, OID_EC_PUBLIC_KEY, &mut alg);
    push_tlv(TAG_OID, curve_oid, &mut alg);

    let mut bits = Vec::with_capacity(point.len() + 1);
    bits.push(0); // unused bits
    bits.extend_from_slice(point);

    let mut body = Vec::with_capacity(alg.len() + bits.len() + 8);
    push_tlv(TAG_SEQUENCE, &alg, &mut body);
    push_tlv(TAG_BIT_STRING, &bits, &mut body);

    let mut out = Vec::with_capacity(body.len() + 4);
    push_tlv(TAG_SEQUENCE, &body, &mut out);
    out
}

/// Renders an OID's contents as dotted decimal, for error messages.
#[must_use]
pub fn oid_to_string(oid: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::new();
    let Some((&first, rest)) = oid.split_first() else {
        return s;
    };
    let _ = write!(s, "{}.{}", first / 40, first % 40);
    let mut acc: u64 = 0;
    for &b in rest {
        acc = (acc << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            let _ = write!(s, ".{acc}");
            acc = 0;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_decode;

    /// A real signature from the KEBA KCP30 record in the reference corpus.
    const KEBA_SIG: &str = "304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699";

    #[test]
    fn a_real_signature_reads_as_canonical() {
        let sig = read_ecdsa_signature(&hex_decode(KEBA_SIG).unwrap()).unwrap();
        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
        assert!(sig.canonical);
    }

    #[test]
    fn a_bare_r_s_is_not_mistaken_for_der() {
        // The Isabellenhütte shape: 64 bytes that happen not to start 0x30.
        let raw = [0xC2u8; 64];
        assert!(read_ecdsa_signature(&raw).is_none());
    }

    #[test]
    fn non_minimal_length_is_accepted_and_flagged() {
        // Re-encode the same signature with a long-form length for the SEQUENCE.
        let der = hex_decode(KEBA_SIG).unwrap();
        let mut loose = alloc::vec![0x30, 0x81, der[1]];
        loose.extend_from_slice(&der[2..]);
        let sig = read_ecdsa_signature(&loose).expect("BouncyCastle accepts this, so must we");
        assert!(!sig.canonical);
        assert_eq!(sig.r, read_ecdsa_signature(&der).unwrap().r);
    }

    #[test]
    fn trailing_bytes_are_accepted_and_flagged() {
        let mut der = hex_decode(KEBA_SIG).unwrap();
        let clean = read_ecdsa_signature(&der).unwrap();
        der.push(0x00);
        let loose = read_ecdsa_signature(&der).unwrap();
        assert_eq!(loose.r, clean.r);
        assert!(!loose.canonical);
    }

    #[test]
    fn an_unpadded_high_bit_scalar_is_read_as_positive_and_flagged() {
        // What `test.xml` in the reference corpus contains, in miniature: as
        // strict DER this integer is negative, and BouncyCastle reads it as
        // the magnitude. So do we — and we say the encoding is not canonical.
        let loose = alloc::vec![0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
        let sig = read_ecdsa_signature(&loose).expect("the reference reads this");
        assert_eq!(sig.r, alloc::vec![0x80]);
        assert!(!sig.canonical);
    }

    #[test]
    fn the_writer_encodes_a_long_length_rather_than_truncating_it() {
        // Reachable from the DER fuzz target: `read_ecdsa_signature` will
        // happily return a 200-byte `r`, and a writer that squeezes the length
        // into one byte emits a *different, well-formed* structure that reads
        // back as something else entirely.
        let big = alloc::vec![0x01u8; 200];
        let der = write_ecdsa_signature(&big, &[0x02]);
        let back = read_ecdsa_signature(&der).expect("our own output must read back");
        assert_eq!(back.r, big);
        assert_eq!(back.s, alloc::vec![0x02]);
        assert!(back.canonical);
    }

    #[test]
    fn a_long_public_key_is_wrapped_with_a_long_length() {
        let point = alloc::vec![0x04u8; 400];
        let der = write_spki(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], &point);
        let spki = read_spki(&der).expect("our own output must read back");
        assert_eq!(spki.key, point);
    }

    #[test]
    fn lengths_use_the_shortest_encoding_that_holds_them() {
        let mut out = Vec::new();
        push_length(0x7f, &mut out);
        assert_eq!(out, alloc::vec![0x7f]);
        out.clear();
        push_length(0x80, &mut out);
        assert_eq!(out, alloc::vec![0x81, 0x80]);
        out.clear();
        push_length(0x0100, &mut out);
        assert_eq!(out, alloc::vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn signatures_round_trip_through_the_writer() {
        let der = hex_decode(KEBA_SIG).unwrap();
        let sig = read_ecdsa_signature(&der).unwrap();
        assert_eq!(write_ecdsa_signature(&sig.r, &sig.s), der);
    }

    #[test]
    fn the_keba_public_key_reads_as_secp256r1() {
        let key = hex_decode(
            "3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE",
        )
        .unwrap();
        let spki = read_spki(&key).unwrap();
        assert_eq!(oid_to_string(spki.curve), "1.2.840.10045.3.1.7");
        assert_eq!(spki.key.len(), 65);
        assert_eq!(spki.key[0], 0x04);
    }

    #[test]
    fn spki_round_trips() {
        let point = [4u8; 65];
        let oid = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let der = write_spki(&oid, &point);
        let spki = read_spki(&der).unwrap();
        assert_eq!(spki.curve, oid);
        assert_eq!(spki.key, point);
    }

    #[test]
    fn oids_render_for_error_messages() {
        assert_eq!(oid_to_string(OID_EC_PUBLIC_KEY), "1.2.840.10045.2.1");
        assert_eq!(
            oid_to_string(&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]),
            "1.3.36.3.3.2.8.1.1.7"
        );
    }
}

#[cfg(test)]
mod corpus_regression {
    use super::*;
    use crate::encoding::hex_decode;

    /// A secp192r1 signature from `test.xml` in the reference corpus: 54 bytes,
    /// two 24-byte INTEGERs.
    #[test]
    fn a_192_bit_der_signature_reads() {
        let sig = hex_decode("303402184b322dbd3e5fcf5d4d0d2334052080ea6791c7126839237f021879989dcbf73069c5abebea76bd9268ccff2c56edb8faf409").unwrap();
        assert_eq!(sig.len(), 54);
        let out = read_ecdsa_signature(&sig).expect("this is DER and must read");
        assert_eq!(out.r.len(), 24);
        assert_eq!(out.s.len(), 24);
    }
}
