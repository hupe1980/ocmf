//! Hex and Base64, tolerant in exactly the ways OCMF data requires.
//!
//! Both are implemented here rather than pulled in, because both have to be
//! lenient in ways a general-purpose crate is right to refuse:
//!
//! - **Whitespace inside hex.** The reference verifier strips it
//!   (`Utils.clearString`), and real transparency XML files carry public keys
//!   as `3059 3013 0607 2A86 …`. A hex decoder that rejects the space rejects
//!   the key.
//! - **Case.** `[OCA Signed Meter Values §3.2.2]` requires base16 to be
//!   case-insensitive, and to *ignore* a `0x` prefix and any non-hexadecimal
//!   character in the printed key.
//! - **Base64 padding.** Present, absent, and URL-safe alphabets all appear in
//!   OCPP payloads.
//!
//! # Example
//!
//! ```
//! use ocmf::encoding::{base64_decode, hex_decode, hex_decode_lossy};
//!
//! // Real transparency files write keys in groups of two bytes.
//! assert_eq!(hex_decode("3059 3013").unwrap(), [0x30, 0x59, 0x30, 0x13]);
//! assert!(hex_decode("de:ad").is_none(), "a colon is not whitespace");
//!
//! // …but `[OCA SMV §3.2.2]` says to ignore it, in that one place only.
//! assert_eq!(hex_decode_lossy("de:ad").unwrap(), [0xde, 0xad]);
//!
//! assert_eq!(base64_decode("QUJD").unwrap(), b"ABC");
//! ```

use alloc::vec::Vec;

/// Decodes hexadecimal, ignoring ASCII whitespace and an optional `0x` prefix.
///
/// # Errors
///
/// Returns `None` when a non-whitespace, non-hex character appears or the digit
/// count is odd.
#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi: Option<u8> = None;
    for c in s.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = hex_val(c)?;
        match hi {
            None => hi = Some(v),
            Some(h) => {
                out.push((h << 4) | v);
                hi = None;
            }
        }
    }
    if hi.is_some() { None } else { Some(out) }
}

/// Decodes hexadecimal, *skipping* every character that is not a hex digit.
///
/// This is the rule `[OCA §3.2.2 Tab. 2]` states for the `base16` form of a
/// public key printed on a meter: "Non-hexadecimal character strings … and a
/// hexadecimal prefix (0x) SHALL be ignored". It is deliberately a separate
/// function from [`hex_decode`], because silently dropping unexpected input is
/// right in exactly one place and wrong everywhere else.
#[must_use]
pub fn hex_decode_lossy(s: &str) -> Option<Vec<u8>> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi: Option<u8> = None;
    for c in s.bytes() {
        let Some(v) = hex_val(c) else { continue };
        match hi {
            None => hi = Some(v),
            Some(h) => {
                out.push((h << 4) | v);
                hi = None;
            }
        }
    }
    if hi.is_some() { None } else { Some(out) }
}

const fn hex_val(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => return None,
    })
}

/// Encodes as lower-case hexadecimal.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> alloc::string::String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

/// Encodes as upper-case hexadecimal, which is how `SD` is conventionally
/// written.
#[must_use]
pub fn hex_encode_upper(bytes: &[u8]) -> alloc::string::String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

/// Decodes Base64, accepting both alphabets, optional padding, and embedded
/// ASCII whitespace.
///
/// # Errors
///
/// Returns `None` on an out-of-alphabet character or an impossible length.
#[must_use]
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c.is_ascii_whitespace() || c == b'=' {
            continue;
        }
        let v = b64_val(c)?;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    // Leftover bits must be zero padding, never data.
    if bits >= 6 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

const fn b64_val(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => return None,
    })
}

/// Encodes as standard, padded Base64.
#[must_use]
pub fn base64_encode(bytes: &[u8]) -> alloc::string::String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = alloc::string::String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        s.push(A[((n >> 18) & 63) as usize] as char);
        s.push(A[((n >> 12) & 63) as usize] as char);
        s.push(if chunk.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        s.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn hex_tolerates_the_spacing_real_transparency_files_use() {
        assert_eq!(
            hex_decode("3059 3013 0607").unwrap(),
            vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07]
        );
        assert_eq!(hex_decode("0xAbCd").unwrap(), vec![0xab, 0xcd]);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn the_oca_base16_rule_skips_what_it_cannot_read() {
        // "Non-hexadecimal character strings ... SHALL be ignored".
        assert_eq!(
            hex_decode_lossy("de:ad be-ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(hex_decode("de:ad").is_none(), "the strict decoder must not");
    }

    #[test]
    fn base64_round_trips_and_accepts_both_alphabets() {
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&data)).unwrap(), data);
        assert_eq!(base64_decode("-_8=").unwrap(), vec![0xfb, 0xff]);
        assert_eq!(base64_decode("QUJD").unwrap(), b"ABC");
        assert_eq!(base64_decode("QUJD\n").unwrap(), b"ABC");
        assert_eq!(
            base64_decode("QUJD").unwrap(),
            base64_decode("QUJD=").unwrap()
        );
    }

    #[test]
    fn base64_rejects_non_zero_padding_bits() {
        assert!(base64_decode("QQ").is_some());
        assert!(base64_decode("QR").is_none(), "trailing bits must be zero");
        assert!(base64_decode("!!").is_none());
    }

    #[test]
    fn hex_encoding_matches_the_conventional_upper_case_of_sd() {
        assert_eq!(hex_encode_upper(&[0xde, 0xad]), "DEAD");
        assert_eq!(hex_encode(&[0xde, 0xad]), "dead");
    }
}
