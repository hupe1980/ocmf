//! Big-endian scalar arithmetic, for the three questions ECDSA asks about `s`.
//!
//! Not a bignum library: four operations on fixed-width big-endian byte
//! strings. They exist so that everything ECDSA needs to know about `s` — is it
//! in range, is it the high half of the malleable pair, what is its twin — is
//! *derived* from one constant per curve, [`Curve::order`](crate::Curve),
//! rather than from a second table of half-orders that can disagree with the
//! first. The orders themselves are checked against `RustCrypto`'s and
//! `OpenSSL`'s copies.
//!
//! All functions are total, allocation-light and constant in *shape* rather
//! than in time. They run on public data only — a signature and a group order
//! are both public — so timing is not a concern here; see
//! [`SECURITY.md`](https://github.com/hupe1980/ocmf/blob/main/concepts/SECURITY.md).

use alloc::vec::Vec;

/// Compares two big-endian magnitudes of any lengths.
#[must_use]
pub(crate) fn cmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let a = trim(a);
    let b = trim(b);
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Whether `s` is a usable ECDSA scalar: `1 <= s < order`.
///
/// Both ends matter. `s = 0` is not invertible and `s >= n` is a different
/// scalar than the one that was signed; a verifier that lets either through is
/// accepting a signature nothing produced.
#[must_use]
pub(crate) fn in_range(s: &[u8], order: &[u8]) -> bool {
    !is_zero(s) && cmp(s, order) == core::cmp::Ordering::Less
}

/// Whether `s` is above `order / 2` — the high half of ECDSA's malleable pair.
///
/// Decided as `2·s > order` rather than against a stored half-order, so there
/// is one constant per curve instead of two that can disagree.
#[must_use]
pub(crate) fn is_high(s: &[u8], order: &[u8]) -> bool {
    cmp(&double(s), order) == core::cmp::Ordering::Greater
}

/// `order − s`, the malleable twin of a signature scalar.
///
/// Returns `s` unchanged when it is not below `order`, which cannot happen for
/// a scalar [`in_range`] has accepted.
#[must_use]
pub(crate) fn negate(s: &[u8], order: &[u8]) -> Vec<u8> {
    if cmp(s, order) != core::cmp::Ordering::Less {
        return s.to_vec();
    }
    let width = order.len();
    let mut out = alloc::vec![0u8; width];
    let mut borrow = 0i16;
    for i in (0..width).rev() {
        let sb = i16::from(byte_at(s, width, i));
        let mut d = i16::from(order[i]) - sb - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = u8::try_from(d).unwrap_or(0);
    }
    out
}

/// Left-pads a scalar to `width` bytes, or `None` when it does not fit.
#[must_use]
pub(crate) fn pad_to(s: &[u8], width: usize) -> Option<Vec<u8>> {
    let t = trim(s);
    if t.len() > width {
        return None;
    }
    let mut out = alloc::vec![0u8; width];
    out[width - t.len()..].copy_from_slice(t);
    Some(out)
}

fn trim(v: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < v.len() && v[i] == 0 {
        i += 1;
    }
    &v[i..]
}

fn is_zero(v: &[u8]) -> bool {
    v.iter().all(|b| *b == 0)
}

/// `2·v`, one byte wider when it has to be.
fn double(v: &[u8]) -> Vec<u8> {
    let v = trim(v);
    let mut out = Vec::with_capacity(v.len() + 1);
    out.push(0);
    out.extend_from_slice(v);
    let mut carry = 0u8;
    for b in out.iter_mut().rev() {
        let doubled = (u16::from(*b) << 1) | u16::from(carry);
        carry = u8::try_from(doubled >> 8).unwrap_or(0);
        *b = u8::try_from(doubled & 0xff).unwrap_or(0);
    }
    out
}

/// The byte of `s` that lines up with index `i` of a `width`-byte number.
fn byte_at(s: &[u8], width: usize, i: usize) -> u8 {
    let s = trim(s);
    if s.len() > width {
        return 0;
    }
    let offset = width - s.len();
    if i < offset { 0 } else { s[i - offset] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::Curve;

    #[test]
    fn comparison_ignores_leading_zeros() {
        use core::cmp::Ordering;
        assert_eq!(cmp(&[0, 0, 1], &[1]), Ordering::Equal);
        assert_eq!(cmp(&[2], &[0, 1]), Ordering::Greater);
        assert_eq!(cmp(&[1, 0], &[0xff]), Ordering::Greater);
    }

    #[test]
    fn a_scalar_must_be_in_one_to_n_minus_one() {
        let n = Curve::Secp256r1.order();
        assert!(in_range(&[1], n));
        assert!(!in_range(&[0], n), "zero is not invertible");
        assert!(!in_range(n, n), "n itself is zero mod n");
        let mut above = n.to_vec();
        *above.last_mut().unwrap() = 0xff;
        assert!(!in_range(&above, n), "beyond n is a different scalar");
    }

    #[test]
    fn negating_twice_is_the_identity_on_every_curve() {
        for c in Curve::ALL {
            let n = c.order();
            for probe in [
                alloc::vec![1u8],
                alloc::vec![0x7f; 8],
                n[..n.len() - 1].to_vec(),
            ] {
                if !in_range(&probe, n) {
                    continue;
                }
                let twin = negate(&probe, n);
                assert!(in_range(&twin, n), "{c}");
                assert_eq!(
                    trim(&negate(&twin, n)),
                    trim(&probe),
                    "{c}: n - (n - s) = s"
                );
                assert!(
                    is_high(&probe, n) != is_high(&twin, n),
                    "{c}: exactly one of a malleable pair is high"
                );
            }
        }
    }

    #[test]
    fn the_boundary_of_the_high_half_is_n_over_two() {
        for c in Curve::ALL {
            let n = c.order();
            // ⌊n/2⌋ is the largest low-`s`, and one more is the smallest high one.
            let half = shift_right_one(n);
            assert!(!is_high(&half, n), "{c}: n/2 is not above n/2");
            let mut plus = half.clone();
            increment(&mut plus);
            assert!(is_high(&plus, n), "{c}: n/2 + 1 is");
            assert!(!is_high(&[1], n), "{c}");
        }
    }

    #[test]
    fn padding_refuses_a_scalar_that_does_not_fit() {
        assert_eq!(pad_to(&[1], 4).unwrap(), alloc::vec![0, 0, 0, 1]);
        assert_eq!(pad_to(&[0, 0, 1, 2], 2).unwrap(), alloc::vec![1, 2]);
        assert!(pad_to(&[1, 2, 3], 2).is_none());
    }

    fn shift_right_one(v: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![0u8; v.len()];
        let mut carry = 0u8;
        for (i, b) in v.iter().enumerate() {
            out[i] = (b >> 1) | (carry << 7);
            carry = b & 1;
        }
        out
    }

    fn increment(v: &mut [u8]) {
        for b in v.iter_mut().rev() {
            let (next, carry) = b.overflowing_add(1);
            *b = next;
            if !carry {
                return;
            }
        }
    }
}
