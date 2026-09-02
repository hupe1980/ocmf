//! Bounds on what a piece of input may cost to read.
//!
//! The defaults come from measurement, not from taste. Across the 256 records
//! of the S.A.F.E. Transparenzsoftware corpus the largest payload section is
//! 932 bytes and the largest reading count is 6, so every default here leaves
//! at least an order of magnitude of headroom while still bounding the worst
//! case at something a charge controller can hold.
//!
//! A limit is never a truncation: exceeding one is a named
//! [`ParseError`](crate::ParseError), so a caller always learns that a record
//! was refused rather than silently shortened.
//!
//! # Example
//!
//! ```
//! use ocmf::Limits;
//!
//! // A charge controller with a small stack, reading records it produced itself.
//! let tight = Limits::DEFAULT.payload(2048).readings(16);
//! assert_eq!(tight.payload, 2048);
//! assert_eq!(tight.record, Limits::DEFAULT.record, "the rest is untouched");
//!
//! // A server that has already bounded its input. Nesting is still capped.
//! assert_eq!(Limits::UNLIMITED.payload, usize::MAX);
//! ```

/// Bounds applied while parsing a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Maximum length of the whole record, in bytes. Default 128 KiB.
    pub record: usize,
    /// Maximum length of the payload section, in bytes. Default 64 KiB
    /// (70× the largest payload observed in the field).
    pub payload: usize,
    /// Maximum number of entries in `RD`. Default 4096 (680× observed).
    pub readings: usize,
    /// Maximum JSON nesting depth. Default 8; the format itself needs 3
    /// (payload → `RD` → reading), and 4 with a vendor object inside a reading.
    ///
    /// Capped at [`Limits::HARD_DEPTH`] however this is set — see there.
    pub depth: usize,
    /// Maximum number of members in any single JSON object. Default 256.
    pub object_members: usize,
    /// Maximum number of `<value>` elements in a S.A.F.E. transparency
    /// container `[crate::xml`]. Default 4096.
    ///
    /// A container arrives from outside — a driver's download, an operator's
    /// archive — so it is bounded like everything else that does. The largest
    /// in the reference test data holds 100.
    pub entries: usize,
}

impl Limits {
    /// The nesting depth the reader will not exceed **whatever `depth` says**.
    ///
    /// The JSON reader recurses, so an unbounded `depth` would turn `[[[[…`
    /// into a stack overflow — which in a `forbid(unsafe_code)` crate is the
    /// one failure mode that cannot be returned as a `Result`. Exceeding this
    /// is [`ParseError::LimitExceeded`](crate::ParseError::LimitExceeded) like
    /// any other bound; 512 is roughly 64× more nesting than any OCMF record
    /// can put to use and comfortably within a small thread's stack.
    pub const HARD_DEPTH: usize = 512;

    /// The defaults documented on each field.
    pub const DEFAULT: Self = Self {
        record: 128 * 1024,
        payload: 64 * 1024,
        readings: 4096,
        depth: 8,
        object_members: 256,
        entries: 4096,
    };

    /// No bounds at all — for a server that has already bounded its input and
    /// would rather see a strange record than lose it.
    ///
    /// "No bounds" is about *size*, not about the stack: nesting is still
    /// capped at [`Self::HARD_DEPTH`].
    pub const UNLIMITED: Self = Self {
        record: usize::MAX,
        payload: usize::MAX,
        readings: usize::MAX,
        depth: usize::MAX,
        object_members: usize::MAX,
        entries: usize::MAX,
    };

    // The type is `#[non_exhaustive]` so that a new bound is not a breaking
    // change — which also means a downstream crate cannot write
    // `Limits { payload: …, ..Limits::DEFAULT }`. These are how it adjusts one.

    /// Sets the maximum length of the whole record, in bytes.
    #[must_use]
    pub const fn record(mut self, bytes: usize) -> Self {
        self.record = bytes;
        self
    }

    /// Sets the maximum length of the payload section, in bytes.
    #[must_use]
    pub const fn payload(mut self, bytes: usize) -> Self {
        self.payload = bytes;
        self
    }

    /// Sets the maximum number of entries in `RD`.
    #[must_use]
    pub const fn readings(mut self, count: usize) -> Self {
        self.readings = count;
        self
    }

    /// Sets the maximum JSON nesting depth, capped at [`Self::HARD_DEPTH`].
    #[must_use]
    pub const fn depth(mut self, depth: usize) -> Self {
        self.depth = depth;
        self
    }

    /// Sets the maximum number of members in any single JSON object.
    #[must_use]
    pub const fn object_members(mut self, count: usize) -> Self {
        self.object_members = count;
        self
    }

    /// Sets the maximum number of `<value>` elements in a transparency
    /// container.
    #[must_use]
    pub const fn entries(mut self, count: usize) -> Self {
        self.entries = count;
        self
    }
}

/// The defaults must leave room for the largest record ever measured — a
/// 932-byte payload with 6 readings at depth 3 — and must stay inside the
/// reader's own ceiling. Checked at compile time, because both sides are
/// constants and a runtime test would only prove it after the build.
const _: () = {
    assert!(Limits::DEFAULT.entries >= 100 * 8);
    assert!(Limits::DEFAULT.payload > 932 * 8);
    assert!(Limits::DEFAULT.readings > 6 * 100);
    assert!(Limits::DEFAULT.depth >= 4);
    assert!(Limits::DEFAULT.depth <= Limits::HARD_DEPTH);
    assert!(Limits::DEFAULT.record >= Limits::DEFAULT.payload);
};

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::Limits;

    #[test]
    fn a_caller_can_adjust_one_bound_without_naming_the_rest() {
        // `#[non_exhaustive]` forbids `Limits { payload: …, ..DEFAULT }` from
        // another crate, so the setters are the only way this works at all.
        let l = Limits::DEFAULT.payload(4096).readings(16);
        assert_eq!(l.payload, 4096);
        assert_eq!(l.readings, 16);
        assert_eq!(l.record, Limits::DEFAULT.record, "the rest is untouched");
    }
}
