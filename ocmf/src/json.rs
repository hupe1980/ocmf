//! A borrowed, span-tracking JSON reader.
//!
//! # Why not `serde_json`
//!
//! OCMF signs the payload section *as written*, and the specification names no
//! JSON profile at all: its References section cites a web page rather than
//! RFC 8259. Three consequences follow, and together they rule out a
//! deserialise-into-a-struct reader:
//!
//! 1. **Every value must keep its exact source span.** `2935.600` states three
//!    valid decimal places; `RV` may arrive as a JSON string; whitespace inside
//!    the payload is lawful and load-bearing. Nothing may be normalised.
//! 2. **Duplicate keys must be visible.** `{"RV":1,…,"RV":2}` is well-formed
//!    under json.org, and different parsers resolve it differently — one signed
//!    record, two lawful readings of what was measured. A reader that silently
//!    keeps the last has already made a billing decision.
//! 3. **Unknown keys must survive.** Vendor extensions sit *inside the
//!    signature*, and in the field they appear inside `RD` objects, where the
//!    specification never granted a namespace.
//!
//! So this reader is lenient by construction and opinionated about reporting:
//! it accepts what real stations emit, and records every departure from RFC
//! 8259 as a [`Deviation`] for the caller to judge.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use ocmf::{DeviationKind, Limits};
//! use ocmf::json::{Value, parse};
//!
//! let mut deviations = Vec::new();
//! let src = r#"{"RV":2935.600,"RU":"\u006bWh","RV":1}"#;
//! let value = parse(src, &Limits::DEFAULT, &mut deviations)?;
//! let object = value.as_object().unwrap();
//!
//! // A number keeps its exact spelling: three valid decimal places, stated.
//! // `get` takes the last of a duplicated key, as Gson and `serde_json` do —
//! // and the ambiguity is reported rather than resolved in silence.
//! assert_eq!(object.get("RV").unwrap().as_number().unwrap().as_str(), "1");
//! assert!(deviations.iter().any(|d| d.kind == DeviationKind::DuplicateKey));
//!
//! // An escape is a spelling, not a different value — and both are kept.
//! let unit = object.get("RU").unwrap().as_str().unwrap();
//! assert_eq!(unit.decode(), "kWh");
//! assert_eq!(unit.as_raw(), r"\u006bWh");
//! # Ok(()) }
//! ```

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use crate::deviation::{Deviation, DeviationKind, Location};
use crate::error::ParseError;
use crate::limits::Limits;

/// A half-open byte range into the source text.
pub type Span = core::ops::Range<usize>;

/// A JSON string as it appeared, plus the means to read what it means.
///
/// The two are different values: `"kWh"` and `"kWh"` are the same string
/// and different bytes. Comparison uses [`Self::decode`]; reproduction uses the
/// original span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawStr<'a> {
    /// The contents between the quotes, exactly as written.
    raw: &'a str,
    /// Whether `raw` contains a backslash escape.
    escaped: bool,
    span: Span,
}

impl<'a> RawStr<'a> {
    /// The bytes between the quotes, exactly as written.
    #[must_use]
    pub const fn as_raw(&self) -> &'a str {
        self.raw
    }

    /// The span of the string *including* its quotes.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span.clone()
    }

    /// The decoded value. Borrowed when the source contains no escape.
    ///
    /// Total: an escape RFC 8259 does not define decodes to the character after
    /// the backslash, and an unpaired surrogate — which no Rust `str` can
    /// hold — to U+FFFD. Both are *reported* as
    /// [`DeviationKind::InvalidStringEscape`] while the string is being
    /// scanned, so nothing is silently normalised; [`Self::as_raw`] still has
    /// the bytes.
    #[must_use]
    pub fn decode(&self) -> Cow<'a, str> {
        if !self.escaped {
            return Cow::Borrowed(self.raw);
        }
        let mut out = String::with_capacity(self.raw.len());
        let mut chars = self.raw.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some('b') => out.push('\u{8}'),
                Some('f') => out.push('\u{c}'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('u') => {
                    let hi = take_hex4(&mut chars);
                    let ch = match hi {
                        Some(hi @ 0xD800..=0xDBFF) => {
                            // A surrogate pair: `😀`.
                            let mut peek = chars.clone();
                            let lo = (peek.next() == Some('\\') && peek.next() == Some('u'))
                                .then(|| take_hex4(&mut peek))
                                .flatten();
                            match lo {
                                Some(lo @ 0xDC00..=0xDFFF) => {
                                    chars = peek;
                                    let c = 0x1_0000
                                        + ((u32::from(hi) - 0xD800) << 10)
                                        + (u32::from(lo) - 0xDC00);
                                    char::from_u32(c)
                                }
                                _ => None,
                            }
                        }
                        Some(hi) => char::from_u32(u32::from(hi)),
                        None => None,
                    };
                    // An unpaired surrogate cannot be represented in a Rust
                    // `str`. U+FFFD keeps the decoded view total; the original
                    // bytes are still available through `as_raw`.
                    out.push(ch.unwrap_or('\u{FFFD}'));
                }
                Some(other) => out.push(other),
                None => break,
            }
        }
        Cow::Owned(out)
    }

    /// Whether the decoded value equals `other`, without allocating when the
    /// source has no escapes.
    #[must_use]
    pub fn equals(&self, other: &str) -> bool {
        if self.escaped {
            self.decode() == other
        } else {
            self.raw == other
        }
    }
}

/// The value of the first four characters of `s` read as hexadecimal.
fn hex4(s: &str) -> Option<u16> {
    take_hex4(&mut s.chars())
}

fn take_hex4(chars: &mut core::str::Chars<'_>) -> Option<u16> {
    let mut v: u16 = 0;
    for _ in 0..4 {
        let d = chars.next()?.to_digit(16)?;
        v = v.checked_mul(16)?.checked_add(u16::try_from(d).ok()?)?;
    }
    Some(v)
}

/// A JSON number, kept as text.
///
/// Never converted to a float. [`crate::Number`] turns this into an exact
/// decimal while remembering the original spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawNumber<'a> {
    text: &'a str,
    span: Span,
}

impl<'a> RawNumber<'a> {
    /// The literal as written.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.text
    }

    /// The span of the literal.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span.clone()
    }
}

/// A JSON value, borrowed from the source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    /// `null`.
    Null(Span),
    /// `true` or `false`.
    Bool(bool, Span),
    /// A number, as text.
    Number(RawNumber<'a>),
    /// A string.
    Str(RawStr<'a>),
    /// An array.
    Array(Array<'a>),
    /// An object.
    Object(Object<'a>),
}

impl<'a> Value<'a> {
    /// The span this value occupies in the source.
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::Null(s) | Self::Bool(_, s) => s.clone(),
            Self::Number(n) => n.span(),
            Self::Str(s) => s.span(),
            Self::Array(a) => a.span.clone(),
            Self::Object(o) => o.span.clone(),
        }
    }

    /// The string, if this is one.
    #[must_use]
    pub const fn as_str(&self) -> Option<&RawStr<'a>> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The number, if this is one.
    #[must_use]
    pub const fn as_number(&self) -> Option<&RawNumber<'a>> {
        match self {
            Self::Number(n) => Some(n),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b, _) => Some(*b),
            _ => None,
        }
    }

    /// The array, if this is one.
    #[must_use]
    pub const fn as_array(&self) -> Option<&Array<'a>> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The object, if this is one.
    #[must_use]
    pub const fn as_object(&self) -> Option<&Object<'a>> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    /// A one-word name for the kind, for error messages.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Null(_) => "null",
            Self::Bool(..) => "boolean",
            Self::Number(_) => "number",
            Self::Str(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

/// A JSON array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Array<'a> {
    /// The elements, in order.
    pub items: Vec<Value<'a>>,
    span: Span,
}

impl Array<'_> {
    /// The span from `[` to `]`.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span.clone()
    }
}

/// A JSON object, with member order preserved.
///
/// Order is not cosmetic here: it is what lets a record be reproduced exactly,
/// and it is how a caller can tell which vendor extension came where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object<'a> {
    /// The members, in source order, duplicates included.
    pub members: Vec<(RawStr<'a>, Value<'a>)>,
    span: Span,
}

impl<'a> Object<'a> {
    /// The span from `{` to `}`.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span.clone()
    }

    /// The **last** member with this key, matching what Gson (the reference
    /// verifier) and `serde_json` both do.
    ///
    /// A duplicate key is separately reported as
    /// [`DeviationKind::DuplicateKey`], so choosing a resolution here never
    /// hides the ambiguity.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value<'a>> {
        self.members
            .iter()
            .rev()
            .find(|(k, _)| k.equals(key))
            .map(|(_, v)| v)
    }

    /// Whether a member with this key exists.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.members.iter().any(|(k, _)| k.equals(key))
    }

    /// Members whose key is not in `known`, in source order.
    ///
    /// This is how vendor extension points are surfaced — at every level, not
    /// only the payload's top level, because that is where they actually occur.
    pub fn extras<'s>(
        &'s self,
        known: &'s [&'s str],
    ) -> impl Iterator<Item = &'s (RawStr<'a>, Value<'a>)> + 's {
        self.members
            .iter()
            .filter(move |(k, _)| !known.iter().any(|n| k.equals(n)))
    }
}

/// Parses a whole JSON document, leniently.
///
/// Exposed because a caller who has a [`Payload`](crate::Payload) in hand often
/// wants to look at the JSON underneath it — at a vendor extension, or at the
/// exact text of a value — and because the same reader that will not disturb an
/// OCMF payload will not disturb anything else either.
///
/// # Errors
///
/// [`ParseError::Json`] for malformed input, [`ParseError::LimitExceeded`] for
/// input that exceeds `limits`.
pub fn parse<'a>(
    src: &'a str,
    limits: &Limits,
    dev: &mut Vec<Deviation>,
) -> Result<Value<'a>, ParseError> {
    let v = parse_value(src, 0, limits, dev)?;
    let rest = src[v.span().end..].trim_start();
    if !rest.is_empty() {
        return Err(ParseError::Json {
            offset: src.len() - rest.len(),
            expected: "end of input",
        });
    }
    Ok(v)
}

/// Parses one JSON value starting at `start`, leniently, recording deviations.
///
/// Returns the value; its span's end is the first byte *after* the value, which
/// is what the section scanner uses to find the true end of a payload that may
/// contain a pipe inside a string.
///
/// # Errors
///
/// As [`parse`], and this one permits trailing bytes after the value.
pub fn parse_value<'a>(
    src: &'a str,
    start: usize,
    limits: &Limits,
    dev: &mut Vec<Deviation>,
) -> Result<Value<'a>, ParseError> {
    let mut p = Parser {
        src,
        bytes: src.as_bytes(),
        pos: start,
        limits,
        dev,
        depth: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    Ok(v)
}

struct Parser<'a, 'd> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    limits: &'d Limits,
    dev: &'d mut Vec<Deviation>,
    depth: usize,
}

impl<'a> Parser<'a, '_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn err(&self, expected: &'static str) -> ParseError {
        ParseError::Json {
            offset: self.pos,
            expected,
        }
    }

    fn value(&mut self) -> Result<Value<'a>, ParseError> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Value::Str),
            Some(b't') => self.literal("true").map(|s| Value::Bool(true, s)),
            Some(b'f') => self.literal("false").map(|s| Value::Bool(false, s)),
            Some(b'n') => self.literal("null").map(Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number().map(Value::Number),
            _ => Err(self.err("a JSON value")),
        }
    }

    fn literal(&mut self, word: &'static str) -> Result<Span, ParseError> {
        let start = self.pos;
        if self.src[start..].starts_with(word) {
            self.pos += word.len();
            Ok(start..self.pos)
        } else {
            Err(self.err("a JSON literal"))
        }
    }

    fn string(&mut self) -> Result<RawStr<'a>, ParseError> {
        let start = self.pos;
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.pos += 1;
        let inner_start = self.pos;
        let mut escaped = false;
        loop {
            match self.peek() {
                None => return Err(self.err("a closing quote")),
                Some(b'"') => {
                    let inner = &self.src[inner_start..self.pos];
                    self.pos += 1;
                    return Ok(RawStr {
                        raw: inner,
                        escaped,
                        span: start..self.pos,
                    });
                }
                Some(b'\\') => {
                    escaped = true;
                    self.report_escape();
                    self.pos += 1;
                    // The escaped character may be multi-byte (`\\ü` occurs in
                    // free-text fields). Advancing one *byte* would leave the
                    // cursor inside a UTF-8 sequence and desynchronise the
                    // rest of the scan.
                    let Some(b) = self.peek() else {
                        return Err(self.err("an escape sequence"));
                    };
                    self.pos += utf8_len(b);
                }
                Some(c) if c < 0x20 => {
                    // RFC 8259 forbids a raw control character in a string.
                    // json.org, which is what OCMF actually cites, is silent.
                    self.dev.push(Deviation::new(
                        DeviationKind::ControlCharacterInString,
                        Location::at(self.pos),
                    ));
                    self.pos += 1;
                }
                Some(_) => {
                    // Advance by one UTF-8 character, not one byte.
                    self.pos += utf8_len(self.bytes[self.pos]);
                }
            }
        }
    }

    /// Reports an escape sequence RFC 8259 does not define, or a `\u` that is
    /// not four hexadecimal digits or is an unpaired surrogate.
    ///
    /// json.org — the JSON reference OCMF actually cites — is no clearer here
    /// than RFC 8259 is generous, and implementations disagree: `serde_json`
    /// refuses the record, Gson takes the character after the backslash. This
    /// reader takes the character and says so, because a record two conforming
    /// parsers read differently is the exact shape of a billing dispute.
    fn report_escape(&mut self) {
        let at = self.pos;
        let rest = &self.src[at + 1..];
        let ok = match rest.as_bytes().first() {
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => true,
            Some(b'u') => match hex4(&rest[1..]) {
                // A high surrogate is lawful only when a low one follows it;
                // a lone low surrogate never is, and four characters that are
                // not hexadecimal are not an escape at all.
                Some(0xD800..=0xDBFF) => {
                    rest.get(5..7) == Some("\\u")
                        && matches!(hex4(&rest[7..]), Some(0xDC00..=0xDFFF))
                }
                Some(0xDC00..=0xDFFF) | None => false,
                Some(_) => true,
            },
            _ => false,
        };
        if !ok {
            self.dev.push(Deviation::new(
                DeviationKind::InvalidStringEscape,
                Location::at(at),
            ));
        }
    }

    fn number(&mut self) -> Result<RawNumber<'a>, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let int_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == int_start {
            return Err(self.err("a digit"));
        }
        // RFC 8259 forbids a leading zero; some stations write one anyway.
        let int = &self.src[int_start..self.pos];
        if int.len() > 1 && int.starts_with('0') {
            self.dev.push(Deviation::new(
                DeviationKind::NonCanonicalNumber,
                Location::at(int_start),
            ));
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let frac_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err(self.err("a digit after the decimal point"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err(self.err("a digit in the exponent"));
            }
        }
        Ok(RawNumber {
            text: &self.src[start..self.pos],
            span: start..self.pos,
        })
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        // `Limits::depth` is the caller's budget. `Limits::HARD_DEPTH` is not:
        // the reader recurses, and a caller who asks for `Limits::UNLIMITED`
        // must still not be able to turn `[[[[…` into a stack overflow, which
        // in a `forbid(unsafe_code)` crate is the one failure mode that is not
        // a `Result`.
        let bound = self.limits.depth.min(Limits::HARD_DEPTH);
        if self.depth > bound {
            return Err(ParseError::LimitExceeded {
                limit: "depth",
                allowed: bound,
            });
        }
        Ok(())
    }

    fn array(&mut self) -> Result<Value<'a>, ParseError> {
        let start = self.pos;
        self.enter()?;
        self.pos += 1; // '['
        // One element per ~24 bytes is a good guess for an OCMF `RD` array and
        // costs nothing when it is wrong.
        let mut items = Vec::with_capacity(((self.bytes.len() - self.pos) / 96).min(8));
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Array(Array {
                items,
                span: start..self.pos,
            }));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Value::Array(Array {
                        items,
                        span: start..self.pos,
                    }));
                }
                _ => return Err(self.err("',' or ']'")),
            }
        }
    }

    fn object(&mut self) -> Result<Value<'a>, ParseError> {
        let start = self.pos;
        self.enter()?;
        self.pos += 1; // '{'
        let mut members: Vec<(RawStr<'a>, Value<'a>)> =
            Vec::with_capacity(((self.bytes.len() - self.pos) / 24).min(16));
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Value::Object(Object {
                members,
                span: start..self.pos,
            }));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("a member name"));
            }
            let key = self.string()?;
            if members.len() >= self.limits.object_members {
                return Err(ParseError::LimitExceeded {
                    limit: "object members",
                    allowed: self.limits.object_members,
                });
            }
            let decoded = key.decode();
            if members.iter().any(|(k, _)| k.equals(&decoded)) {
                self.dev.push(Deviation::new(
                    DeviationKind::DuplicateKey,
                    Location::named(key.span.start, &decoded),
                ));
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("':'"));
            }
            self.pos += 1;
            self.skip_ws();
            let v = self.value()?;
            members.push((key, v));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    self.depth -= 1;
                    return Ok(Value::Object(Object {
                        members,
                        span: start..self.pos,
                    }));
                }
                _ => return Err(self.err("',' or '}'")),
            }
        }
    }
}

const fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> (Value<'_>, Vec<Deviation>) {
        let mut dev = Vec::new();
        let v = parse_value(src, 0, &Limits::DEFAULT, &mut dev).expect("parses");
        (v, dev)
    }

    #[test]
    fn value_span_ends_at_the_closing_brace() {
        let src = r#"{"a":1}   trailing"#;
        let (v, _) = parse(src);
        assert_eq!(v.span(), 0..7);
        assert_eq!(&src[v.span()], r#"{"a":1}"#);
    }

    #[test]
    fn a_pipe_inside_a_string_does_not_end_the_value() {
        let src = r#"{"TT":"Tarif|A","x":1}|{"SD":"00"}"#;
        let (v, _) = parse(src);
        assert_eq!(&src[v.span()], r#"{"TT":"Tarif|A","x":1}"#);
    }

    #[test]
    fn numbers_keep_their_text() {
        let (v, _) = parse(r#"{"RV":2935.600}"#);
        let n = v.as_object().unwrap().get("RV").unwrap();
        assert_eq!(n.as_number().unwrap().as_str(), "2935.600");
    }

    #[test]
    fn duplicate_keys_are_reported_and_the_last_wins() {
        let (v, dev) = parse(r#"{"RV":1,"RV":2}"#);
        assert_eq!(dev.len(), 1);
        assert_eq!(dev[0].kind, DeviationKind::DuplicateKey);
        let n = v.as_object().unwrap().get("RV").unwrap();
        assert_eq!(n.as_number().unwrap().as_str(), "2");
    }

    #[test]
    fn escapes_decode_but_the_raw_text_survives() {
        let (v, _) = parse(r#"{"RU":"kWh"}"#);
        let s = v.as_object().unwrap().get("RU").unwrap().as_str().unwrap();
        assert_eq!(s.decode(), "kWh");
        assert_eq!(s.as_raw(), r"kWh");
        assert!(s.equals("kWh"));
    }

    #[test]
    fn surrogate_pairs_decode() {
        let (v, _) = parse(r#"{"GI":"😀"}"#);
        let s = v.as_object().unwrap().get("GI").unwrap().as_str().unwrap();
        assert_eq!(s.decode(), "😀");
    }

    #[test]
    fn leading_zeros_are_accepted_and_reported() {
        let (_, dev) = parse(r#"{"RV":007}"#);
        assert_eq!(dev[0].kind, DeviationKind::NonCanonicalNumber);
    }

    #[test]
    fn an_escaped_multibyte_character_does_not_desynchronise_the_scan() {
        // `\\ü` is one backslash and one two-byte character. Advancing a single
        // byte past the backslash would leave the cursor mid-character.
        let src = r#"{"TT":"a\ü b","RV":1}"#;
        let (v, _) = parse(src);
        let o = v.as_object().unwrap();
        assert_eq!(o.get("TT").unwrap().as_str().unwrap().decode(), "aü b");
        assert_eq!(o.get("RV").unwrap().as_number().unwrap().as_str(), "1");
        assert_eq!(&src[v.span()], src);
    }

    #[test]
    fn unlimited_still_cannot_overflow_the_stack() {
        // `Limits::UNLIMITED` is a caller's decision about *their* input size,
        // never a licence to recurse without a floor.
        let deep = "[".repeat(Limits::HARD_DEPTH + 8);
        let mut dev = Vec::new();
        let err = parse_value(&deep, 0, &Limits::UNLIMITED, &mut dev).unwrap_err();
        assert!(matches!(
            err,
            ParseError::LimitExceeded {
                limit: "depth",
                allowed: Limits::HARD_DEPTH
            }
        ));
    }

    #[test]
    fn depth_is_bounded() {
        let deep = "[".repeat(64);
        let mut dev = Vec::new();
        let err = parse_value(&deep, 0, &Limits::DEFAULT, &mut dev).unwrap_err();
        assert!(matches!(
            err,
            ParseError::LimitExceeded { limit: "depth", .. }
        ));
    }

    #[test]
    fn non_ascii_inside_strings_is_not_split_mid_character() {
        let src = r#"{"TT":"Tarif Süd €"}"#;
        let (v, _) = parse(src);
        let s = v.as_object().unwrap().get("TT").unwrap().as_str().unwrap();
        assert_eq!(s.decode(), "Tarif Süd €");
    }
}
