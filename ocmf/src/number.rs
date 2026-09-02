//! Exact decimals that remember how they were written.
//!
//! `RV` is a physical quantity whose *number of decimal places is part of the
//! statement*: `2935.600` says three valid digits, and `[OCMF Tab. 7]` is
//! explicit that "the representation must not be transformed … since this
//! would change the representation of the physical quantity and thus
//! potentially the number of valid digits".
//!
//! A `f64` cannot hold that — `9.2` becomes `9.199999999999999289…`, which is
//! S.A.F.E. issue #33 — and the reference verifier compares start and stop
//! readings as Java `double`s. Here a number is a [`Decimal`] parsed from the
//! token's own text, carrying that text alongside, so arithmetic is exact and
//! reproduction is byte-identical.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! let text = r#"OCMF|{"FV":"1.0","GI":"KEBA_KCP30","GS":"17619300","GV":"2.8.5","PG":"T32","IS":false,"IL":"NONE","IF":["RFID_NONE","OCPP_NONE","ISO15118_NONE","PLMN_NONE"],"IT":"NONE","ID":"","RD":[{"TM":"2019-08-13T10:03:15,000+0000 I","TX":"B","EF":"","ST":"G","RV":0.2596,"RI":"1-b:1.8.0","RU":"kWh"},{"TM":"2019-08-13T10:03:36,000+0000 R","TX":"E","EF":"","ST":"G","RV":0.2597,"RI":"1-b:1.8.0","RU":"kWh"}]}|{"SD":"304502200E2F107C987A300AC1695CA89EA149A8CDFA16188AF0A33EE64B67964AA943F9022100889A72B6D65364BEA8562E7F6A0253157ACFF84FE4929A93B5964D23C4265699"}"#;
//! let record = ocmf::Record::parse(text)?;
//! let value = record.payload().readings()[0].value().unwrap();
//!
//! // The value for arithmetic, the text for reproduction, and the scale
//! // because "0.2596" states four valid decimal places and 0.259_600 does not.
//! assert_eq!(value.as_str(), "0.2596");
//! assert_eq!(value.scale(), 4);
//! assert_eq!(value.value().to_string(), "0.2596");
//! assert!(!value.was_quoted());
//! # Ok(()) }
//! ```

use rust_decimal::Decimal;

use crate::json::Value;

/// An OCMF number: exact value, original spelling, and how it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number<'a> {
    text: &'a str,
    value: Decimal,
    quoted: bool,
}

impl<'a> Number<'a> {
    /// The exact value.
    #[must_use]
    pub const fn value(&self) -> Decimal {
        self.value
    }

    /// The literal exactly as it appeared, without any quotes.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.text
    }

    /// Whether the source wrote this number as a JSON string.
    ///
    /// True for 23 readings in the reference corpus — Isabellenhütte writes
    /// `"RV":"00000000.000"`. The value is the same; the record is not.
    #[must_use]
    pub const fn was_quoted(&self) -> bool {
        self.quoted
    }

    /// The number of decimal places the source stated.
    #[must_use]
    pub const fn scale(&self) -> u32 {
        self.value.scale()
    }

    /// Reads a numeric field, whichever of the two shapes it arrived in.
    ///
    /// `Err` carries the text that could not be read, so the caller can report
    /// it verbatim. It is never a reason to refuse the record: a number nobody
    /// can hold exactly is not a meter reading, and everything else about the
    /// record — including its signature — is unaffected.
    ///
    /// # Errors
    ///
    /// The offending text, when it is not an exact decimal or is not a scalar
    /// at all.
    pub(crate) fn from_value(v: &Value<'a>) -> Result<Self, &'a str> {
        match v {
            Value::Number(n) => Self::build(n.as_str(), false),
            Value::Str(s) => Self::build(s.as_raw(), true),
            other => Err(other.kind()),
        }
    }

    fn build(text: &'a str, quoted: bool) -> Result<Self, &'a str> {
        // A quoted number is not a JSON number and is not held to its grammar.
        // The corpus contains `"RV":"       9.038"` — padded to a fixed width,
        // as a meter display would be. The value is the number; the text is
        // what was written, and reproduction uses the text.
        let digits = if quoted { text.trim() } else { text };
        // …but "not held to the JSON grammar" is not "held to nothing". An
        // unquoted number already passed the reader's RFC 8259 grammar; a
        // quoted one passed nothing, and `Decimal::from_str_exact` accepts `_`
        // as a digit separator and a leading `+`, so `"1_000"` would read as a
        // thousand kilowatt-hours. A meter reading is money: the shape of a
        // quoted one is checked here rather than inherited from a
        // general-purpose parser's convenience features.
        if quoted && !is_plain_decimal(digits) {
            return Err(text);
        }
        // `Decimal` is 96-bit: a JSON number outside its range, or with more
        // than 28 decimal places, is refused rather than rounded. No meter
        // writes one; a crafted record might, and rounding money is the one
        // thing this crate must never do.
        let value = Decimal::from_str_exact(digits).map_err(|_| text)?;
        Ok(Self {
            text,
            value,
            quoted,
        })
    }
}

/// `-? digit+ ( '.' digit+ )?` — no separators, no leading `+`, no exponent.
///
/// Deliberately *narrower* than JSON, which permits an exponent: `RV` states a
/// number of valid decimal places and `1.0e3` states none of them. It is
/// applied only to a **quoted** number, because an unquoted one has already
/// been through the reader's JSON grammar and an exponent there is lawful text
/// this crate has no business refusing.
fn is_plain_decimal(s: &str) -> bool {
    let s = s.strip_prefix('-').unwrap_or(s);
    let (int, frac) = s.split_once('.').map_or((s, None), |(i, f)| (i, Some(f)));
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit());
    digits(int) && frac.is_none_or(digits)
}

impl core::fmt::Display for Number<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn num(text: &str) -> Number<'_> {
        Number::build(text, false).expect("parses")
    }

    #[test]
    fn trailing_zeros_are_part_of_the_statement() {
        let n = num("2935.600");
        assert_eq!(n.scale(), 3);
        assert_eq!(n.to_string(), "2935.600");
        assert_eq!(n.value().to_string(), "2935.600");
    }

    #[test]
    fn the_value_that_breaks_floats_survives() {
        // 9.2 as f64 is 9.199999999999999289457264239899814128875732421875.
        let n = num("9.2");
        assert_eq!(n.value(), Decimal::from_str_exact("9.2").unwrap());
        assert_eq!(n.to_string(), "9.2");
    }

    #[test]
    fn a_quoted_reading_keeps_its_leading_zeros() {
        let n = Number::build("00000000.000", true).unwrap();
        assert!(n.was_quoted());
        assert_eq!(n.as_str(), "00000000.000");
        assert_eq!(n.value(), Decimal::ZERO);
        assert_eq!(n.scale(), 3);
    }

    #[test]
    fn a_quoted_reading_is_still_held_to_a_number_grammar() {
        // `Decimal` would read every one of these; none of them is a reading.
        for junk in ["1_000", "+1", "1e3", "", " ", "1.", ".5", "--1", "0x10"] {
            // `1_000` is the one that matters: `Decimal` reads it as a
            // thousand, and a thousand kilowatt-hours is a real invoice.
            assert!(
                Number::build(junk, true).is_err(),
                "{junk} must not read as a meter value"
            );
        }
        // And the padded form a real meter emits still does.
        let n = Number::build("       9.038", true).unwrap();
        assert_eq!(n.as_str(), "       9.038", "reproduction uses the text");
        assert_eq!(n.value().to_string(), "9.038");
    }

    #[test]
    fn arithmetic_is_exact() {
        let start = num("10.1").value();
        let end = num("20.2").value();
        assert_eq!((end - start).to_string(), "10.1");
    }
}
