//! Building and signing records.
//!
//! # Text first, always
//!
//! The builder produces the payload *text*, hashes those exact bytes, and signs
//! the hash. There is no path from a typed value to a signature that does not go
//! through the bytes that will be transmitted — which is the same rule the
//! reading side enforces, stated from the other end.
//!
//! # Deterministic by default
//!
//! ECDSA leaks the private key if a nonce is ever reused across two signatures.
//! On a charge controller with a weak entropy source that is not a theoretical
//! risk, and the consequence is not one bad record but a fleet's worth of
//! evidence voided at once. So the default signer is **RFC 6979 deterministic**
//! ECDSA, which needs no randomness at all, and [`ExternalSigner`] hands the
//! prehashed 32 bytes to a secure element or HSM — which is what a certified
//! measuring capsule actually contains.
//!
//! # Nothing is emitted that cannot be read back
//!
//! Every record this builder produces is re-parsed and verified against the
//! signer's own public key before it is returned. A signing path that can emit
//! an unverifiable record is worse than no signing path at all.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! # #[cfg(feature = "curve-p256")] {
//! use ocmf::sign::{ReadingSpec, RecordBuilder, Secp256r1Signer, Signer};
//! use ocmf::{
//!     IdentificationLevel, IdentificationType, Location, OcmfTime, Pagination, Unit,
//! };
//! use rust_decimal::Decimal;
//!
//! let signer = Secp256r1Signer::from_bytes(&[0x2a; 32])?;
//! let at = |s: &str| OcmfTime::parse(s, &Location::at(0), &mut Vec::new()).unwrap();
//!
//! let record = RecordBuilder::new()
//!     .gateway("ocmf", "GW-1", "0.1.0")
//!     .pagination(Pagination::transaction(1))
//!     .meter_serial("1TEST00000001")
//!     .identification(
//!         false,
//!         IdentificationLevel::None,
//!         Vec::new(),
//!         IdentificationType::None,
//!         "",
//!     )
//!     .reading(
//!         ReadingSpec::new(
//!             at("2024-03-01T08:00:00,000+0100 S"),
//!             Decimal::from_str_exact("100.000")?,
//!             "01-00:B1.08.00*FF",
//!             Unit::KWh,
//!         )
//!         .begin(),
//!     )
//!     .reading(
//!         ReadingSpec::new(
//!             at("2024-03-01T09:30:00,000+0100 S"),
//!             Decimal::from_str_exact("129.500")?,
//!             "01-00:B1.08.00*FF",
//!             Unit::KWh,
//!         )
//!         .end(),
//!     )
//!     .sign(&signer)?;
//!
//! // RFC 6979: the same input signs to the same bytes, every time.
//! assert!(record.as_str().starts_with("OCMF|"));
//!
//! // The record was re-read and re-verified before it was returned, under the
//! // strictest profile this crate has — so it has nothing to report about
//! // itself, and a notified body will find nothing either.
//! let parsed = record.record()?;
//! assert!(parsed.deviations().is_empty());
//! ocmf::verify(&parsed, &signer.public_key()?)?;
//! # }
//! # Ok(()) }
//! ```

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use rust_decimal::Decimal;

use crate::error::BuildError;
use crate::key::PublicKey;
use crate::payload::{
    ChargePointIdType, CurrentType, IdentificationFlag, IdentificationLevel, IdentificationType,
    MeterState, Pagination, PaginationContext, TransactionMarker, Unit,
};
use crate::record::RecordBuf;
use crate::signature::Curve;
use crate::time::OcmfTime;

/// Something that can produce an ECDSA signature over a SHA-256 digest.
pub trait Signer {
    /// The curve this signer signs on.
    fn curve(&self) -> Curve;

    /// The matching public key, used for the builder's self-check.
    ///
    /// # Errors
    ///
    /// [`BuildError::Signer`] when the key cannot be derived.
    fn public_key(&self) -> Result<PublicKey, BuildError>;

    /// Signs a 32-byte SHA-256 digest, returning `(r, s)` big-endian.
    ///
    /// # Errors
    ///
    /// [`BuildError::Signer`] when the underlying signer fails.
    fn sign_prehash(&self, digest: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), BuildError>;
}

/// A signer backed by a secure element, HSM or any other external device.
///
/// The closure receives the SHA-256 digest and returns `(r, s)`. The public key
/// is supplied up front because the private key never leaves the device.
pub struct ExternalSigner<F> {
    curve: Curve,
    public_key: PublicKey,
    sign: F,
}

impl<F> ExternalSigner<F>
where
    F: Fn(&[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)>,
{
    /// Wraps an external signing function.
    pub fn new(public_key: PublicKey, sign: F) -> Self {
        Self {
            curve: public_key.curve(),
            public_key,
            sign,
        }
    }
}

impl<F> core::fmt::Debug for ExternalSigner<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExternalSigner")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}

impl<F> Signer for ExternalSigner<F>
where
    F: Fn(&[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)>,
{
    fn curve(&self) -> Curve {
        self.curve
    }

    fn public_key(&self) -> Result<PublicKey, BuildError> {
        Ok(self.public_key.clone())
    }

    fn sign_prehash(&self, digest: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), BuildError> {
        (self.sign)(digest).ok_or(BuildError::Signer)
    }
}

macro_rules! rfc6979_signer {
    ($(#[$m:meta])* $name:ident, $krate:ident, $curve:expr, $feature:literal) => {
        $(#[$m])*
        #[cfg(feature = $feature)]
        #[cfg_attr(docsrs, doc(cfg(feature = $feature)))]
        #[derive(Clone)]
        pub struct $name($krate::ecdsa::SigningKey);

        #[cfg(feature = $feature)]
        impl $name {
            /// Wraps a private scalar, big-endian, at the curve's field width.
            ///
            /// # Errors
            ///
            /// [`BuildError::Signer`] when the scalar is not a valid key.
            pub fn from_bytes(scalar: &[u8]) -> Result<Self, BuildError> {
                $krate::ecdsa::SigningKey::from_slice(scalar)
                    .map(Self)
                    .map_err(|_| BuildError::Signer)
            }
        }

        #[cfg(feature = $feature)]
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Never the key material, not even in a debug build.
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        #[cfg(feature = $feature)]
        impl Signer for $name {
            fn curve(&self) -> Curve {
                $curve
            }

            fn public_key(&self) -> Result<PublicKey, BuildError> {
                use $krate::elliptic_curve::sec1::ToEncodedPoint;
                let vk = self.0.verifying_key();
                let point = vk.as_affine().to_encoded_point(false);
                PublicKey::from_sec1($curve, point.as_bytes()).map_err(|_| BuildError::Signer)
            }

            fn sign_prehash(&self, digest: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), BuildError> {
                use $krate::ecdsa::signature::hazmat::PrehashSigner;
                let sig: $krate::ecdsa::Signature =
                    self.0.sign_prehash(digest).map_err(|_| BuildError::Signer)?;
                // Emit the low-`s` form. OCMF permits either — `(r, s)` and
                // `(r, n - s)` are the same statement — but a verifier that
                // enforces low-`s` (k256's default, and every Bitcoin-adjacent
                // stack) refuses the high one. Choosing the form everybody
                // accepts costs nothing.
                let sig = sig.normalize_s().unwrap_or(sig);
                let bytes = sig.to_bytes();
                let width = $curve.field_bytes();
                Ok((bytes[..width].to_vec(), bytes[width..].to_vec()))
            }
        }
    };
}

rfc6979_signer!(
    /// RFC 6979 deterministic ECDSA on secp256r1 — the OCMF default curve.
    Secp256r1Signer, p256, Curve::Secp256r1, "curve-p256");
rfc6979_signer!(
    /// RFC 6979 deterministic ECDSA on secp384r1, hashing with SHA-256 as
    /// `[OCMF Tab. 22]` requires.
    Secp384r1Signer, p384, Curve::Secp384r1, "curve-p384");
rfc6979_signer!(
    /// RFC 6979 deterministic ECDSA on secp256k1.
    Secp256k1Signer, k256, Curve::Secp256k1, "curve-k256");
// There is deliberately no secp192r1 signer. `p192` 0.13 publishes the
// verifying half of ECDSA and not the signing half, and a 192-bit curve is not
// something new hardware should be signing with in any case: it is here so that
// eBZ LD3 records — which the Transparenzsoftware ships as reference data — can
// be *checked*, which is the direction that matters for a curve on its way out.

/// `LC` — the cable-loss compensation parameters `[OCMF Tab. 24]`.
///
/// `LR` and `LU` are mandatory inside the block; `LN` and `LI` are the
/// traceability fields that let an auditor find the characteristics used.
#[derive(Debug, Clone)]
pub struct LossCompensationSpec<'a> {
    /// `LN` — a traceability text for the characteristics used, ≤ 20 chars.
    pub name: Option<&'a str>,
    /// `LI` — a traceability identifier from the meter's documentation.
    pub id: Option<Decimal>,
    /// `LR` — the cable resistance used. Mandatory.
    pub resistance: Decimal,
    /// `LU` — the unit of `LR`. Mandatory, and only `mOhm` or `uOhm` is
    /// defined; the builder refuses anything else.
    pub unit: Unit<'a>,
}

impl<'a> LossCompensationSpec<'a> {
    /// A compensation block with only the two mandatory fields.
    #[must_use]
    pub const fn new(resistance: Decimal, unit: Unit<'a>) -> Self {
        Self {
            name: None,
            id: None,
            resistance,
            unit,
        }
    }

    /// Sets `LN`.
    #[must_use]
    pub const fn name(mut self, name: &'a str) -> Self {
        self.name = Some(name);
        self
    }

    /// Sets `LI`.
    #[must_use]
    pub const fn id(mut self, id: Decimal) -> Self {
        self.id = Some(id);
        self
    }
}

/// One reading, for the builder.
#[derive(Debug, Clone)]
pub struct ReadingSpec<'a> {
    /// `TM`.
    pub time: OcmfTime,
    /// `TX`.
    pub transaction: Option<TransactionMarker>,
    /// `RV`.
    pub value: Option<Decimal>,
    /// `RI`.
    pub obis: Option<&'a str>,
    /// `RU`.
    pub unit: Option<Unit<'a>>,
    /// `RT`.
    pub current_type: Option<CurrentType<'a>>,
    /// `CL`.
    pub cumulated_loss: Option<Decimal>,
    /// `EF`.
    pub error_flags: Option<&'a str>,
    /// `ST`.
    pub state: MeterState,
}

impl<'a> ReadingSpec<'a> {
    /// A reading of `value` in `unit` from register `obis`, with the meter in
    /// good order.
    #[must_use]
    pub fn new(time: OcmfTime, value: Decimal, obis: &'a str, unit: Unit<'a>) -> Self {
        Self {
            time,
            transaction: None,
            value: Some(value),
            obis: Some(obis),
            unit: Some(unit),
            current_type: None,
            cumulated_loss: None,
            error_flags: Some(""),
            state: MeterState::Ok,
        }
    }

    /// Marks this reading as the start of a transaction.
    #[must_use]
    pub const fn begin(mut self) -> Self {
        self.transaction = Some(TransactionMarker::Begin);
        self
    }

    /// Marks this reading as the end of a transaction.
    #[must_use]
    pub const fn end(mut self) -> Self {
        self.transaction = Some(TransactionMarker::End);
        self
    }

    /// Sets `TX` explicitly.
    #[must_use]
    pub const fn transaction(mut self, marker: TransactionMarker) -> Self {
        self.transaction = Some(marker);
        self
    }

    /// Sets `RT`.
    #[must_use]
    pub const fn current_type(mut self, t: CurrentType<'a>) -> Self {
        self.current_type = Some(t);
        self
    }

    /// Sets `ST`.
    #[must_use]
    pub const fn state(mut self, state: MeterState) -> Self {
        self.state = state;
        self
    }

    /// Sets `EF`.
    #[must_use]
    pub const fn error_flags(mut self, flags: &'a str) -> Self {
        self.error_flags = Some(flags);
        self
    }

    /// Sets `CL`.
    #[must_use]
    pub const fn cumulated_loss(mut self, loss: Decimal) -> Self {
        self.cumulated_loss = Some(loss);
        self
    }
}

/// Builds an OCMF record and signs it.
#[derive(Debug, Clone, Default)]
pub struct RecordBuilder<'a> {
    format_version: Option<&'a str>,
    gateway_id: Option<&'a str>,
    gateway_serial: Option<&'a str>,
    gateway_version: Option<&'a str>,
    pagination: Option<Pagination>,
    meter_vendor: Option<&'a str>,
    meter_model: Option<&'a str>,
    meter_serial: Option<&'a str>,
    meter_firmware: Option<&'a str>,
    identification_status: Option<bool>,
    identification_level: Option<IdentificationLevel<'a>>,
    identification_flags: Option<Vec<IdentificationFlag<'a>>>,
    identification_type: Option<IdentificationType<'a>>,
    identification_data: Option<&'a str>,
    tariff_text: Option<&'a str>,
    charge_controller_firmware: Option<&'a str>,
    loss_compensation: Option<LossCompensationSpec<'a>>,
    charge_point_id_type: Option<ChargePointIdType<'a>>,
    charge_point_id: Option<&'a str>,
    readings: Vec<ReadingSpec<'a>>,
    write_algorithm: bool,
}

impl<'a> RecordBuilder<'a> {
    /// A new builder.
    ///
    /// `FV` is **derived from the fields the record actually uses** unless
    /// [`Self::format_version`] sets it — see [`Self::required_format_version`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            format_version: None,
            write_algorithm: true,
            ..Self::default()
        }
    }

    /// Sets `FV` explicitly, overriding the derived value.
    #[must_use]
    pub const fn format_version(mut self, v: &'a str) -> Self {
        self.format_version = Some(v);
        self
    }

    /// The oldest `FV` that can describe this record: `CF` ⇒ 1.3, `LC` ⇒ 1.2,
    /// `TT` ⇒ 1.1, otherwise 1.0.
    ///
    /// Stamping the newest revision instead is the obvious default and the
    /// wrong one: the legally recognised verifier dispatches on `version <= 1.3`
    /// (R7), so `1.4` on a record that uses nothing newer than 1.0 makes a
    /// station's evidence unreadable by the tool a driver runs, for nothing.
    ///
    /// The unified OBIS range of `[OCMF Tab. 25]` arrived in 1.4 but changes no
    /// field, so it does not raise the floor.
    #[must_use]
    pub const fn required_format_version(&self) -> &'static str {
        if self.charge_controller_firmware.is_some() {
            "1.3"
        } else if self.loss_compensation.is_some() {
            "1.2"
        } else if self.tariff_text.is_some() {
            "1.1"
        } else {
            "1.0"
        }
    }

    /// Sets `GI`, `GS` and `GV` together — they describe one component.
    #[must_use]
    pub const fn gateway(mut self, id: &'a str, serial: &'a str, version: &'a str) -> Self {
        self.gateway_id = Some(id);
        self.gateway_serial = Some(serial);
        self.gateway_version = Some(version);
        self
    }

    /// Sets `PG`.
    #[must_use]
    pub const fn pagination(mut self, p: Pagination) -> Self {
        self.pagination = Some(p);
        self
    }

    /// Sets `MV`, `MM`, `MS` and `MF`.
    #[must_use]
    pub const fn meter(
        mut self,
        vendor: &'a str,
        model: &'a str,
        serial: &'a str,
        firmware: &'a str,
    ) -> Self {
        self.meter_vendor = Some(vendor);
        self.meter_model = Some(model);
        self.meter_serial = Some(serial);
        self.meter_firmware = Some(firmware);
        self
    }

    /// Sets `MS` alone — the one meter field `[OCMF Tab. 3]` makes mandatory.
    #[must_use]
    pub const fn meter_serial(mut self, serial: &'a str) -> Self {
        self.meter_serial = Some(serial);
        self
    }

    /// Sets the user assignment: `IS`, `IL`, `IF`, `IT` and `ID`.
    #[must_use]
    pub fn identification(
        mut self,
        assigned: bool,
        level: IdentificationLevel<'a>,
        flags: Vec<IdentificationFlag<'a>>,
        kind: IdentificationType<'a>,
        data: &'a str,
    ) -> Self {
        self.identification_status = Some(assigned);
        self.identification_level = Some(level);
        self.identification_flags = Some(flags);
        self.identification_type = Some(kind);
        self.identification_data = Some(data);
        self
    }

    /// Sets `TT`, the tariff text.
    #[must_use]
    pub const fn tariff_text(mut self, text: &'a str) -> Self {
        self.tariff_text = Some(text);
        self
    }

    /// Sets `CF`, the charge-controller firmware version.
    #[must_use]
    pub const fn charge_controller_firmware(mut self, v: &'a str) -> Self {
        self.charge_controller_firmware = Some(v);
        self
    }

    /// Sets `LC`, the cable-loss compensation block `[OCMF Tab. 24]`.
    #[must_use]
    pub fn loss_compensation(mut self, lc: LossCompensationSpec<'a>) -> Self {
        self.loss_compensation = Some(lc);
        self
    }

    /// Sets `CT` and `CI`.
    #[must_use]
    pub const fn charge_point(mut self, kind: ChargePointIdType<'a>, id: &'a str) -> Self {
        self.charge_point_id_type = Some(kind);
        self.charge_point_id = Some(id);
        self
    }

    /// Appends a reading.
    #[must_use]
    pub fn reading(mut self, r: ReadingSpec<'a>) -> Self {
        self.readings.push(r);
        self
    }

    /// Whether to write `SA` even when it is the default algorithm.
    ///
    /// Default `true`. Only 23 of 256 real records write it, so omitting it is
    /// well-trodden — but writing it costs 32 bytes and removes an assumption.
    #[must_use]
    pub const fn write_algorithm(mut self, write: bool) -> Self {
        self.write_algorithm = write;
        self
    }

    /// Renders the payload section exactly as it will be signed.
    ///
    /// Exposed because it is worth being able to look at the bytes before they
    /// are committed to.
    ///
    /// # Errors
    ///
    /// [`BuildError`] when a required field is missing, a value contains `|`,
    /// or the readings do not form a coherent record.
    ///
    /// # Panics
    ///
    /// Never: `validate` runs first and returns [`BuildError::MissingField`]
    /// for an unset `PG`, which is the only value unwrapped below.
    #[allow(clippy::too_many_lines, reason = "the canonical field order, in order")]
    pub fn payload_text(&self) -> Result<String, BuildError> {
        self.validate()?;
        let mut s = String::with_capacity(320);
        s.push('{');
        let mut w = Writer {
            out: &mut s,
            first: true,
        };

        w.str_field(
            "FV",
            Some(
                self.format_version
                    .unwrap_or_else(|| self.required_format_version()),
            ),
        )?;
        w.str_field("GI", self.gateway_id)?;
        w.str_field("GS", self.gateway_serial)?;
        w.str_field("GV", self.gateway_version)?;
        w.str_field("PG", Some(&self.pagination.expect("validated").to_string()))?;
        w.str_field("MV", self.meter_vendor)?;
        w.str_field("MM", self.meter_model)?;
        w.str_field("MS", self.meter_serial)?;
        w.str_field("MF", self.meter_firmware)?;
        if let Some(v) = self.identification_status {
            w.raw_field("IS", if v { "true" } else { "false" });
        }
        w.str_field("IL", self.identification_level.map(|l| l.as_str()))?;
        if let Some(flags) = &self.identification_flags {
            w.key("IF");
            w.out.push('[');
            for (i, f) in flags.iter().enumerate() {
                if i > 0 {
                    w.out.push(',');
                }
                write_json_string(w.out, f.as_str(), "IF")?;
            }
            w.out.push(']');
        }
        w.str_field("IT", self.identification_type.map(|t| t.as_str()))?;
        w.str_field("ID", self.identification_data)?;
        w.str_field("TT", self.tariff_text)?;
        w.str_field("CF", self.charge_controller_firmware)?;
        if let Some(lc) = &self.loss_compensation {
            w.key("LC");
            w.out.push('{');
            let mut lw = Writer {
                out: w.out,
                first: true,
            };
            lw.str_field("LN", lc.name)?;
            if let Some(id) = lc.id {
                lw.raw_field("LI", &id.to_string());
            }
            lw.raw_field("LR", &lc.resistance.to_string());
            lw.str_field("LU", Some(lc.unit.as_str()))?;
            w.out.push('}');
        }
        w.str_field("CT", self.charge_point_id_type.map(|t| t.as_str()))?;
        w.str_field("CI", self.charge_point_id)?;

        w.key("RD");
        w.out.push('[');
        for (i, r) in self.readings.iter().enumerate() {
            if i > 0 {
                w.out.push(',');
            }
            w.out.push('{');
            let mut rw = Writer {
                out: w.out,
                first: true,
            };
            rw.str_field("TM", Some(&r.time.to_string()))?;
            if let Some(tx) = r.transaction {
                rw.str_field("TX", Some(&alloc::format!("{}", tx.letter())))?;
            }
            if let Some(v) = r.value {
                rw.raw_field("RV", &v.to_string());
            }
            rw.str_field("RI", r.obis)?;
            rw.str_field("RU", r.unit.map(|u| u.as_str()))?;
            rw.str_field("RT", r.current_type.map(|t| t.as_str()))?;
            if let Some(cl) = r.cumulated_loss {
                rw.raw_field("CL", &cl.to_string());
            }
            rw.str_field("EF", r.error_flags)?;
            rw.str_field("ST", Some(&alloc::format!("{}", r.state.letter())))?;
            w.out.push('}');
        }
        w.out.push(']');
        s.push('}');
        Ok(s)
    }

    /// Signs the record and returns it, having re-read and re-verified it.
    ///
    /// # Errors
    ///
    /// [`BuildError`] from validation or the signer, and
    /// [`BuildError::SelfCheck`] if the emitted record does not read back and
    /// verify — which would be a bug in this crate, not in the caller's input.
    pub fn sign<S: Signer>(&self, signer: &S) -> Result<RecordBuf, BuildError> {
        // Omitting `SA` says "secp256r1" `[OCMF Tab. 22]`. Omitting it while
        // signing on another curve produces a record that reads as a lie, and
        // the self-check below would catch it only as a mystified
        // `SelfCheck("the signature did not verify")`.
        if !self.write_algorithm && signer.curve() != Curve::Secp256r1 {
            return Err(BuildError::AlgorithmMustBeWritten {
                curve: signer.curve().name(),
            });
        }
        let payload = self.payload_text()?;

        let digest = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(payload.as_bytes());
            let out: [u8; 32] = h.finalize().into();
            out
        };
        let (r, s) = signer.sign_prehash(&digest)?;
        // Every record this crate writes carries the low-`s` form. OCMF permits
        // either — `(r, s)` and `(r, n - s)` are the same statement — but a
        // verifier that enforces the low one (k256's default, and every
        // Bitcoin-adjacent stack) refuses the high form, and a record that
        // fails an audit somewhere else is a record that failed. The pure-Rust
        // signers already emit it; normalising here is what extends the promise
        // to `ExternalSigner`, where the bytes come out of somebody's HSM.
        let curve = signer.curve();
        if !crate::scalar::in_range(&r, curve.order())
            || !crate::scalar::in_range(&s, curve.order())
        {
            return Err(BuildError::Signer);
        }
        let s = if crate::scalar::is_high(&s, curve.order()) {
            crate::scalar::negate(&s, curve.order())
        } else {
            s
        };
        let der = crate::der::write_ecdsa_signature(&r, &s);

        let mut text = String::with_capacity(payload.len() + 220);
        text.push_str(crate::record::HEADER);
        text.push('|');
        text.push_str(&payload);
        text.push('|');
        text.push('{');
        if self.write_algorithm {
            text.push_str(r#""SA":""#);
            text.push_str(curve.algorithm().as_str());
            text.push_str(r#"","#);
        }
        text.push_str(r#""SD":""#);
        text.push_str(&crate::encoding::hex_encode_upper(&der));
        text.push_str(r#""}"#);

        // Never emit a record that cannot be read back and checked — and
        // never one this crate's own strictest reader would refuse. `validate`
        // above is the promise; this is the proof, on the bytes themselves.
        let buf = RecordBuf::new(text, crate::Profile::Strict, crate::Limits::DEFAULT)
            .map_err(|_| BuildError::SelfCheck("the record did not parse under Profile::Strict"))?;
        {
            let record = buf
                .record()
                .map_err(|_| BuildError::SelfCheck("the record did not re-parse"))?;
            if record.signed_bytes() != payload.as_bytes() {
                return Err(BuildError::SelfCheck("the signed span moved"));
            }
            let key = signer.public_key()?;
            crate::verify::verify(&record, &key)
                .map_err(|_| BuildError::SelfCheck("the signature did not verify"))?;
        }
        Ok(buf)
    }

    /// Everything that must hold before a byte is written.
    ///
    /// The bar is not "the builder produces JSON": it is that **a record this
    /// crate writes is accepted by [`Profile::Strict`](crate::Profile)**, which
    /// [`Self::sign`] then re-checks on the emitted text. So every value that
    /// would become a `Departure::Specification` deviation on the reading side
    /// is refused here — an undefined table value, an OBIS code outside the
    /// `[OCMF Tab. 25]` form, a `TM` with no synchronisation letter — because a
    /// station that emits one has to hear it from its own build, not from a
    /// notified body.
    #[allow(clippy::too_many_lines, reason = "one check per rule Strict enforces")]
    fn validate(&self) -> Result<(), BuildError> {
        let required = |field: &'static str, spec: &'static str, present: bool| {
            if present {
                Ok(())
            } else {
                Err(BuildError::MissingField { field, spec })
            }
        };
        let defined = |field: &'static str, spec: &'static str, ok: bool| {
            if ok {
                Ok(())
            } else {
                Err(BuildError::FieldValue { field, spec })
            }
        };
        let bounded = |field: &'static str,
                       spec: &'static str,
                       max: usize,
                       value: Option<&str>|
         -> Result<(), BuildError> {
            if let Some(t) = value
                && t.chars().count() > max
            {
                return Err(BuildError::TooLong {
                    field,
                    len: t.chars().count(),
                    max,
                    spec,
                });
            }
            Ok(())
        };

        // ── The record's own shape ─────────────────────────────────────────
        let pagination = self.pagination.ok_or(BuildError::MissingField {
            field: "PG",
            spec: "OCMF Tab. 2",
        })?;
        defined(
            "PG",
            "OCMF Tab. 2",
            !matches!(pagination.context(), PaginationContext::Other(_)),
        )?;
        if self.readings.is_empty() {
            return Err(BuildError::NoReadings);
        }
        // `[OCMF Tab. 3]` marks `MS` `1..1`. 89 % of real records omit it and
        // this crate reads every one of them — and writes none.
        required("MS", "OCMF Tab. 3", self.meter_serial.is_some())?;

        if let Some(v) = self.format_version {
            defined("FV", "OCMF Tab. 1", is_major_minor(v))?;
        }

        // ── The user assignment ────────────────────────────────────────────
        //
        // "Present iff there is a transaction reference, even when nobody could
        // be assigned" `[OCMF Tab. 4]`. A station that assigned nobody writes
        // `IS: false` with `IL`/`IT` of `NONE`; it does not write nothing.
        if pagination.context() == PaginationContext::Transaction {
            required("IS", "OCMF Tab. 4", self.identification_status.is_some())?;
        }
        if self.identification_status.is_some() {
            required("IF", "OCMF Tab. 4", self.identification_flags.is_some())?;
            required("IT", "OCMF Tab. 4", self.identification_type.is_some())?;
        }
        if let Some(level) = self.identification_level {
            defined("IL", "OCMF Tab. 11", level.is_defined())?;
        }
        if let Some(kind) = self.identification_type {
            defined("IT", "OCMF Tab. 17", kind.is_defined())?;
        }
        for flag in self.identification_flags.iter().flatten() {
            defined("IF", "OCMF Tab. 13-16", flag.is_defined())?;
        }
        if let (Some(kind), Some(id)) = (self.identification_type, self.identification_data)
            && kind.data_is_well_formed(id) == Some(false)
        {
            return Err(BuildError::FieldValue {
                field: "ID",
                spec: "OCMF Tab. 17",
            });
        }

        // ── The charge point ───────────────────────────────────────────────
        if let Some(kind) = self.charge_point_id_type {
            defined("CT", "OCMF Tab. 18", kind.is_defined())?;
            if let Some(id) = self.charge_point_id
                && kind.id_is_well_formed(id) == Some(false)
            {
                return Err(BuildError::FieldValue {
                    field: "CI",
                    spec: "OCMF Tab. 18",
                });
            }
        }

        bounded("TT", "OCMF Tab. 4", 250, self.tariff_text)?;
        bounded("CF", "OCMF Tab. 5", 25, self.charge_controller_firmware)?;

        if let Some(lc) = &self.loss_compensation {
            defined(
                "LU",
                "OCMF Tab. 24",
                matches!(lc.unit, Unit::MilliOhm | Unit::MicroOhm),
            )?;
            bounded("LN", "OCMF Tab. 24", 20, lc.name)?;
        }

        // ── The readings ───────────────────────────────────────────────────
        for r in &self.readings {
            // A `TM` whose civil fields are not a date would be written and
            // then fail to read back; `[OCMF Tab. 19]`'s letter is not
            // decoration, and a reading without one states nothing about its
            // own clock.
            defined("TM", "OCMF Tab. 7", r.time.is_valid())?;
            required("TM", "OCMF Tab. 19", r.time.status.is_some())?;
            defined("ST", "OCMF Tab. 10", r.state.is_defined())?;
            if let Some(tx) = r.transaction {
                defined("TX", "OCMF Tab. 7", tx.is_defined())?;
            }
            if let Some(u) = r.unit {
                defined("RU", "OCMF Tab. 20", u.is_defined())?;
            }
            if let Some(t) = r.current_type {
                defined("RT", "OCMF Tab. 21", t.is_defined())?;
            }
            // `[OCMF Tab. 7]`'s exemption covers a reading with no value at
            // all; a value with no unit is not a quantity.
            if r.value.is_some() {
                required("RU", "OCMF Tab. 7", r.unit.is_some())?;
            }
            if let Some(flags) = r.error_flags {
                defined(
                    "EF",
                    "OCMF Tab. 7",
                    flags.chars().all(|c| matches!(c, 'E' | 't')),
                )?;
            }
            // `[OCMF Tab. 25]` gives one form; the reference corpus uses
            // twelve others, and this crate reads them all. It writes the one.
            if let Some(code) = r.obis {
                let parsed = crate::obis::ObisCode::parse(code).ok_or(BuildError::FieldValue {
                    field: "RI",
                    spec: "OCMF Tab. 25",
                })?;
                defined("RI", "OCMF Tab. 25", parsed.is_canonical())?;
            }
        }

        let count = |f: fn(TransactionMarker) -> bool| {
            self.readings
                .iter()
                .filter(|r| r.transaction.is_some_and(f))
                .count()
        };
        if count(TransactionMarker::is_begin) > 1 {
            return Err(BuildError::TransactionMarkers {
                reason: "more than one reading marks the begin of the transaction",
            });
        }
        if count(TransactionMarker::is_end) > 1 {
            return Err(BuildError::TransactionMarkers {
                reason: "more than one reading marks the end of the transaction",
            });
        }
        Ok(())
    }
}

/// `<major>.<minor>` — `[OCMF Tab. 1]`'s shape for `FV`.
fn is_major_minor(v: &str) -> bool {
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit());
    v.split_once('.')
        .is_some_and(|(major, minor)| digits(major) && digits(minor))
}

struct Writer<'w> {
    out: &'w mut String,
    first: bool,
}

impl Writer<'_> {
    fn key(&mut self, name: &str) {
        if self.first {
            self.first = false;
        } else {
            self.out.push(',');
        }
        self.out.push('"');
        self.out.push_str(name);
        self.out.push_str("\":");
    }

    fn str_field(&mut self, name: &'static str, value: Option<&str>) -> Result<(), BuildError> {
        if let Some(v) = value {
            self.key(name);
            write_json_string(self.out, v, name)?;
        }
        Ok(())
    }

    fn raw_field(&mut self, name: &str, value: &str) {
        self.key(name);
        self.out.push_str(value);
    }
}

/// Writes a JSON string, refusing the one character that would make the record
/// unreadable.
fn write_json_string(out: &mut String, s: &str, field: &'static str) -> Result<(), BuildError> {
    use core::fmt::Write as _;
    if s.contains('|') {
        return Err(BuildError::PipeInField { field });
    }
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deviation::Location;
    use crate::record::Record;
    use alloc::vec;

    fn a_time(s: &str) -> OcmfTime {
        let mut dev = vec![];
        OcmfTime::parse(s, &Location::at(0), &mut dev).unwrap()
    }

    fn builder<'a>() -> RecordBuilder<'a> {
        RecordBuilder::new()
            .gateway("ocmf-rs", "TEST-1", "0.1.0")
            .pagination(Pagination::transaction(1))
            .meter_serial("METER-1")
            .identification(
                true,
                IdentificationLevel::Verified,
                vec![IdentificationFlag::parse("RFID_PLAIN")],
                IdentificationType::Iso14443,
                "1F2D3A4F5506C7",
            )
            .reading(
                ReadingSpec::new(
                    a_time("2018-07-24T13:22:04,000+0200 S"),
                    Decimal::from_str_exact("2935.600").unwrap(),
                    "01-00:B1.08.00*FF",
                    Unit::KWh,
                )
                .begin()
                .current_type(CurrentType::Dc),
            )
            .reading(
                ReadingSpec::new(
                    a_time("2018-07-24T13:26:04,000+0200 S"),
                    Decimal::from_str_exact("2965.100").unwrap(),
                    "01-00:B1.08.00*FF",
                    Unit::KWh,
                )
                .end()
                .current_type(CurrentType::Dc),
            )
    }

    #[cfg(feature = "curve-p256")]
    fn signer() -> Secp256r1Signer {
        Secp256r1Signer::from_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn a_signed_record_verifies_with_the_signers_own_key() {
        let buf = builder().sign(&signer()).unwrap();
        let record = buf.record().unwrap();
        let key = signer().public_key().unwrap();
        let v = crate::verify::verify(&record, &key).expect("its own signature");
        assert_eq!(v.payload().readings().len(), 2);
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn signing_is_deterministic() {
        // RFC 6979: the same input signs to the same bytes, every time.
        assert_eq!(
            builder().sign(&signer()).unwrap().as_str(),
            builder().sign(&signer()).unwrap().as_str()
        );
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn the_signed_span_is_the_payload_text_the_builder_showed() {
        let b = builder();
        let payload = b.payload_text().unwrap();
        let buf = b.sign(&signer()).unwrap();
        let record = buf.record().unwrap();
        assert_eq!(record.signed_bytes(), payload.as_bytes());
        assert_eq!(record.payload_text(), payload);
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn a_built_record_round_trips_and_reads_back_field_for_field() {
        let buf = builder().sign(&signer()).unwrap();
        let text = buf.as_str().to_string();
        let record = Record::parse(&text).unwrap();
        assert_eq!(record.to_string(), text);
        let p = record.payload();
        assert_eq!(p.meter_serial(), Some("METER-1"));
        assert_eq!(p.pagination().unwrap().to_string(), "T1");
        assert_eq!(p.readings()[0].value().unwrap().as_str(), "2935.600");
        assert_eq!(
            p.readings()[0].obis().unwrap().register(),
            crate::obis::Register::TotalImportDevice
        );
        // A record this crate builds has nothing to report about itself.
        assert!(record.deviations().is_empty(), "{:?}", record.deviations());
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn strict_accepts_what_this_builder_emits() {
        let buf = builder().sign(&signer()).unwrap();
        let text = buf.as_str().to_string();
        Record::parse_with(&text, crate::Profile::Strict, &crate::Limits::DEFAULT)
            .expect("the builder emits specification-clean records");
    }

    #[test]
    fn a_pipe_in_a_field_is_refused_before_anything_is_signed() {
        let err = builder()
            .tariff_text("Tarif|Nacht")
            .payload_text()
            .unwrap_err();
        assert_eq!(err, BuildError::PipeInField { field: "TT" });
    }

    #[test]
    fn incoherent_records_are_refused() {
        assert_eq!(
            RecordBuilder::new().payload_text().unwrap_err(),
            BuildError::MissingField {
                field: "PG",
                spec: "OCMF Tab. 2"
            }
        );
        assert_eq!(
            RecordBuilder::new()
                .pagination(Pagination::transaction(1))
                .meter_serial("M")
                .payload_text()
                .unwrap_err(),
            BuildError::NoReadings
        );
        // A transaction record states whether a user was assigned, even when
        // the answer is "nobody" `[OCMF Tab. 4]`.
        assert_eq!(
            RecordBuilder::new()
                .pagination(Pagination::transaction(1))
                .meter_serial("M")
                .reading(ReadingSpec::new(
                    a_time("2024-03-01T08:00:00,000+0100 S"),
                    Decimal::ONE,
                    "01-00:B1.08.00*FF",
                    Unit::KWh,
                ))
                .payload_text()
                .unwrap_err(),
            BuildError::MissingField {
                field: "IS",
                spec: "OCMF Tab. 4"
            }
        );
        // `[OCMF Tab. 3]` marks `MS` mandatory and 89 % of real records omit
        // it. This crate reads every one of them and writes none.
        assert_eq!(
            RecordBuilder::new()
                .pagination(Pagination::transaction(1))
                .reading(ReadingSpec::new(
                    a_time("2024-03-01T08:00:00,000+0100 S"),
                    Decimal::ONE,
                    "01-00:B1.08.00*FF",
                    Unit::KWh,
                ))
                .payload_text()
                .unwrap_err(),
            BuildError::MissingField {
                field: "MS",
                spec: "OCMF Tab. 3"
            }
        );
        // …and a fiscal record does not.
        RecordBuilder::new()
            .pagination(Pagination::fiscal(1))
            .meter_serial("M")
            .reading(ReadingSpec::new(
                a_time("2024-03-01T08:00:00,000+0100 S"),
                Decimal::ONE,
                "01-00:B1.08.00*FF",
                Unit::KWh,
            ))
            .payload_text()
            .expect("fiscal readings sit outside any transaction");

        let two_begins = builder().reading(
            ReadingSpec::new(
                a_time("2018-07-24T13:30:04,000+0200 S"),
                Decimal::ONE,
                "01-00:B1.08.00*FF",
                Unit::KWh,
            )
            .begin(),
        );
        assert!(matches!(
            two_begins.payload_text(),
            Err(BuildError::TransactionMarkers { .. })
        ));
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn the_loss_compensation_block_is_written_and_reads_back() {
        let buf = builder()
            .loss_compensation(
                LossCompensationSpec::new(Decimal::from_str_exact("2.5").unwrap(), Unit::MilliOhm)
                    .name("cable_A")
                    .id(Decimal::ONE),
            )
            .sign(&signer())
            .unwrap();
        let text = buf.as_str().to_string();
        let record = Record::parse(&text).unwrap();
        let lc = record.payload().loss_compensation().expect("LC is there");
        assert_eq!(lc.name.as_deref(), Some("cable_A"));
        assert_eq!(lc.resistance.as_ref().unwrap().as_str(), "2.5");
        assert_eq!(lc.unit, Some(Unit::MilliOhm));
        assert!(record.deviations().is_empty(), "{:?}", record.deviations());
    }

    #[test]
    fn the_format_version_is_derived_from_the_fields_the_record_uses() {
        let base = || {
            RecordBuilder::new()
                .pagination(Pagination::transaction(1))
                .meter_serial("M")
                .identification(
                    false,
                    IdentificationLevel::None,
                    vec![],
                    IdentificationType::None,
                    "",
                )
                .reading(ReadingSpec::new(
                    a_time("2024-03-01T08:00:00,000+0100 S"),
                    Decimal::ONE,
                    "01-00:B1.08.00*FF",
                    Unit::KWh,
                ))
        };
        let fv = |b: RecordBuilder<'_>| {
            let t = b.payload_text().unwrap();
            let at = t.find(r#""FV":""#).unwrap() + 6;
            t[at..].split('"').next().unwrap().to_string()
        };

        assert_eq!(fv(base()), "1.0", "a plain record needs nothing newer");
        assert_eq!(fv(base().tariff_text("Tarif 1")), "1.1");
        assert_eq!(
            fv(base().loss_compensation(LossCompensationSpec::new(Decimal::ONE, Unit::MilliOhm))),
            "1.2"
        );
        assert_eq!(fv(base().charge_controller_firmware("2.1")), "1.3");
        assert_eq!(fv(base().format_version("1.4")), "1.4", "explicit wins");

        // And the derived default is one the legally recognised verifier reads,
        // which "the newest version number" would not have been (R7).
        let record = base().sign(&signer()).unwrap();
        crate::Record::parse_with(
            record.as_str(),
            crate::Profile::Reference,
            &crate::Limits::DEFAULT,
        )
        .expect("the official tool dispatches on this version");
    }

    #[test]
    fn a_field_whose_shape_its_table_states_is_checked_before_signing() {
        // `[OCMF Tab. 17]`: an ISO14443 UID is 4 or 7 bytes of hex.
        let bad_id = RecordBuilder::new()
            .pagination(Pagination::transaction(1))
            .meter_serial("M")
            .identification(
                true,
                IdentificationLevel::Verified,
                vec![],
                IdentificationType::Iso14443,
                "NOT-A-UID",
            )
            .reading(ReadingSpec::new(
                a_time("2024-03-01T08:00:00,000+0100 S"),
                Decimal::ONE,
                "01-00:B1.08.00*FF",
                Unit::KWh,
            ));
        assert_eq!(
            bad_id.payload_text().unwrap_err(),
            BuildError::FieldValue {
                field: "ID",
                spec: "OCMF Tab. 17"
            }
        );

        // `[OCMF Tab. 18]`: CBIDC is a charge box ID, a space, a connector ID.
        assert_eq!(
            builder()
                .charge_point(ChargePointIdType::ChargeBoxAndConnector, "STEVE_01")
                .payload_text()
                .unwrap_err(),
            BuildError::FieldValue {
                field: "CI",
                spec: "OCMF Tab. 18"
            }
        );
        builder()
            .charge_point(ChargePointIdType::ChargeBoxAndConnector, "STEVE_01 1")
            .payload_text()
            .expect("with the separator it is well formed");

        // `[OCMF Tab. 1]`: `<major>.<minor>`, no revision digit.
        assert_eq!(
            builder()
                .format_version("1.4.1")
                .payload_text()
                .unwrap_err(),
            BuildError::FieldValue {
                field: "FV",
                spec: "OCMF Tab. 1"
            }
        );
    }

    #[test]
    fn a_loss_compensation_unit_outside_table_24_is_refused() {
        let err = builder()
            .loss_compensation(LossCompensationSpec::new(Decimal::ONE, Unit::KWh))
            .payload_text()
            .unwrap_err();
        assert_eq!(
            err,
            BuildError::FieldValue {
                field: "LU",
                spec: "OCMF Tab. 24"
            }
        );
    }

    #[test]
    #[cfg(feature = "curve-k256")]
    fn a_non_default_curve_may_not_omit_sa() {
        // Without `SA` the record claims secp256r1, which it is not.
        let k = Secp256k1Signer::from_bytes(&[5u8; 32]).unwrap();
        assert_eq!(
            builder().write_algorithm(false).sign(&k).unwrap_err(),
            BuildError::AlgorithmMustBeWritten { curve: "secp256k1" }
        );
        // With it, the record says what it is and verifies.
        let buf = builder().sign(&k).unwrap();
        assert!(buf.as_str().contains("ECDSA-secp256k1-SHA256"));
    }

    #[test]
    fn a_tariff_text_over_250_characters_is_refused() {
        let long: String = core::iter::repeat_n('a', 251).collect();
        assert!(matches!(
            builder().tariff_text(&long).payload_text(),
            Err(BuildError::TooLong { field: "TT", .. })
        ));
    }

    #[test]
    fn decimals_keep_their_scale_through_the_writer() {
        let b = RecordBuilder::new()
            .pagination(Pagination::transaction(1))
            .meter_serial("M")
            .identification(
                false,
                IdentificationLevel::None,
                vec![],
                IdentificationType::None,
                "",
            )
            .reading(ReadingSpec::new(
                a_time("2018-07-24T13:22:04,000+0200 S"),
                Decimal::from_str_exact("0.100").unwrap(),
                "01-00:B1.08.00*FF",
                Unit::KWh,
            ));
        assert!(b.payload_text().unwrap().contains(r#""RV":0.100"#));
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn an_external_signer_sees_only_the_digest() {
        let inner = signer();
        let key = inner.public_key().unwrap();
        let external = ExternalSigner::new(key, |digest: &[u8; 32]| {
            assert_eq!(digest.len(), 32);
            inner.sign_prehash(digest).ok()
        });
        let buf = builder().sign(&external).unwrap();
        assert_eq!(buf.as_str(), builder().sign(&signer()).unwrap().as_str());
    }

    #[test]
    #[cfg(feature = "curve-p256")]
    fn a_signer_never_prints_its_key() {
        let s = alloc::format!("{:?}", signer());
        assert_eq!(s, "Secp256r1Signer(<redacted>)");
    }
}
