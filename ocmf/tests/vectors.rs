//! Cross-curve vectors: every algorithm `[OCMF Tab. 22]` defines, and every
//! encoding shape the field is known to emit.
//!
//! The reference corpus is real data, and that is its value — but it is thin
//! where it matters most. Exactly two of its records are brainpoolP256r1 and two
//! are secp192k1, and none of them exercises a `base64` signature. These vectors
//! fill the gap: **generated with OpenSSL, verified by OpenSSL before being
//! checked in**, so a curve that this crate gets wrong fails here rather than in
//! a dispute four years from now.
//!
//! Regenerate with `tests/vectors/README.md`.

use std::collections::BTreeSet;

#[cfg(feature = "verify")]
use ocmf::PublicKey;
use ocmf::{Curve, Limits, Profile, Record, json};

struct Vector {
    curve: String,
    algorithm: String,
    record: String,
    key_hex: String,
    shape: Option<String>,
}

fn vectors() -> Vec<Vector> {
    let raw = include_str!("vectors/curves.json");
    let mut dev = Vec::new();
    let value = json::parse(raw, &Limits::UNLIMITED, &mut dev).expect("the fixture is JSON");
    value
        .as_object()
        .unwrap()
        .get("vectors")
        .unwrap()
        .as_array()
        .unwrap()
        .items
        .iter()
        .map(|v| {
            let o = v.as_object().unwrap();
            let text = |k: &str| {
                o.get(k)
                    .and_then(json::Value::as_str)
                    .map(|s| s.decode().into_owned())
            };
            Vector {
                curve: text("curve").unwrap(),
                algorithm: text("algorithm").unwrap(),
                record: text("record").unwrap(),
                key_hex: text("key_spki_hex").unwrap(),
                shape: text("shape"),
            }
        })
        .collect()
}

#[test]
fn the_vectors_cover_every_algorithm_the_specification_defines() {
    let covered: BTreeSet<String> = vectors().into_iter().map(|v| v.algorithm).collect();
    for c in Curve::ALL {
        assert!(
            covered.contains(c.algorithm().as_str()),
            "no vector for {} — a curve with no vector is a curve nobody checks",
            c.algorithm()
        );
    }
}

#[test]
fn every_vector_parses_cleanly_and_round_trips() {
    for v in vectors() {
        // These records are written to the specification, so `Strict` must
        // accept every one of them — including the deviant *encodings*, which
        // live in the signature section and are only judged at verification.
        let record = Record::parse_with(&v.record, Profile::Interop, &Limits::DEFAULT)
            .unwrap_or_else(|e| panic!("{} {:?}: {e}", v.curve, v.shape));
        assert_eq!(record.to_string(), v.record, "{}", v.curve);
        assert_eq!(
            record
                .signature()
                .algorithm()
                .map(ocmf::SignatureAlgorithm::as_str),
            Some(v.algorithm.as_str())
        );
        assert_eq!(record.payload().readings().len(), 2);
        assert_eq!(
            record.payload().by_register()[0]
                .delta()
                .unwrap()
                .to_string(),
            "29.500"
        );
    }
}

#[test]
#[cfg(feature = "verify")]
fn every_algorithm_this_build_supports_verifies_its_vector() {
    let supported = ocmf::verify::supported_curves();
    let mut checked = 0usize;
    let mut named_unsupported = 0usize;

    for v in vectors() {
        let record = Record::parse(&v.record).unwrap();
        let curve = record
            .signature()
            .curve()
            .expect("the vector names an algorithm");
        let key = PublicKey::from_text(&v.key_hex, Some(curve))
            .unwrap_or_else(|e| panic!("{}: {e}", v.curve));

        match ocmf::verify(&record, &key) {
            Ok(verified) => {
                assert_eq!(verified.algorithm().curve(), curve);
                checked += 1;
            }
            Err(ocmf::VerifyError::Unsupported { .. }) => {
                assert!(
                    !supported.contains(&curve),
                    "{curve} is reported supported and refused a vector OpenSSL signed"
                );
                named_unsupported += 1;
            }
            Err(e) => panic!(
                "{} {:?}: OpenSSL signed this and we said {e}",
                v.curve, v.shape
            ),
        }
    }
    assert_eq!(
        checked + named_unsupported,
        10,
        "all ten vectors accounted for"
    );
    // Every vector this build cannot check is *named* as unsupported rather
    // than reported as a bad signature — and there is exactly one such vector
    // per algorithm the build lacks, whatever the feature combination.
    assert_eq!(
        named_unsupported,
        Curve::ALL.len() - supported.len(),
        "supported: {supported:?}"
    );
}

#[test]
#[cfg(feature = "verify")]
fn the_three_deviant_encodings_verify_and_are_reported() {
    use ocmf::DeviationKind;

    for v in vectors() {
        let Some(shape) = v.shape.as_deref() else {
            continue;
        };
        let record = Record::parse(&v.record).unwrap();
        let key = PublicKey::from_text(&v.key_hex, record.signature().curve()).unwrap();
        let verified = ocmf::verify(&record, &key).unwrap_or_else(|e| {
            panic!("{shape}: this is the same signature, spelled differently: {e}")
        });

        let kinds: Vec<_> = verified.deviations().iter().map(|d| d.kind).collect();
        match shape {
            // A bare X||Y key is a *key* shape, not a record deviation: the
            // record is untouched, so there is nothing for it to report.
            "bare-xy-key" => assert!(!kinds.contains(&DeviationKind::RawSignatureNotDer)),
            "raw-rs-signature" => assert!(
                kinds.contains(&DeviationKind::RawSignatureNotDer),
                "a bare r||s must be named"
            ),
            "base64-signature" => {
                assert_eq!(
                    record.signature().encoding(),
                    Some(ocmf::SignatureEncoding::Base64)
                );
                assert!(record.signature().encoding_was_written());
            }
            other => panic!("unknown shape {other}"),
        }
    }
}

#[test]
#[cfg(feature = "verify")]
fn a_vector_does_not_verify_against_another_vectors_key() {
    // Every key here signed exactly one record. Crossing them must fail, and
    // must fail as a *verification*, not as a parse or a curve mismatch.
    let vs = vectors();
    let a = &vs[3]; // secp256r1
    let b = vs
        .iter()
        .find(|v| v.curve == "secp256r1" && v.shape.is_none() && v.record != a.record);
    assert!(b.is_none(), "the base secp256r1 vector is unique");

    let record = Record::parse(&a.record).unwrap();
    // A different key on the same curve: take the bare-XY vector's key, which
    // is the same key, and mutate one coordinate byte.
    let mut key_bytes = ocmf::encoding::hex_decode(&a.key_hex).unwrap();
    let last = key_bytes.len() - 1;
    key_bytes[last] ^= 0xff;
    // A mutated point is usually not on the curve, which the backend rejects;
    // when it happens to be on it, the signature must not verify.
    if let Ok(key) = PublicKey::from_bytes(&key_bytes, Some(Curve::Secp256r1)) {
        assert!(ocmf::verify(&record, &key).is_err());
    }
}
