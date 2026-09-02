#![no_main]
//! Key ingestion never panics, on any of the five shapes or on none of them.
use libfuzzer_sys::fuzz_target;
use ocmf::{Curve, PublicKey};

fuzz_target!(|data: &[u8]| {
    for hint in [None, Some(Curve::Secp256r1), Some(Curve::Secp384r1)] {
        let _ = PublicKey::from_bytes(data, hint);
        if let Ok(text) = core::str::from_utf8(data) {
            let _ = PublicKey::from_text(text, hint);
            let _ = PublicKey::from_oca(text, hint);
        }
    }
});
