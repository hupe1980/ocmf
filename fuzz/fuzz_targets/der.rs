#![no_main]
//! The lenient DER reader never panics, and anything it reads it re-encodes to
//! the same scalars.
use libfuzzer_sys::fuzz_target;
use ocmf::der;

fuzz_target!(|data: &[u8]| {
    if let Some(sig) = der::read_ecdsa_signature(data) {
        let reencoded = der::write_ecdsa_signature(&sig.r, &sig.s);
        let again = der::read_ecdsa_signature(&reencoded).expect("our own output reads back");
        assert_eq!(again.r, sig.r);
        assert_eq!(again.s, sig.s);
        assert!(again.canonical, "the writer emits canonical DER");
    }
    let _ = der::read_spki(data);
});
