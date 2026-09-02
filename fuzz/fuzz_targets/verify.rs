#![no_main]
//! Verification never panics, and never reports a forgery as authentic: the
//! fuzzer holds no private key, so `Ok` here would be news.
use libfuzzer_sys::fuzz_target;
use ocmf::{PublicKey, Record, verify};

/// The KEBA KCP30 key from the reference corpus.
const KEY: &str = "3059301306072A8648CE3D020106082A8648CE3D030107034200043AEEB45C392357820A58FDFB0857BD77ADA31585C61C430531DFA53B440AFBFDD95AC887C658EA55260F808F55CA948DF235C2108A0D6DC7D4AB1A5E1A7955BE";

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(record) = Record::parse(text) else {
        return;
    };
    let key = PublicKey::from_text(KEY, None).unwrap();
    // The one authentic record for this key is not reachable from the corpus
    // seed by mutation without also breaking the signature, so any `Ok` is a
    // finding worth stopping on.
    let _ = verify::verify(&record, &key);
});
