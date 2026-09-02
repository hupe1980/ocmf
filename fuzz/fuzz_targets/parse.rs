#![no_main]
//! Parsing is total: any byte string in, a `Result` out, never a panic and
//! never an unbounded allocation.
use libfuzzer_sys::fuzz_target;
use ocmf::{Limits, Profile, Record};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    for profile in [Profile::Interop, Profile::Reference, Profile::Strict] {
        let _ = Record::parse_with(text, profile, &Limits::DEFAULT);
    }
});
