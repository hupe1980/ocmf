#![no_main]
//! Whatever parses must reproduce itself byte for byte, and its signed span
//! must be exactly what the reference implementation's `split("|")[1]` yields
//! whenever no pipe hides inside a string.
use libfuzzer_sys::fuzz_target;
use ocmf::Record;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(record) = Record::parse(text) else {
        return;
    };
    assert_eq!(record.to_string(), text, "round trip must be the identity");

    let naive: Vec<&str> = text.split('|').collect();
    let payload_has_pipe = record.payload_text().contains('|');
    if !payload_has_pipe && naive.len() > 2 {
        assert_eq!(record.payload_text(), naive[1], "signed span must match the naive split");
    }
});
