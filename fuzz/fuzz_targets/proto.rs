#![no_main]
//! Protobuf varint / field walker over arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for field in segb::proto::iter_fields(data) {
        // Drain the iterator; each yielded field (or error) must not panic.
        let _ = field;
    }
    let _ = segb::proto::as_str(data);
});
