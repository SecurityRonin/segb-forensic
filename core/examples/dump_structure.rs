//! Validation helper: dump SEGB record structure (state, timestamp, payload
//! length) — NOT payload content. Run against a real Biome SEGB file (e.g.
//! `App.MenuItem`) to reconcile `segb-core`'s container parse with the
//! `ccl-segb` reference.
//!
//! Usage: `cargo run -p segb-core --example dump_structure -- <segb-file>`
#![allow(clippy::unwrap_used, clippy::expect_used)]

fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_structure <segb-file>");
    let data = std::fs::read(&path).expect("read file");
    let mut cur = std::io::Cursor::new(data);
    let records = segb::read_segb(&mut cur).expect("parse SEGB");
    println!("records: {}", records.len());
    for (i, r) in records.iter().enumerate() {
        println!(
            "  [{i}] state={:?} ts_unix={:?} payload_len={}",
            r.state(),
            r.timestamp_unix(),
            r.payload().len()
        );
    }
}
