//! Validation helper: decode and dump Apple Biome `App.MenuItem` records
//! (application name + menu-item text + timestamp) from a SEGB stream.
//!
//! Where `dump_structure` reconciles the *container* (state / timestamp / CRC)
//! against `ccl-segb`, this dumps the decoded *protobuf fields* so the field
//! mapping itself — field 1 = `application`, field 2 = `menu_item` — can be
//! reconciled against the *known* menu selections driven on a real macOS Tahoe
//! system. That closes the gap neither `dump_structure` (container only) nor the
//! iOS corpus (no menu bar) can: `ccl-segb` hands back raw payload bytes, so it
//! cannot be the oracle for the protobuf interpretation — the driven selections
//! are.
//!
//! Only `Written` records carry a live payload (a `Deleted` record's payload is
//! wiped), matching the `segb-forensic` analyzer's Written-only audit.
//!
//! Usage: `cargo run -p segb-core --example dump_menuitems -- <segb-file>`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use segb::common::EntryState;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: dump_menuitems <segb-file>");
    let data = std::fs::read(&path).expect("read file");
    let mut cur = std::io::Cursor::new(data);
    let records = segb::read_segb(&mut cur).expect("parse SEGB");
    let mut decoded = 0usize;
    for (i, r) in records.iter().enumerate() {
        if r.state() != EntryState::Written {
            continue;
        }
        match segb::menuitem::decode_app_menu_item(r.payload(), r.timestamp_unix()) {
            Ok(m) => {
                println!(
                    "  [{i}] application={:?} menu_item={:?} ts_unix={:?}",
                    m.application, m.menu_item, m.timestamp_unix
                );
                decoded += 1;
            }
            Err(e) => println!("  [{i}] decode_error={e}"),
        }
    }
    println!("menu_items: {decoded}");
}
