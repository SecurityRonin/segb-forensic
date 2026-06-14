**Panic-free reader for Apple SEGB container files (Biome streams) — decodes SEGB v1 and v2 records with state, timestamps, and protobuf payload; includes App.MenuItem field walker.**

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## 30-second start

```toml
[dependencies]
segb-core = "0.1"
```

```rust
use std::fs::File;
use std::io::BufReader;
use segb::{read_segb, menuitem::decode_app_menu_item};

let f = File::open("/path/to/App.MenuItem/local")?;
let mut r = BufReader::new(f);
for record in read_segb(&mut r)? {
    let item = decode_app_menu_item(record.payload(), record.timestamp_unix())?;
    println!("{:?} selected {:?}", item.application, item.menu_item);
}
```

## What it parses

The `App.MenuItem` Biome stream (`~/Library/Biome/streams/restricted/App.MenuItem/local`),
introduced in macOS Tahoe 26, captures every menu item the user selected — e.g.
`"Finder"` / `"Move to Trash"`, `"TextEdit"` / `"Save..."` — with a timestamp.
The file is SEGB-encapsulated protobuf and requires specific tooling; most
commercial forensic suites do not parse it.

This library handles the SEGB container layer (both v1 and v2) and provides a
minimal protobuf field walker for the `App.MenuItem` payload.

## SEGB variant support

| Variant | Magic location | Header | Alignment |
|---------|---------------|--------|-----------|
| SEGB v1 | Last 4 bytes of 56-byte header | 56 bytes | 8 bytes |
| SEGB v2 | First 4 bytes of 32-byte header | 32 bytes | 4 bytes |

`read_segb()` detects the variant automatically.

## Validation status

Real-sample validation is **pending** — see [`docs/validation.md`](docs/validation.md).
The byte layout is sourced from the ccl-segb reference implementation
(<https://github.com/cclgroupltd/ccl-segb>) by Alex Caithness / CCL Solutions.

## References

- ccl-segb: <https://github.com/cclgroupltd/ccl-segb>
- Unit 42 research: <https://unit42.paloaltonetworks.com/new-macos-artifact-discovered/>

---

[Privacy Policy](https://securityronin.github.io/segb-core/privacy/) · [Terms of Service](https://securityronin.github.io/segb-core/terms/) · © 2026 Security Ronin Ltd
