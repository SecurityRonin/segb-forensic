# Validation Status

## Summary

**Real-sample validation is PENDING.**

`segb-core` 0.1.0 is correct-by-construction from the ccl-segb reference
implementation. The byte layout, record framing, CRC-32 algorithm, timestamp
epoch, and alignment rules are sourced verbatim from the ccl-segb Python source.
Synthetic fixtures in the integration test suite exercise all code paths.
**No real macOS Tahoe 26 `App.MenuItem/local` sample has been tested.**

---

## What Has Been Validated

| Claim | Method | Status |
|---|---|---|
| SEGB v1 header layout (56-byte, magic at offset 52) | Traced from `ccl_segb1.py:HEADER_LENGTH=56`, `file_header[-4:] == MAGIC` | ✅ Sourced from reference |
| SEGB v1 record header struct `"<iiddIi"` (32 bytes) | Traced from `ccl_segb1.py:RECORD_HEADER_LENGTH=32`, `struct.unpack("<iiddIi", ...)` | ✅ Sourced from reference |
| SEGB v1 8-byte record alignment | Traced from `ccl_segb1.py:ALIGNMENT_BYTES_LENGTH=8` | ✅ Sourced from reference |
| SEGB v2 header layout (32-byte, magic at offset 0, struct `"<4sid16s"`) | Traced from `ccl_segb2.py:HEADER_LENGTH=32`, `struct.unpack("<4sid16s", ...)` | ✅ Sourced from reference |
| SEGB v2 trailer entry struct `"<2id"` (16 bytes) | Traced from `ccl_segb2.py:TRAILER_ENTRY_LENGTH=16`, `struct.unpack("<2id", ...)` | ✅ Sourced from reference |
| SEGB v2 entry sub-header 8 bytes: CRC32(u32) + unknown(i32) | Traced from `ccl_segb2.py:ENTRY_HEADER_LENGTH=8`, `struct.unpack("Ii", ...)` | ✅ Sourced from reference |
| SEGB v2 4-byte entry alignment | Traced from `ccl_segb2.py`: `if (remainder := trailer_entry.end_offset % 4) != 0` | ✅ Sourced from reference |
| `EntryState` values (Written=1, Deleted=3, Unknown=4) | `ccl_segb_common.py:EntryState` | ✅ Sourced from reference |
| Cocoa epoch = 2001-01-01T00:00:00Z (offset +978307200 Unix s) | `ccl_segb_common.py:COCOA_EPOCH` | ✅ Sourced from reference |
| CRC-32 = zlib/IEEE polynomial (Python `zlib.crc32`) | `ccl_segb1.py`/`ccl_segb2.py`: `zlib.crc32(data)` | ✅ Verified against Python |
| App.MenuItem protobuf field 1 = application, field 2 = menu_item | forensicnomicon catalog `macos_biome_app_menuitem` + Unit 42 article | ⚠️ Inferred, not confirmed from a real sample |
| End-to-end SEGB v1 round-trip | Synthetic byte-exact fixtures in `core/tests/segb_integration.rs` | ✅ 34 tests green |
| End-to-end SEGB v2 round-trip | Synthetic byte-exact fixtures in `core/tests/segb_integration.rs` | ✅ 34 tests green |

---

## What Is Pending

### Real macOS Tahoe 26 sample reconciliation

The Doer-Checker gap: a real `App.MenuItem/local` file from a macOS Tahoe 26
system needs to be:

1. Parsed by ccl-segb (`python ccl_segb_cli.py <file>`) to produce the
   ground-truth output.
2. Parsed by `segb-core` (`read_segb()`) to produce the Rust output.
3. Both outputs compared field-by-field: state, timestamp, payload bytes, CRC
   pass/fail, and (for App.MenuItem records) decoded application name and menu
   item text.

Until this reconciliation is done, the following claims are **unconfirmed**:

- That Apple's actual implementation matches the ccl-segb-documented layout in
  all edge cases (e.g. very large records, files with many entries, files with
  truncated data from rotation).
- That the App.MenuItem protobuf fields 1 and 2 are indeed `application` and
  `menu_item` in that order.
- That no additional required fields or header variants exist in the wild.

### How to run the reconciliation

```bash
# 1. Obtain App.MenuItem/local from a macOS Tahoe 26 system.
cp ~/Library/Biome/streams/restricted/App.MenuItem/local /tmp/local.segb

# 2. Run ccl-segb (reference oracle).
python ccl_segb_cli.py /tmp/local.segb > /tmp/ccl_segb_output.txt

# 3. Run segb-core against the same file (add a CLI binary to the workspace,
#    or write a quick test that reads the real file).

# 4. Compare timestamps, states, and payload hex between the two outputs.
```

---

## Reference Implementations

- **ccl-segb** (Alex Caithness / CCL Solutions, MIT license):
  <https://github.com/cclgroupltd/ccl-segb>
  - `ccl_segb/ccl_segb1.py` (version 0.3) — SEGB v1 layout
  - `ccl_segb/ccl_segb2.py` (version 0.4) — SEGB v2 layout
  - `ccl_segb/ccl_segb_common.py` — shared types (EntryState, Cocoa epoch)

- **Unit 42 research article** (Palo Alto Networks, 2026):
  <https://unit42.paloaltonetworks.com/new-macos-artifact-discovered/>
  — describes App.MenuItem as "SEGB-encapsulated protobuf" capturing
  `application` name and `menu_item` text per record.

- **forensicnomicon catalog** (SecurityRonin):
  `src/catalog/descriptors/macos_ext.rs`, entry `macos_biome_app_menuitem`
  — canonical field schema (`application`, `menu_item`, `timestamp`).
