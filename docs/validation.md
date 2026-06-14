# Validation Status

## Summary

**The SEGB v2 container is validated against real Apple Biome data + the
ccl-segb reference. The App.MenuItem protobuf field mapping is still PENDING
(needs a macOS Tahoe 26 sample).**

`segb-core` is correct-by-construction from the ccl-segb reference (byte layout,
record framing, CRC-32, timestamp epoch, alignment sourced verbatim), and its
**SEGB v2 reader now reconciles exactly with ccl-segb on a real Apple Biome
stream** (see below). What remains unconfirmed is only the App.MenuItem
*protobuf* field numbering, which requires a real `App.MenuItem/local` from
macOS Tahoe 26 (the stream does not exist on earlier macOS).

### Public iOS-17 reconciliation — 401/401, both variants (2026-06-14)

The strongest validation: **Josh Hickman's public iOS 17.3 image** (DigitalCorpora,
CC for research) contains real Apple Biome SEGB streams. segb-core was run against
**every** SEGB file in it and reconciled against the ccl-segb reference oracle:

| | count | segb-core vs ccl-segb |
|---|---|---|
| SEGB **v1** files | 139 | record counts match |
| SEGB **v2** files | 262 | record counts match |
| **Total** | **401** | **401 PASS / 0 MISMATCH** |

Streams covered include `_DKEvent.Safari.History`, `_DKEvent.Device.BatteryPercentage`,
`MicroLocationVisit`, `Siri.SelfTriggerSuppression`, DuetActivityScheduler
app-launch/kill, `unifiedMessageStream`, etc. This validates **both** the v1 and v2
container readers against real Apple data, publicly and reproducibly (provenance +
MD5 in `issen/docs/corpus-catalog.md` entry A7). Note: the biome stream dirs unzip
with restrictive Apple modes (0700) — `chmod -R u+rwX` before scanning.

### Private macOS-15.7 reconciliation (2026-06-14)

A real Biome SEGB v2 stream from a macOS 15.7 (Sequoia) host —
`~/Library/Biome/streams/restricted/Lighthouse.Ledger.TaskTelemetry/local/...`,
a benign system-telemetry stream — was parsed by **both** ccl-segb (oracle) and
`segb-core`, and the container parse matched **exactly**:

| Field | ccl-segb (oracle) | segb-core | Match |
|---|---|---|---|
| Record count | 785 | 785 | ✅ |
| Record states | all `Written` | all `Written` | ✅ |
| First timestamp | `2026-05-30 02:58:20.870580` | `1780109900.870580` (= same UTC instant) | ✅ |

This is a genuine, independent-oracle validation of the v2 container, record
framing, state decoding, and Cocoa→Unix timestamp conversion against real Apple
data — not synthetic fixtures. The sample is the host owner's private data and is
**not** committed (Biome streams are user-private; `tests/data/` is gitignored).
The `dump_structure` example reproduces the run on any SEGB file.

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
| **SEGB v2 container on REAL Apple Biome data** | **785-record telemetry stream reconciled with ccl-segb: count, states, timestamps all match** | ✅ **Real-data validated (2026-06-14)** |

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
