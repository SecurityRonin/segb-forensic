# 2. Ground the SEGB byte layout on the ccl-segb reference

Date: 2026-07-24
Status: Accepted

## Context

SEGB is an undocumented Apple format. There is no vendor spec for the container
framing, the record header struct, the timestamp epoch, the CRC, or the
alignment rules. Coding the layout from guesswork is exactly how inverted offsets
and wrong-endian reads ship green (fleet "Research-First" discipline: find the
authoritative reference before writing a line). Two SEGB variants exist in the
wild — v1 (older) and v2 (newer, iOS 17+) — with different header positions and
alignment, so the reader must detect and handle both.

The community reference is **ccl-segb** (Alex Caithness / CCL Solutions), the
canonical reverse-engineering of the format, itself informed by Cellebrite's v2
writeup. It is MIT-licensed and readable as a paper spec.

## Decision

Derive every structural constant and field offset **verbatim from ccl-segb**,
citing the source file and symbol at each site:

- **Endianness: little-endian throughout.** All integer/`f64` reads use LE
  helpers (`common.rs::le_i32/le_u32/le_f64`), matching ccl-segb's `struct`
  format prefixes (`"<iiddIi"`, `"<4sid16s"`, `"<2id"`).
- **SEGB v1** (`segb1.rs`): 56-byte file header with magic `b"SEGB"` at the
  **last** 4 bytes (offset 52), 32-byte per-record header (`<iiddIi`), payload
  padded to an 8-byte boundary. Constants trace to `ccl_segb1.py`
  (`HEADER_LENGTH=56`, `RECORD_HEADER_LENGTH=32`, `ALIGNMENT_BYTES_LENGTH=8`).
- **SEGB v2** (`segb2.rs`): 32-byte header with magic at **offset 0**, an
  end-of-file trailer of 16-byte entries (`<2id`), an 8-byte per-entry
  sub-header (`crc32:u32 + unknown:i32`), 4-byte alignment. Constants trace to
  `ccl_segb2.py`.
- **Variant detection by magic position** (`read_segb` in `lib.rs`): rewind to
  0, try v1 (magic at header end), then v2 (magic at header start); neither ⇒
  `SegbError::BadMagic`.
- **Timestamps**: stored as Cocoa/`CFAbsoluteTime` `f64` seconds since
  2001-01-01; converted with `+978_307_200` (`common.rs::COCOA_EPOCH_UNIX_SECS`,
  from `ccl_segb_common.py:COCOA_EPOCH`). Non-finite values decode to `None`.
- **`EntryState`**: `Written=1, Deleted=3, Unknown=4` from
  `ccl_segb_common.py:EntryState`.

Correctness is then proven against real Apple data reconciled with ccl-segb as
an independent oracle (`docs/validation.md`): 401/401 SEGB files in Josh
Hickman's public iOS 17.3 image, plus a private 785-record macOS 15.7 v2 stream.

## Consequences

- Every offset, size, and epoch in the reader is traceable to a cited reference
  line, so a reviewer can check the layout against ccl-segb without re-deriving
  it. The module doc-comments carry the full layout tables.
- The reader is only as correct as ccl-segb for edge cases neither has seen
  (very large records, rotation-truncated files); `docs/validation.md` records
  this honestly and names Apple-device ground truth as the remaining independent
  leg, since no second open-source SEGB parser exists (iLEAPP vendors ccl-segb;
  mac_apt has none).
- A v2 quirk is preserved deliberately: the 8-byte entry sub-header uses a
  native-endian `struct.unpack("Ii", …)` in ccl-segb; we read it LE to match the
  rest of the file and the observed data, and document the ambiguity in
  `segb2.rs`.
