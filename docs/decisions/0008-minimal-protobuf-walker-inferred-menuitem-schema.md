# 8. Minimal protobuf walker; inferred App.MenuItem schema (validation pending)

Date: 2026-07-24
Status: Accepted

## Context

The `App.MenuItem` Biome stream (introduced in macOS Tahoe 26) carries a
protobuf payload per SEGB record. Apple has published no `.proto` schema. The
reader needs to surface the two meaningful text fields — the application name and
the selected menu-item text — without a full protobuf toolchain, and without
over-claiming a field mapping that has not been confirmed against a real sample.

Two honesty constraints shape this: keep `segb-core` dependency-minimal (ADR
0005 — only `thiserror`, no `prost`/`protobuf` codegen for two length-delimited
fields), and label an inferred schema as inferred rather than presenting it as
established fact (fleet Evidence-Based Rigor: mark tier-3 inference explicitly).

## Decision

1. **Hand-roll a minimal protobuf field walker** (`core/src/proto.rs`) that
   decodes the four standard protobuf wire types (varint, 64-bit,
   length-delimited, 32-bit) — of which the App.MenuItem payload uses only varint
   and length-delimited — with bounds-checked varint reads
   (`SegbError::MalformedVarint`, `ProtobufOverflow`). No dependency, no full
   protobuf runtime.
2. **Map the App.MenuItem fields as inferred** (`core/src/menuitem.rs`): field 1
   (length-delimited) = application name, field 2 = menu-item text, both UTF-8.
   The provenance is documented inline: the forensicnomicon catalog entry
   `macos_biome_app_menuitem` and the Unit 42 research article (Palo Alto
   Networks, 2026), **not** an Apple `.proto`.
3. **Record the gap loudly** in `docs/validation.md`: the App.MenuItem field
   numbering is marked "⚠️ Inferred, not confirmed from a real sample," with the
   exact reconciliation steps to close it once a real Tahoe 26 `App.MenuItem/
   local` is available.

## Consequences

- The reader decodes App.MenuItem today from the inferred mapping and is honest
  that the mapping is unconfirmed; the container framing (v1/v2) is separately
  and fully validated against real Apple data (ADR 0002).
- If a real Tahoe 26 sample shows the field order differs, only the
  `menuitem.rs` mapping changes — the container reader and the general protobuf
  walker are unaffected.
- The minimal walker is fuzzed (`fuzz/fuzz_targets/proto.rs`,
  `menuitem.rs`) so a malformed payload cannot panic even though the schema is
  provisional.
