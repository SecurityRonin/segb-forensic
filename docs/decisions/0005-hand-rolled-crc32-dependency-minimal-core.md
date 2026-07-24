# 5. Hand-roll the CRC-32; keep `segb-core` dependency-minimal

Date: 2026-07-24
Status: Accepted

## Context

SEGB records store a CRC-32 over the payload; the reader must recompute it to
expose stored-vs-computed for the analyzer's integrity check. ccl-segb uses
Python's `zlib.crc32` (the IEEE/RFC-1952 polynomial). In Rust this could be a
dependency (`crc32fast`, `crc`) or a small in-crate function.

The fleet's crypto rule ("Never hand-roll a cryptographic primitive — use a
mature audited crate") is deliberately about **cryptographic** primitives
(hashes, ciphers, KDFs) where a hand-rolled S-box is wrong and side-channel
unsafe. **CRC-32 is a non-cryptographic checksum** — a fixed, fully-specified
bit algorithm with a public reference and a trivially checkable oracle — so that
rule does not apply. What does apply is keeping `segb-core` a lean, broadly
reusable reader with the smallest possible dependency surface (only `thiserror`),
so a downstream tool that wants a Biome reader takes almost nothing transitive.

## Decision

Implement CRC-32 in-crate as `segb1.rs::crc32_of` — the standard reflected
IEEE/RFC-1952 algorithm (`0xEDB8_8320`, init/final `0xFFFF_FFFF`) — and reuse it
from the v2 reader (`segb2.rs` calls `segb1::crc32_of`). Keep `segb-core`'s only
runtime dependency `thiserror`.

Correctness is pinned to an **independent oracle** at the unit level: the
`crc32_known_value` / `crc32_empty` tests assert
`crc32_of(b"hello world") == 0x0d4a_1185` and `crc32_of(b"") == 0` — the exact
values Python's `zlib.crc32` produces (`segb1.rs` tests). The full-file
reconciliation harness (`scripts/diff_vs_ccl_segb.py`) further compares the
CRC-pass/fail verdict per record against ccl-segb.

## Consequences

- `segb-core` compiles with a single dependency; no CRC crate, no version churn,
  no license to clear beyond `thiserror`.
- The CRC is validated by a byte-exact known-answer test against `zlib`, so it is
  not a self-graded fixture — it matches the reference implementation the format
  was reverse-engineered from.
- This is a codec-adjacent hand-roll justified by (a) CRC being non-cryptographic
  and fully specified, and (b) an independent oracle proving the output; it does
  **not** license hand-rolling any actual cryptographic primitive elsewhere in
  the fleet.
