# 4. Paranoid Gatekeeper — forbid(unsafe), panic-free, fuzzed

Date: 2026-07-24
Status: Accepted

## Context

SEGB files are untrusted, attacker-controllable input: a Biome stream can be
pulled from a compromised device or a hostile image. A length field that lies, a
truncated record, a trailer entry that overruns the file, or a 10-byte protobuf
varint must never crash the tool or, worse, drive an out-of-bounds read or an
allocation bomb. A forensic reader that panics on a crafted artifact is a denial
of service on the investigation. This is the fleet Security & Robustness Standard
("Paranoid Gatekeeper") applied to a new format.

## Decision

Enforce a panic-free posture both statically and dynamically.

**Static** (`Cargo.toml` `[workspace.lints]`, inherited by both members):

- `unsafe_code = "forbid"` — no `unsafe` anywhere; the reader is pure Rust with
  no C bindings, so the fleet's mmap `deny`+bounded-allow exception is not
  needed.
- `clippy::unwrap_used` / `expect_used` = `deny` in production; tests opt out via
  `#![cfg_attr(test, allow(…))]` and `clippy.toml` (`allow-unwrap-in-tests`).
- `correctness`/`suspicious` = `deny`, `all`/`pedantic` = `warn`.

**Bounds-checked reads.** Every fixed-width field goes through
`common.rs::le_i32/le_u32/le_f64`, which return `0` (or `NaN` for `f64`) when the
slice is short rather than panicking. Every length, offset, entry count, trailer
size, and varint from the file is range-checked before use, and malformed input
surfaces as a typed `SegbError` variant (`error.rs`: `TruncatedPayload`,
`InvalidLength`, `InvalidEntryCount`, `TrailerOverflow`, `MalformedVarint`,
`ProtobufOverflow`, …), never a silent default.

**Dynamic.** `cargo-fuzz` targets cover every parsed structure — `segb1`,
`segb2`, `proto`, `menuitem`, and a `forensic` target driving the full
`read_segb` → `audit` pipeline (`fuzz/fuzz_targets/`) — with the invariant "must
not panic." CI runs them on nightly (`cargo +nightly fuzz`, since `+nightly`
beats the `rust-toolchain.toml` pin — commit `bf2c70a`).

## Consequences

- Malformed evidence degrades to a typed error or a partial record list, never a
  crash or a wrong value. The README leads with the measured claim ("fuzzed") and
  qualifies the static half ("panic-free-by-construction"), per fleet robustness
  wording (commit `a34ab50`).
- The `unsafe`-forbidden badge is honest: the workspace genuinely forbids
  `unsafe`, unlike the mmap crates that carry bounded allows.
- Bounds-checked helpers are slightly more verbose than raw slice indexing; that
  is the intended cost.
