# 9. Low CI-verified MSRV floor, distinct from the dev toolchain pin

Date: 2026-07-24
Status: Accepted

## Context

The fleet separates the **dev toolchain** (what contributors build/fmt/clippy
with) from the **declared MSRV** (`rust-version` — a downstream-facing promise).
`segb-core` is a published library that third parties may link, so a low,
CI-verified MSRV is a deliberate compatibility feature, not something to raise
casually (fleet "Rust MSRV & Toolchain Policy"; a raised library MSRV narrows its
crates.io audience). The dev toolchain, by contrast, tracks the current stable so
the whole fleet ends fmt/clippy drift.

## Decision

- **Dev toolchain**: pin `rust-toolchain.toml` to the current fleet stable
  (`channel = "1.96.0"`, commit `6e021c4`) with `clippy`/`rustfmt` components
  declared in the toml (single source of truth).
- **Declared MSRV**: `rust-version = "1.81"` in `[workspace.package]`
  (`Cargo.toml`), inherited by both `segb-core` and `segb-forensic`. This is the
  low floor a downstream consumer is promised — well below the 1.96 dev pin — and
  is CI-verified in a dedicated low-MSRV job.

## Consequences

- `segb-core` stays consumable by older toolchains as a general Biome reader; the
  1.96 dev pin never leaks into the promise.
- Because both members inherit one `rust-version`, the analyzer shares the
  reader's floor. Should `segb-forensic` ever need a newer-Rust feature via
  `forensicnomicon`, the split lets the floor move for the analyzer without
  dragging `segb-core` up — not required today.
- **Rationale for the exact `1.81` value** (vs the fleet's more common
  `1.75`/`1.80` floors) is reconstructed from structure: it is the low
  CI-verified floor the crates currently build against, tracking the effective
  minimum of the dependency graph (`thiserror` 2, `forensicnomicon` 1). The
  original intent behind choosing `1.81` specifically over `1.80` is not
  recovered in available history; the *decision to keep a low floor distinct from
  the dev pin* is the load-bearing, grounded part.
