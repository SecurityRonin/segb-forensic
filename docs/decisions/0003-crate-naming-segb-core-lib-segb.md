# 3. Crate naming — publish `segb-core`, import as `segb`

Date: 2026-07-24
Status: Accepted

## Context

The fleet Crate naming grammar (`ronin-issen/CLAUDE.md`) fixes two names per
single-format repo: `<x>-core` (reader) and `<x>-forensic` (analyzer). Here
`<x>` = `segb`. Two constraints pull in opposite directions:

1. A crate name is read **bare** on crates.io — in search, `cargo add`, and
   dependency lists — with all repo/GitHub context stripped, so the published
   name must be self-describing.
2. The import path callers type should be short and natural (`use segb::…`), not
   a suffixed mouthful.

## Decision

Publish the reader as package **`segb-core`** with **`[lib] name = "segb"`**
(`core/Cargo.toml`):

```toml
[package]
name = "segb-core"
[lib]
name = "segb"
```

- **Package `segb-core`** self-describes on crates.io as "the core of the
  `segb-forensic` suite," per the grammar's self-describing rule.
- **Lib name `segb`** keeps the ergonomic import (`use segb::{read_segb, …}`;
  `menuitem::decode_app_menu_item`), so consumer code and the workspace
  dependency alias (`segb = { version = "0.2", path = "core", package =
  "segb-core" }` in the root `Cargo.toml`) read cleanly.
- The analyzer stays **`segb-forensic`** (the repo/headline name), the
  Pattern-A single-format shape.

## Consequences

- Consumers write `segb-forensic = "…"` or `segb-core = "…"` on crates.io but
  `use segb::…` in code — the split name never leaks into call sites.
- The workspace and the analyzer both refer to the reader via the `segb` alias,
  so a future rename of the package would touch only the alias line, not every
  `use`.
- `segb-forensic` (the workspace's own name) and `segb-core` are distinct
  crates.io names, so neither collides with the other at publish.
