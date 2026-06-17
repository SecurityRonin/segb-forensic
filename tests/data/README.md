# segb-core test data

## biome/ — real Apple Biome SEGB fixtures (regression)

Two small, benign device-telemetry SEGB streams extracted from **Joshua Hickman's
public iOS 17.3 forensic image** ([DigitalCorpora](https://digitalcorpora.s3.amazonaws.com/corpora/mobile/iOS17/iOS_17_Public_Image.tar.gz),
synthetic persona, freely licensed for training/education/testing/research). No
user content, no PII — pure hardware-setting toggles. Record counts were
reconciled exactly against the **ccl-segb** reference oracle, and the full image
(401 SEGB files, 139 v1 + 262 v2) reconciles 401/401 — see `docs/validation.md`.

| File | SEGB | Records | Stream | MD5 |
|---|---|---|---|---|
| `Device.Power.LowPowerMode.v1.segb` | v1 | 16 | `/private/var/mobile/Library/Biome/streams/restricted/Device.Power.LowPowerMode/local` | `ddc6a585844a080d2987dce683757e9c` |
| `Device.Display.TrueTone.v2.segb` | v2 | 7 | `/private/var/db/biome/streams/restricted/Device.Display.TrueTone/local` | `385ee19b06ed5efd107a8ee12e439ca1` |

Exercised by `core/tests/real_fixtures.rs`. Image provenance + MD5 of the source
tar.gz: `issen/docs/corpus-catalog.md` entry A7.

#### Device.Display.Backlight.tahoe26.v2.segb — `REAL-self` (macOS 26.5 Tahoe)

- **Identity:** a real Apple Biome **SEGB v2** stream from macOS 26.5 (build
  25F71). Its post-magic header field is `0x08` vs `0x07` on iOS 17 v2 — a
  Tahoe-era bump the v2 reader tolerates. 8 records, every CRC valid; benign
  device-display telemetry, no user content/PII.
- **Source:** read-only mount of a `macos-tahoe-base:latest` (cirruslabs, public)
  VM disk; `/private/var/db/biome/streams/restricted/Device.Display.Backlight/local/<id>`.
- **Asserted by:** `core/tests/real_fixtures.rs::real_tahoe26_segb_v2_backlight`.
