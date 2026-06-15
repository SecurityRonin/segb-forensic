#!/usr/bin/env bash
#
# Reproducible macOS Tahoe `App.MenuItem` capture + reconciliation harness.
#
# Closes the Doer-Checker gap that the iOS corpus and `dump_structure` cannot:
# the App.MenuItem protobuf field mapping (field 1 = application, field 2 =
# menu_item) needs a *real macOS Tahoe* sample to confirm, because iOS has no
# menu bar and `ccl-segb` only hands back raw payload bytes (so it is the oracle
# for the container, not for the protobuf interpretation). The oracle here is the
# set of menu items this script *deliberately selects* — known ground truth.
#
# Pipeline:  provision Tahoe VM (tart)  ->  drive UI to select KNOWN menu items
#            ->  extract App.MenuItem/local  ->  reconcile (container + fields)
#            ->  teardown.
#
# tart is used (not UTM) precisely because this is meant to be repeatable/CI-able:
# a versioned image + scriptable lifecycle. For a one-off you could do the same
# steps by hand in a UTM VM.
#
# ─────────────────────────────────────────────────────────────────────────────
# THIS IS A SCAFFOLD. Three things are environment-specific and MUST be verified
# before a real run (each is marked `# VERIFY` below):
#   1. VM_IMAGE — a Tahoe (macOS 26) tart image tag that actually exists/builds.
#   2. Guest permissions — the SSH session needs Accessibility + Automation
#      (to drive menus) and Full Disk Access (to read ~/Library/Biome). Grant
#      once in System Settings > Privacy & Security, or bake into the image.
#   3. APP/MENU selections — the apps and menu items below are illustrative;
#      adjust to whatever is present and stable on your Tahoe build.
# Nothing here has been run end-to-end (no Tahoe image on hand); treat green
# output as "reconciled", red as "investigate".
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── config (override via env) ────────────────────────────────────────────────
VM_NAME="${VM_NAME:-segb-tahoe}"
VM_IMAGE="${VM_IMAGE:-ghcr.io/cirruslabs/macos-tahoe-base:latest}"   # VERIFY: tag exists
VM_USER="${VM_USER:-admin}"
VM_PASS="${VM_PASS:-admin}"                                          # cirruslabs default
OUT_DIR="${OUT_DIR:-$(pwd)/tahoe-capture}"
KEEP_VM="${KEEP_VM:-0}"                                              # 1 = leave VM running
BIOME_STREAM='Library/Biome/streams/restricted/App.MenuItem/local'
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CCL_SEGB_PATH="${CCL_SEGB_PATH:-$HOME/src/ccl-segb}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 0. prerequisites ─────────────────────────────────────────────────────────
command -v tart    >/dev/null || die "tart not found — brew install cirruslabs/cli/tart"
command -v cargo   >/dev/null || die "cargo not found"
command -v python3 >/dev/null || die "python3 not found"
[ -d "$CCL_SEGB_PATH" ] || die "ccl-segb not at $CCL_SEGB_PATH — git clone https://github.com/cclgroupltd/ccl-segb (set CCL_SEGB_PATH)"
SSHPASS=(); command -v sshpass >/dev/null && SSHPASS=(sshpass -p "$VM_PASS")
mkdir -p "$OUT_DIR"

# ── 1. provision the VM ──────────────────────────────────────────────────────
log "cloning $VM_IMAGE -> $VM_NAME"
tart list --format json 2>/dev/null | grep -q "\"$VM_NAME\"" || tart clone "$VM_IMAGE" "$VM_NAME"
log "starting $VM_NAME (headless)"
tart run "$VM_NAME" --no-graphics >/dev/null 2>&1 &
cleanup() {
  if [ "$KEEP_VM" = "1" ]; then log "KEEP_VM=1 — leaving $VM_NAME running"; return; fi
  log "stopping $VM_NAME"; tart stop "$VM_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "waiting for guest IP…"
IP=""
for _ in $(seq 1 90); do IP="$(tart ip "$VM_NAME" 2>/dev/null || true)"; [ -n "$IP" ] && break; sleep 2; done
[ -n "$IP" ] || die "VM never reported an IP"
SSH=("${SSHPASS[@]}" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${VM_USER}@${IP}")
log "guest up at $IP"
for _ in $(seq 1 30); do "${SSH[@]}" true 2>/dev/null && break; sleep 2; done

# ── 2. drive the UI to generate KNOWN menu selections (ground truth) ──────────
# App.MenuItem only populates from genuine UI interaction. This selects a fixed
# set of menu items and records each as a "<App>\t<Item>" ground-truth line.
# VERIFY: requires Accessibility + Automation permission in the guest.
log "driving menu selections in guest (ground truth)…"
"${SSH[@]}" 'cat > /tmp/drive_menus.scpt' <<'SCPT'
-- Illustrative: adjust apps/items to your Tahoe build. Each `select` line both
-- performs the click and echoes the ground-truth pair to stdout.
on pick(appName, menuName, itemName)
    tell application appName to activate
    delay 0.6
    tell application "System Events" to tell process appName
        click menu item itemName of menu menuName of menu bar 1
    end tell
    log appName & tab & itemName
    delay 0.4
end pick

pick("TextEdit", "Format", "Make Plain Text")
pick("TextEdit", "Edit", "Select All")
pick("Finder", "View", "as Icons")
SCPT
# `log` output goes to stderr; capture it as the ground truth.
"${SSH[@]}" 'osascript /tmp/drive_menus.scpt 2>&1 1>/dev/null' > "$OUT_DIR/ground_truth.tsv" || \
  die "UI driving failed — check Accessibility/Automation permission in the guest"
log "ground truth:"; sed 's/^/    /' "$OUT_DIR/ground_truth.tsv"

# Give Biome a moment to flush the stream to disk.
sleep 5

# ── 3. extract the Biome stream ──────────────────────────────────────────────
# VERIFY: reading ~/Library/Biome needs Full Disk Access (or SIP disabled).
log "extracting $BIOME_STREAM"
"${SSH[@]}" "cat ~/$BIOME_STREAM" > "$OUT_DIR/App.MenuItem.local" \
  || die "could not read Biome stream — grant Full Disk Access to the SSH/Terminal in the guest"
[ -s "$OUT_DIR/App.MenuItem.local" ] || die "extracted stream is empty"
log "captured $(wc -c < "$OUT_DIR/App.MenuItem.local") bytes -> $OUT_DIR/App.MenuItem.local"

# ── 4a. container reconciliation: segb-core vs ccl-segb (existing harness) ────
log "container reconciliation (state / timestamp / CRC) vs ccl-segb"
python3 "$REPO_ROOT/scripts/diff_vs_ccl_segb.py" "$OUT_DIR/App.MenuItem.local"

# ── 4b. field reconciliation: segb-core decode vs the driven ground truth ─────
log "field reconciliation (application / menu_item) vs driven selections"
cargo run -q -p segb-core --example dump_menuitems -- "$OUT_DIR/App.MenuItem.local" \
  > "$OUT_DIR/ours_menuitems.txt"
sed 's/^/    /' "$OUT_DIR/ours_menuitems.txt"
python3 - "$OUT_DIR/ours_menuitems.txt" "$OUT_DIR/ground_truth.tsv" <<'PY'
import re, sys
ours_path, truth_path = sys.argv[1], sys.argv[2]
# segb-core line: [i] application=Some("Finder") menu_item=Some("as Icons") ts_unix=Some(...)
pair = re.compile(r'application=Some\("(?P<app>(?:[^"\\]|\\.)*)"\).*?menu_item=Some\("(?P<item>(?:[^"\\]|\\.)*)"\)')
ours = {(m["app"], m["item"]) for m in (pair.search(l) for l in open(ours_path)) if m}
truth = set()
for l in open(truth_path):
    l = l.rstrip("\n")
    if "\t" in l:
        a, i = l.split("\t", 1); truth.add((a.strip(), i.strip()))
missing = truth - ours      # driven but not decoded → field mapping / decode gap
extra   = ours - truth      # decoded but not driven → background menu activity (often benign)
print(f"    driven={len(truth)} decoded(written)={len(ours)} matched={len(truth & ours)}")
for a, i in sorted(missing): print(f"    MISSING (driven, not decoded): {a!r} -> {i!r}")
for a, i in sorted(extra):   print(f"    extra  (decoded, not driven): {a!r} -> {i!r}")
# A driven selection that segb-core fails to surface is a real field-mapping
# failure; `extra` is informational (the OS records its own menu use too).
sys.exit(1 if missing else 0)
PY

log "DONE — capture at $OUT_DIR; both reconciliations passed (see output above)."
