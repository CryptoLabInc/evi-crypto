#!/usr/bin/env bash
# Fetch EVIS v1 binary key fixtures from gs://envector-qa/evi/fixtures/evis-v1/<version>/
# and verify each file against the published sha256 manifest.
#
# Usage:
#   ./fetch.sh [-d <dest>] [-v <version>]
#
# Defaults:
#   <version> = v1
#   <dest>    = crypto/test/fixtures/evis-v1/<version>
#
# Auth: assumes the active gcloud credential (ADC or impersonated SA) has
# `roles/storage.objectViewer` on the gs://envector-qa/evi/fixtures/ prefix.
# CI workflows obtain this via GitHub OIDC -> Workload Identity Federation
# (es2-msa/es2-github-pool -> evi-fixture-reader@es2-msa.iam.gserviceaccount.com).
#
# The bucket-level IAM Condition restricts the SA to objects under the
# evi/fixtures/ prefix. `storage.objects.list` is a bucket-level operation and
# is NOT covered by an object-name condition, so this script avoids `cp -r`
# (which expands a wildcard via list) and instead reads the per-version
# manifest first, then fetches each file by exact path (objects.get).

set -euo pipefail

VERSION="v1"
DEST=""
BUCKET="gs://envector-qa/evi/fixtures/evis-v1"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dest) DEST="$2"; shift 2 ;;
        -v|--version) VERSION="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$DEST" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    DEST="$SCRIPT_DIR/$VERSION"
fi

mkdir -p "$DEST"

echo "fetch evis-v1 fixtures: $BUCKET/$VERSION/ -> $DEST"

# Step 1: fetch the manifest (single objects.get, prefix-condition compatible).
gcloud storage cp "$BUCKET/$VERSION/manifest.json" "$DEST/manifest.json" --quiet

MANIFEST="$DEST/manifest.json"
if [[ ! -f "$MANIFEST" ]]; then
    echo "manifest.json missing under $DEST" >&2
    exit 1
fi

# Step 2: parse manifest and fetch each listed file by exact name.
python3 - "$MANIFEST" "$BUCKET/$VERSION" "$DEST" <<'PY'
import json, pathlib, subprocess, sys

manifest_path, src_root, dest_root = sys.argv[1], sys.argv[2], sys.argv[3]
manifest = json.load(open(manifest_path))
dest = pathlib.Path(dest_root)

paths = sorted(manifest["files"].keys())
print(f"fetching {len(paths)} fixture file(s) from {src_root}")
for rel in paths:
    out_path = dest / rel
    out_path.parent.mkdir(parents=True, exist_ok=True)
    src = f"{src_root}/{rel}"
    subprocess.run(["gcloud", "storage", "cp", src, str(out_path), "--quiet"], check=True)
PY

echo "verify sha256 against manifest..."
python3 - "$MANIFEST" "$DEST" <<'PY'
import hashlib, json, pathlib, sys
manifest = json.load(open(sys.argv[1]))
dest = pathlib.Path(sys.argv[2])
bad = 0
for rel, meta in manifest["files"].items():
    p = dest / rel
    if not p.exists():
        print(f"MISSING: {rel}"); bad += 1; continue
    data = p.read_bytes()
    if len(data) != meta["size"]:
        print(f"SIZE MISMATCH: {rel} got={len(data)} want={meta['size']}"); bad += 1; continue
    actual = hashlib.sha256(data).hexdigest()
    if actual != meta["sha256"]:
        print(f"SHA MISMATCH: {rel} got={actual} want={meta['sha256']}"); bad += 1; continue
if bad:
    print(f"FAILED: {bad} file(s)"); sys.exit(1)
print(f"OK: {len(manifest['files'])} fixture(s) verified")
PY

echo "ready: export EVIS_V1_FIXTURE_DIR=$DEST"
