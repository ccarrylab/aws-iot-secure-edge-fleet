#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# check_publish_release.sh - exercise publish_release.py end to end, offline.
#
# WHY: nothing in CI ever ran the release tooling. That is how a wrong AWS CLI
# flag reached main with every check green - the workflow parsed and tested
# Python it never invoked. A --dry-run publish costs nothing, touches no AWS
# resource, and exercises argument parsing, packaging, hashing and job-document
# construction for real.
#
# It also pins the contract points that have broken in practice:
#   - packageS3Uri is derived from the SAME key the upload uses, so a custom
#     --key-prefix is honoured rather than silently replaced by "packages/"
#   - the create-job argv uses --job-executions-rollout-config, the flag
#     create-job actually accepts (--rollout-config belongs to
#     create-job-template)
#
# Usage:  bash tools/check_publish_release.sh
# Exit 0 = pass, 1 = failure. Needs bash, tar, gzip, python3.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
PUBLISH="$REPO_ROOT/publish_release.py"

if [ ! -f "$PUBLISH" ]; then
    echo "FAIL: publish_release.py not found at $PUBLISH" >&2
    exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/publish-check.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

PASS=0
FAIL=0
ok()    { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()   { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
has()   { if grep -qF -- "$2" "$3"; then ok "$1"; else bad "$1 (missing: $2)"; fi; }
lacks() { if grep -qF -- "$2" "$3"; then bad "$1 (unexpected: $2)"; else ok "$1"; fi; }

# A minimal build tree carrying one executable, as a release package would.
BUILD="$WORK/build"
mkdir -p "$BUILD/bin"
printf '#!/bin/sh\necho edge-agent\n' > "$BUILD/bin/agent"
chmod +x "$BUILD/bin/agent"
printf 'runtime config\n' > "$BUILD/etc.conf"

echo "publish_release.py checks"

# ---------------------------------------------------------------------------
# 1. --dry-run runs clean with the default key prefix.
# ---------------------------------------------------------------------------
echo "dry run, default key prefix:"
OUT="$WORK/dryrun.txt"
if python3 "$PUBLISH" --version 1.2.3 --build-dir "$BUILD" \
        --bucket example-bucket --thing-group example-fleet \
        --dry-run > "$OUT" 2>&1; then
    ok "exits 0"
else
    bad "exits 0"
    sed 's/^/       /' "$OUT"
fi

has "reports the version" "=== publishing edge-agent 1.2.3 ===" "$OUT"
has "computed a sha256" "sha256 " "$OUT"
has "packageS3Uri uses the default prefix" "s3://example-bucket/packages/1.2.3.tar.gz" "$OUT"
has "invokes create-job" "create-job" "$OUT"
has "uses the create-job rollout flag" "--job-executions-rollout-config" "$OUT"
lacks "does not use the create-job-template flag" '"--rollout-config"' "$OUT"
has "targets the thing group" "example-fleet" "$OUT"

# ---------------------------------------------------------------------------
# 2. A custom --key-prefix must reach packageS3Uri, not only the upload.
# ---------------------------------------------------------------------------
echo "dry run, custom key prefix:"
OUT2="$WORK/dryrun-prefix.txt"
python3 "$PUBLISH" --version 1.2.3 --build-dir "$BUILD" \
    --bucket example-bucket --thing-group example-fleet \
    --key-prefix "releases/" --dry-run > "$OUT2" 2>&1 || true

has "upload uses the custom prefix" "s3://example-bucket/releases/1.2.3.tar.gz" "$OUT2"
lacks "packageS3Uri does not fall back to packages/" "s3://example-bucket/packages/1.2.3.tar.gz" "$OUT2"

# ---------------------------------------------------------------------------
# 3. Input validation happens before anything is uploaded.
# ---------------------------------------------------------------------------
echo "input validation:"
OUT3="$WORK/bad-version.txt"
if python3 "$PUBLISH" --version "../../etc" --build-dir "$BUILD" \
        --bucket example-bucket --thing-group example-fleet \
        --dry-run > "$OUT3" 2>&1; then
    bad "refuses a path-traversal version"
else
    ok "refuses a path-traversal version"
fi

# ---------------------------------------------------------------------------
# 4. Packaging is deterministic: same tree in, same digest out.
# ---------------------------------------------------------------------------
echo "reproducibility:"
digest() {
    python3 "$PUBLISH" --version 1.2.3 --build-dir "$BUILD" \
        --bucket example-bucket --thing-group example-fleet --dry-run 2>/dev/null \
        | grep -m1 'sha256 ' | awk '{print $NF}'
}
S1=$(digest) || true
S2=$(digest) || true
if [ -n "$S1" ] && [ "$S1" = "$S2" ]; then
    ok "repacking the same tree yields the same digest"
else
    bad "repacking the same tree yields the same digest (got [$S1] then [$S2])"
fi

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
