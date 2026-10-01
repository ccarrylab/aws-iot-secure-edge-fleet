#!/bin/sh
# ---------------------------------------------------------------------------
# t_ota_boot_guard.sh - contract tests for deploy/ota-boot-guard.sh
#
# The guard is the only component whose failure is unrecoverable in the field:
# it runs BEFORE the agent, with no network, to undo an activation that never
# confirmed. It was previously covered only indirectly, by the Python
# BootGuard class that writes the files it reads. This suite exercises the
# script itself.
#
# It asserts the CONTRACT between agent.py and the guard:
#   - "pending" holds the PREVIOUS version, verbatim (agent.py writes it
#     with write_text(), so no trailing newline)
#   - "boot_count" counts unconfirmed boots, incremented once per run
#   - rollback fires at exactly MAX_UNCONFIRMED_BOOTS (3)
#   - "current" still resolves to a real directory after a rollback
#   - state files are cleared once a rollback has happened
#   - with no "pending" file the guard is a no-op
#
# Usage:  sh device-agent/tests/t_ota_boot_guard.sh [path-to-guard]
# Exit 0 = pass, 1 = failure.
# ---------------------------------------------------------------------------
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
GUARD=${1:-"$HERE/../deploy/ota-boot-guard.sh"}

if [ ! -f "$GUARD" ]; then
    echo "FAIL: guard not found at $GUARD" >&2
    exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/boot-guard-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

PASS=0
FAIL=0

ok()    { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()   { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
check() { # check <description> <expected> <actual>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected [$2], got [$3])"; fi
}

# Fresh state dir: two installed releases, current -> the newer one, which is
# the state left behind by an activation that has not been confirmed.
reset_state() {
    SD="$WORK/state"
    rm -rf "$SD"
    mkdir -p "$SD/packages/1.0.0" "$SD/packages/1.1.0"
    echo "known good" > "$SD/packages/1.0.0/app.py"
    echo "never confirmed" > "$SD/packages/1.1.0/app.py"
    ln -s "$SD/packages/1.1.0" "$SD/packages/current"
}

run_guard() { OTA_STATE_DIR="$SD" sh "$GUARD" >/dev/null 2>&1; }

echo "ota-boot-guard.sh contract tests"
echo "  guard: $GUARD"

# ---------------------------------------------------------------------------
echo "no pending file (nothing to undo):"
reset_state
run_guard
check "exit status 0" "0" "$?"
check "current untouched" "$SD/packages/1.1.0" "$(readlink "$SD/packages/current")"
check "no boot_count written" "no" "$([ -e "$SD/boot_count" ] && echo yes || echo no)"

# ---------------------------------------------------------------------------
echo "first unconfirmed boot:"
reset_state
printf '1.0.0' > "$SD/pending"
run_guard
check "count is 1" "1" "$(cat "$SD/boot_count")"
check "no rollback yet" "$SD/packages/1.1.0" "$(readlink "$SD/packages/current")"
check "pending retained" "yes" "$([ -f "$SD/pending" ] && echo yes || echo no)"

# ---------------------------------------------------------------------------
echo "second unconfirmed boot:"
run_guard
check "count is 2" "2" "$(cat "$SD/boot_count")"
check "still no rollback" "$SD/packages/1.1.0" "$(readlink "$SD/packages/current")"

# ---------------------------------------------------------------------------
echo "third unconfirmed boot (threshold):"
run_guard
check "rolled back to previous" "$SD/packages/1.0.0" "$(readlink "$SD/packages/current")"
check "current resolves to a real dir" "yes" "$([ -d "$SD/packages/current" ] && echo yes || echo no)"
check "pending cleared" "no" "$([ -e "$SD/pending" ] && echo yes || echo no)"
check "boot_count cleared" "no" "$([ -e "$SD/boot_count" ] && echo yes || echo no)"
check "rollback.log written" "yes" "$([ -s "$SD/rollback.log" ] && echo yes || echo no)"

# ---------------------------------------------------------------------------
echo "no newline in pending (exact format agent.py writes):"
reset_state
printf '1.0.0' > "$SD/pending"
printf '2' > "$SD/boot_count"
run_guard
check "reaches threshold and rolls back" "$SD/packages/1.0.0" "$(readlink "$SD/packages/current")"

# ---------------------------------------------------------------------------
echo "rollback target missing:"
reset_state
printf '9.9.9' > "$SD/pending"
printf '2' > "$SD/boot_count"
run_guard
check "current left alone" "$SD/packages/1.1.0" "$(readlink "$SD/packages/current")"
check "state cleared anyway" "no" "$([ -e "$SD/pending" ] && echo yes || echo no)"
check "failure recorded" "yes" "$(grep -q 'missing' "$SD/rollback.log" && echo yes || echo no)"

# ---------------------------------------------------------------------------
echo "corrupt boot_count:"
reset_state
printf '1.0.0' > "$SD/pending"
printf 'garbage' > "$SD/boot_count"
run_guard
check "survives a non-numeric count" "0" "$?"

# ---------------------------------------------------------------------------
echo "repeated runs are idempotent once rolled back:"
reset_state
printf '1.0.0' > "$SD/pending"
printf '2' > "$SD/boot_count"
run_guard
run_guard
check "still on the previous release" "$SD/packages/1.0.0" "$(readlink "$SD/packages/current")"
check "state stays clear" "no" "$([ -e "$SD/pending" ] && echo yes || echo no)"

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
