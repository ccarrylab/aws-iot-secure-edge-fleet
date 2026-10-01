#!/bin/sh
# ---------------------------------------------------------------------------
# ota-boot-guard.sh — local rollback guard for the Secure Edge Fleet agent.
#
# WHY THIS EXISTS: the agent's own rollback logic cannot help when the release
# that fails IS the agent (or anything it needs to start). In that case the
# process never reaches its health check, nothing reports FAILED to the job,
# and the device boot-loops on the broken build. This script runs BEFORE the
# application, uses nothing but /bin/sh and two small files, and needs no
# network — so it can undo an activation that the application never confirmed.
#
# Install: /usr/local/bin/ota-boot-guard.sh   (chmod 0755)
# Wire it up as ExecStartPre= in edge-agent.service.
# ---------------------------------------------------------------------------
set -eu

STATE_DIR=${OTA_STATE_DIR:-/var/lib/edge-agent}
PENDING="$STATE_DIR/pending"
BOOT_COUNT="$STATE_DIR/boot_count"
MAX_UNCONFIRMED_BOOTS=3

[ -f "$PENDING" ] || exit 0        # nothing pending, nothing to do

mkdir -p "$STATE_DIR"
count=$(cat "$BOOT_COUNT" 2>/dev/null || echo 0)
count=$((count + 1))
echo "$count" > "$BOOT_COUNT"

if [ "$count" -ge "$MAX_UNCONFIRMED_BOOTS" ]; then
    previous=$(cat "$PENDING")
    echo "ota-boot-guard: $count unconfirmed boots - rolling back to $previous" \
        >> "$STATE_DIR/rollback.log" 2>/dev/null || true

    if [ -d "$STATE_DIR/packages/$previous" ]; then
        # Atomic symlink swap: a partially written link is worse than none,
        # because the device then starts nothing at all.
        tmp_link="$STATE_DIR/packages/.current.rollback.$$"
        ln -s "$STATE_DIR/packages/$previous" "$tmp_link"
        mv -Tf "$tmp_link" "$STATE_DIR/packages/current"
        echo "ota-boot-guard: $(date -u +%FT%TZ) rolled back to $previous" \
            >> "$STATE_DIR/rollback.log" 2>/dev/null || true
    else
        echo "ota-boot-guard: rollback target $previous missing" \
            >> "$STATE_DIR/rollback.log" 2>/dev/null || true
    fi

    # pending.json belongs to the activation we just undid; leaving it behind
    # would make the agent believe a confirmation is still owed for a version
    # that is no longer current.
    rm -f "$PENDING" "$BOOT_COUNT" "$STATE_DIR/pending.json"
fi

exit 0
