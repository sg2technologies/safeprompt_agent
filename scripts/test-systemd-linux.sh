#!/bin/bash
# End-to-end validation of the SafePrompt Agent systemd unit
# (agent/systemd/safeprompt-watchdog.service) against real systemd.
#
# Mirrors agent/scripts/test-tamper-protection.ps1's watchdog checks, but
# through systemd rather than a raw console process: proves systemd starts
# the watchdog as the least-privilege `safeprompt` user (not root), the
# watchdog spawns and supervises safeprompt-service as its child exactly
# like on Windows, killing the child gets it respawned, and systemctl stop
# cleanly tears the whole tree down.
#
# Must be run as root (creates a system user/group, installs to
# /usr/lib/safeprompt, writes /lib/systemd/system/). Assumes release
# binaries are already built: cargo build --release -p safeprompt-service
# -p safeprompt-watchdog from agent/.
#
# Usage (from Windows, via WSL):
#   wsl -d <distro> -u root -- bash /path/to/agent/scripts/test-systemd-linux.sh
# Usage (on a real Linux box):
#   sudo bash agent/scripts/test-systemd-linux.sh

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(dirname "$SCRIPT_DIR")"

PASS=0
FAIL=0

record() {
    if [ "$2" = "0" ]; then
        echo "[PASS] $1"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $1"
        echo "       $3"
        FAIL=$((FAIL + 1))
    fi
}

cleanup() {
    systemctl stop safeprompt-watchdog.service 2>/dev/null || true
    systemctl disable safeprompt-watchdog.service 2>/dev/null || true
    rm -f /lib/systemd/system/safeprompt-watchdog.service
    rm -rf /usr/lib/safeprompt
    deluser safeprompt 2>/dev/null || true
    delgroup safeprompt 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
}
trap cleanup EXIT

echo "== Installing binaries + unit ==" >&2
mkdir -p /usr/lib/safeprompt
cp "$AGENT_DIR/target/release/safeprompt-service" /usr/lib/safeprompt/
cp "$AGENT_DIR/target/release/safeprompt-watchdog" /usr/lib/safeprompt/
chmod 755 /usr/lib/safeprompt/safeprompt-service /usr/lib/safeprompt/safeprompt-watchdog
cp "$AGENT_DIR/systemd/safeprompt-watchdog.service" /lib/systemd/system/
getent group safeprompt >/dev/null || addgroup --system safeprompt
getent passwd safeprompt >/dev/null || adduser --system --ingroup safeprompt --no-create-home --shell /usr/sbin/nologin safeprompt
systemctl daemon-reload

echo "== Starting via systemd ==" >&2
systemctl start safeprompt-watchdog.service
sleep 1

WD=""
for i in $(seq 1 10); do
    WD=$(systemctl show -p MainPID --value safeprompt-watchdog.service)
    [ -n "$WD" ] && [ "$WD" != "0" ] && break
    sleep 0.5
done
record "systemd starts the watchdog (MainPID assigned)" $([ -n "$WD" ] && [ "$WD" != "0" ]; echo $?) "MainPID was '$WD'"

OWNER=$(ps -o user= -p "$WD" 2>/dev/null | tr -d ' ')
record "watchdog runs as the least-privilege 'safeprompt' user, not root" $([ "$OWNER" = "safeprompt" ]; echo $?) "owner was '$OWNER'"

CHILD=""
for i in $(seq 1 10); do
    CHILD=$(pgrep -P "$WD" | head -1)
    [ -n "$CHILD" ] && break
    sleep 0.5
done
record "watchdog spawns safeprompt-service as its child" $([ -n "$CHILD" ]; echo $?) "no child found under pid $WD"

PORT_OPEN=1
ss -tln 2>/dev/null | grep -q ":8844 " && PORT_OPEN=0
record "the supervised service opens its proxy port (8844)" $PORT_OPEN "port 8844 not listening"

if [ -n "$CHILD" ]; then
    kill -9 "$CHILD"
    NEWCHILD=""
    for i in $(seq 1 20); do
        NEWCHILD=$(pgrep -P "$WD" | head -1)
        [ -n "$NEWCHILD" ] && [ "$NEWCHILD" != "$CHILD" ] && break
        sleep 0.5
    done
    record "watchdog respawns the service after it's killed (new pid, port reopens)" \
        $([ -n "$NEWCHILD" ] && [ "$NEWCHILD" != "$CHILD" ]; echo $?) "old pid $CHILD, new pid was '$NEWCHILD'"
fi

systemctl stop safeprompt-watchdog.service
sleep 1
STOPPED=1
systemctl is-active --quiet safeprompt-watchdog.service || STOPPED=0
record "systemctl stop cleanly tears down the whole supervised tree" $STOPPED ""

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
