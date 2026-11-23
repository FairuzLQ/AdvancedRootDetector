#!/usr/bin/env bash
# Real-device lab: runs the demo app's scan on a live emulator under several attack
# scenarios and stores each result as JSON in $OUT_DIR/<scenario>.json.
#
# Usage: run_scenarios.sh <app-debug.apk> [scenario ...]
# Scenarios: baseline frida_server frida_attach frida_hook jdwp_debugger magisk*
# Requires: adb on PATH, a booted emulator, python3 + frida-tools for the Frida scenarios.
set -uo pipefail

APK="$1"; shift
SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -eq 0 ] && SCENARIOS=(baseline frida_server frida_attach frida_hook jdwp_debugger)
PKG=id.jayatech.rootdetector.app
OUT_DIR="${OUT_DIR:-lab/emulator/out}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT_DIR"

log() { echo "::group::$*" 2>/dev/null || true; echo "== $*"; }
endlog() { echo "::endgroup::" 2>/dev/null || true; }

adb wait-for-device
adb install -r -g "$APK" >/dev/null

# start_app <scenario> <delay_ms>: launches a lab-mode scan writing files/<scenario>.json,
# prints the app PID. The result file is unique per scenario and deleted first, so a stale
# result can never be picked up (logcat -c is unreliable on some images).
start_app() {
    adb shell am force-stop "$PKG"
    adb shell run-as "$PKG" rm -f "files/$1.json"
    # First launch after install can be slow (dexopt); allow 90 s and re-issue the intent once.
    for attempt in 1 2; do
        adb shell am start -W -n "$PKG/.MainActivity" --es lab_out "$1.json" --el lab_delay_ms "$2" >/dev/null
        for _ in $(seq 1 45); do
            pid=$(adb shell pidof "$PKG" | tr -d '\r')
            [ -n "$pid" ] && { echo "$pid"; return 0; }
            sleep 1
        done
        echo "app did not start (attempt $attempt)" >&2
    done
    adb logcat -d -b crash | tail -20 >&2
    return 1
}

# collect <scenario>: waits for files/<scenario>.json and pulls it
collect() {
    local name="$1"
    for _ in $(seq 1 120); do
        # No `run-as <pkg> test`: run-as execs a binary and API 28 has no /system/bin/test
        # (only the shell builtin), so the check always failed there. The app writes the file
        # atomically (tmp + rename), so a readable, valid JSON file is a finished result.
        adb exec-out run-as "$PKG" cat "files/$name.json" > "$OUT_DIR/$name.json" 2>/dev/null
        if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT_DIR/$name.json" 2>/dev/null; then
            echo "saved $OUT_DIR/$name.json ($(grep -c '"id"' "$OUT_DIR/$name.json") indicators)"
            return 0
        fi
        sleep 1
    done
    echo "timeout waiting for scan in scenario $name"
    echo "app pid: '$(adb shell pidof "$PKG" | tr -d '\r')'"
    echo "files/: $(adb shell run-as "$PKG" ls -la files 2>&1 | tr -d '\r')"
    adb logcat -d -b crash | tail -40
    adb logcat -d | grep -iE "RDLAB|RootDetector|AndroidRuntime|FATAL|DEBUG" | tail -60
    echo '{"error":"timeout"}' > "$OUT_DIR/$name.json"
    return 1
}

ensure_frida_server() {
    adb root >/dev/null; adb wait-for-device
    local ver arch
    ver=$(python3 -c 'import frida; print(frida.__version__)')
    arch=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
    case "$arch" in x86_64) arch=x86_64 ;; x86) arch=x86 ;; arm64-v8a) arch=arm64 ;; *) arch=arm ;; esac
    if [ ! -f "/tmp/fs-$ver-$arch" ]; then
        curl -fsSL "https://github.com/frida/frida/releases/download/$ver/frida-server-$ver-android-$arch.xz" \
            | xz -d > "/tmp/fs-$ver-$arch"
    fi
    # Renamed on purpose — name-based file rules should NOT be what catches it.
    adb push "/tmp/fs-$ver-$arch" /data/local/tmp/fs64 >/dev/null
    adb shell chmod 755 /data/local/tmp/fs64
    # Note: `pgrep -f fs64` would match the adb shell command line itself — use exact comm.
    adb shell pkill -x fs64 2>/dev/null || true
    # -D daemonizes; redirect stdio so adb shell does not wait on the daemon's fds
    timeout 15 adb shell "/data/local/tmp/fs64 -D </dev/null >/dev/null 2>&1 &" || true
    for _ in $(seq 1 20); do
        if frida-ps -U >/dev/null 2>&1; then
            echo "frida-server $ver running: $(adb shell pidof fs64 | tr -d '\r')"
            return 0
        fi
        sleep 1
    done
    echo "frida-server did not come up"
    return 1
}

stop_frida_server() { adb shell pkill -x fs64 || true; adb shell rm -f /data/local/tmp/fs64; }

rc=0
for sc in "${SCENARIOS[@]}"; do
    log "scenario: $sc"
    case "$sc" in
        baseline|magisk*)
            start_app "$sc" 0 >/dev/null && collect "$sc" || rc=1
            ;;
        frida_server)
            ensure_frida_server || rc=1
            start_app "$sc" 0 >/dev/null && collect "$sc" || rc=1
            stop_frida_server
            ;;
        frida_attach|frida_hook)
            ensure_frida_server || rc=1
            pid=$(start_app "$sc" 20000) || { rc=1; endlog; continue; }
            python3 "$HERE/frida_attach.py" "$pid" 60 $([ "$sc" = frida_hook ] && echo hook) &
            # (frida_attach.py prints "frida: {'type': 'send', 'payload': 'attached'}" once injected)
            fpid=$!
            collect "$sc" || rc=1
            kill "$fpid" 2>/dev/null; wait "$fpid" 2>/dev/null
            stop_frida_server
            ;;
        jdwp_debugger)
            pid=$(start_app "$sc" 20000) || { rc=1; endlog; continue; }
            adb forward tcp:8700 "jdwp:$pid"
            # jdb stays attached while its stdin is open
            (sleep 60 | jdb -attach localhost:8700 >/dev/null 2>&1) &
            jpid=$!
            collect "$sc" || rc=1
            kill "$jpid" 2>/dev/null; adb forward --remove tcp:8700
            ;;
        *)
            echo "unknown scenario $sc"; rc=1 ;;
    esac
    endlog
done
exit $rc
