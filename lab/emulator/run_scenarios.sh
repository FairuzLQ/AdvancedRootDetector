#!/usr/bin/env bash
# Real-device lab: runs the demo app's scan on a live emulator under several attack
# scenarios and stores each result as JSON in $OUT_DIR/<scenario>.json.
#
# Usage: run_scenarios.sh <app-debug.apk> [scenario ...]
# Scenarios: baseline frida_server frida_attach jdwp_debugger magisk
# Requires: adb on PATH, a booted emulator, python3 + frida-tools for the Frida scenarios.
set -uo pipefail

APK="$1"; shift
SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -eq 0 ] && SCENARIOS=(baseline frida_server frida_attach jdwp_debugger)
PKG=id.jayatech.rootdetector.app
OUT_DIR="${OUT_DIR:-lab/emulator/out}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT_DIR"

log() { echo "::group::$*" 2>/dev/null || true; echo "== $*"; }
endlog() { echo "::endgroup::" 2>/dev/null || true; }

adb wait-for-device
adb install -r -g "$APK" >/dev/null

# start_app <delay_ms>: launches a lab-mode scan, prints the app PID
start_app() {
    adb shell am force-stop "$PKG"
    adb logcat -c
    adb shell am start -W -n "$PKG/.MainActivity" --es lab_out lab_result.json --el lab_delay_ms "$1" >/dev/null
    for _ in $(seq 1 30); do
        pid=$(adb shell pidof "$PKG" | tr -d '\r')
        [ -n "$pid" ] && { echo "$pid"; return 0; }
        sleep 1
    done
    return 1
}

# collect <scenario>: waits for RDLAB_DONE and pulls the JSON
collect() {
    local name="$1"
    for _ in $(seq 1 180); do
        if adb logcat -d -s RDLAB:I | grep -q RDLAB_DONE; then
            adb exec-out run-as "$PKG" cat files/lab_result.json > "$OUT_DIR/$name.json"
            echo "saved $OUT_DIR/$name.json ($(grep -c '"id"' "$OUT_DIR/$name.json") indicators)"
            return 0
        fi
        sleep 1
    done
    echo "timeout waiting for scan in scenario $name"
    adb logcat -d | tail -50
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
    adb shell "pgrep -f fs64 >/dev/null || (/data/local/tmp/fs64 -D &)"
    sleep 3
}

stop_frida_server() { adb shell pkill -f fs64 || true; adb shell rm -f /data/local/tmp/fs64; }

rc=0
for sc in "${SCENARIOS[@]}"; do
    log "scenario: $sc"
    case "$sc" in
        baseline|magisk)
            start_app 0 >/dev/null && collect "$sc" || rc=1
            ;;
        frida_server)
            ensure_frida_server
            start_app 0 >/dev/null && collect "$sc" || rc=1
            stop_frida_server
            ;;
        frida_attach)
            ensure_frida_server
            pid=$(start_app 20000) || { rc=1; endlog; continue; }
            python3 "$HERE/frida_attach.py" "$pid" 60 &
            fpid=$!
            collect "$sc" || rc=1
            kill "$fpid" 2>/dev/null; wait "$fpid" 2>/dev/null
            stop_frida_server
            ;;
        jdwp_debugger)
            pid=$(start_app 20000) || { rc=1; endlog; continue; }
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
