#!/usr/bin/env bash
# EXPERIMENTAL: roots an AVD with rootAVD (Magisk) and runs the "magisk" scenario.
# Usage: magisk_lab.sh <app-debug.apk> <avd-name> <ramdisk path relative to $ANDROID_HOME>
set -euo pipefail
APK="$1"; AVD="$2"; RAMDISK="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"
EMU="$ANDROID_HOME/emulator/emulator"
export PATH="$ANDROID_HOME/platform-tools:$PATH"

boot() {
    nohup "$EMU" -avd "$AVD" -no-window -gpu swiftshader_indirect -no-snapshot -noaudio -no-boot-anim \
        -camera-back none >> /tmp/emulator.log 2>&1 &
    adb wait-for-device
    for _ in $(seq 1 300); do
        [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && return 0
        sleep 2
    done
    echo "emulator did not boot"; tail -50 /tmp/emulator.log; return 1
}

wait_shutdown() {
    for _ in $(seq 1 120); do
        pgrep -f "qemu-system" >/dev/null || return 0
        sleep 2
    done
    adb emu kill || true
    sleep 5
}

boot
rm -rf /tmp/rootAVD
git clone --depth 1 https://gitlab.com/newbit/rootAVD.git /tmp/rootAVD
( cd /tmp/rootAVD && ./rootAVD.sh "$RAMDISK" < /dev/null ) || true
wait_shutdown
boot
echo "== after root: id via su (may be denied for shell) =="
adb shell 'su -c id' || true
adb shell 'ls -la /debug_ramdisk /sbin 2>/dev/null | head' || true
bash "$HERE/run_scenarios.sh" "$APK" magisk
