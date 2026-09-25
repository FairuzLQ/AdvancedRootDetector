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
    timeout 300 adb wait-for-device || { echo "no adb device"; tail -80 /tmp/emulator.log; return 1; }
    for _ in $(seq 1 150); do
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

echo "== [1/4] first boot"
boot
echo "== [2/4] rootAVD (Magisk) patching $RAMDISK"
rm -rf /tmp/rootAVD
git clone --depth 1 https://gitlab.com/newbit/rootAVD.git /tmp/rootAVD
# `yes ""` answers any interactive prompt with the default; hard 10 min cap.
( cd /tmp/rootAVD && yes "" | timeout 600 ./rootAVD.sh "$RAMDISK" ) || echo "rootAVD exited with $?"
echo "== [3/4] waiting for AVD shutdown"
wait_shutdown
echo "== [4/4] cold boot with patched ramdisk"
boot
echo "== after root: id via su (may be denied for shell) =="
adb shell 'su -c id' || true
adb shell 'ls -la /debug_ramdisk /sbin 2>/dev/null | head' || true
rc=0
bash "$HERE/run_scenarios.sh" "$APK" magisk || rc=1

# Magisk's own hiding: enable Zygisk (+ reboot), then enforce the DenyList for our app.
# `adb root` gives a uid-0 shell on google_apis images, so the magisk CLI can be used directly.
PKG=id.jayatech.rootdetector.app
magisk_cli() { adb root >/dev/null 2>&1; adb wait-for-device; adb shell "magisk $*"; }

echo "== enable Zygisk and reboot"
magisk_cli --sqlite "\"REPLACE INTO settings (key,value) VALUES('zygisk',1)\""
adb reboot; sleep 5
timeout 300 adb wait-for-device
for _ in $(seq 1 150); do
    [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
    sleep 2
done
magisk_cli --sqlite "\"SELECT key,value FROM settings\"" || true
bash "$HERE/run_scenarios.sh" "$APK" magisk_zygisk || rc=1

echo "== enforce DenyList for $PKG"
magisk_cli --denylist enable
magisk_cli --denylist add "$PKG"
magisk_cli --denylist ls || true
bash "$HERE/run_scenarios.sh" "$APK" magisk_zygisk_denylist || rc=1
exit $rc
