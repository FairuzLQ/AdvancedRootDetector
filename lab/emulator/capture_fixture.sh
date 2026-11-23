#!/usr/bin/env bash
# Captures a lab fixture from a connected device into lab/fixtures/<name>/.
# Usage: capture_fixture.sh <name>
#
# Per-app files (maps, status, fd, task comm, mounts) are read via `run-as` from the
# DEBUG demo app so they reflect an app process (DenyList / namespace applies to it —
# start the app first). System-wide files are read from the adb shell.
set -uo pipefail
NAME="$1"; PKG="${PKG:-id.jayatech.rootdetector.app}"
DIR="$(cd "$(dirname "$0")/.." && pwd)/fixtures/$NAME"
mkdir -p "$DIR"
sh()  { adb shell "$@" 2>/dev/null | tr -d '\r'; }
app() { adb shell run-as "$PKG" sh -c "'$*'" 2>/dev/null | tr -d '\r'; }

pid=$(sh pidof "$PKG")
[ -z "$pid" ] && { echo "start $PKG on the device first"; exit 1; }

sh cat /proc/version            > "$DIR/proc_version"
sh getprop                      > "$DIR/getprop"
sh cat /proc/net/unix           > "$DIR/net_unix"
sh cat /proc/net/tcp            > "$DIR/net_tcp"
sh ps -A                        > "$DIR/ps"
sh 'cat /proc/[0-9]*/comm'      > "$DIR/comm"
sh 'ls -la /proc/*/exe'         > "$DIR/exe_ls"
sh pm list packages -u          > "$DIR/pm_list"
sh ls /data/local/tmp           > "$DIR/tmp_ls"
app "cat /proc/$pid/maps"       > "$DIR/maps"
app "cat /proc/$pid/status"     > "$DIR/status"
app "cat /proc/$pid/mounts"     > "$DIR/mounts"
app "cat /proc/$pid/mountinfo"  > "$DIR/mountinfo"
app "cat /proc/1/mounts"        > "$DIR/mounts_init"
app "cat /proc/$pid/task/*/comm" > "$DIR/task_comm"
app "for f in /proc/$pid/fd/*; do readlink \$f; done" > "$DIR/fd_links"
# Drop empty captures (not readable on this Android version)
find "$DIR" -type f -empty -delete
[ -f "$DIR/expect" ] || printf '# TODO: add must/mustnot/clean directives\n' > "$DIR/expect"
echo "captured into $DIR — edit $DIR/expect, add a README, then run: gradle -p lab/host test"
