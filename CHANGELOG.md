# Changelog

## [Unreleased]
- `native_inline_hook`: libc prologues in memory vs libc.so on disk — catches Frida Interceptor
  hooks regardless of name (verified on emulator API 30/34/35)
- `DetectionResult.timingsMs`: per-detector scan time
- `su -c id` execution is now opt-in (`RootDetector.suExecutionEnabled`): on rooted devices it
  popped up the root prompt and added ~2 s to every scan (measured in the lab)
- Lab: Magisk on emulator (rootAVD), Frida hook scenario, API 28–35 matrix, libFuzzer, weekly run
- Device lab: `CleanDeviceScanTest` on real stock phones via Firebase Test Lab (false-positive gate)

## [1.6.0] — Frida & Debugger Detection + False Positive Fixes

## What's New

### Debug & instrumentation detection (`DebugDetector`)
Verified on real x86_64 emulators (API 30 and 34) in CI with a real Frida 17 agent and a real JDWP debugger:
- **Frida agent threads** — `gum-js-loop`, `gmain`, `gdbus` in `/proc/self/task/*/comm`
- **Frida agent mapping** — `/memfd:frida-agent-64.so (deleted)` in `/proc/self/maps`, including frida-gadget repackaged into the APK's own lib dir (skipped by the native maps scan on purpose)
- **JDWP debugger attached** and **ptrace tracer** (`TracerPid`)

### Privileged tools as INFO (`ToolingDetector` + `RiskLevel.INFO`)
Hail, Ice Box, Shizuku, Dhizuku, Hide My Applist, Lucky Patcher, MT Manager are reported but **never make `isRooted` true** — they also work without root (Shizuku / Dhizuku / Device Owner).

### New root signals
- `/proc/self/mountinfo` — magic-mount module bind mounts (`/adb/modules/...`) invisible in `/proc/mounts`
- `pm list packages -u` — Magisk/KSU managers hidden or frozen with Hail / Ice Box are still found
- SukiSU Ultra, `/data/adb/apd`, ZygiskNext (`zygisksu`), TrickyStore, Play Integrity Fix, SUSFS module paths; rw `/` on system-as-root devices

### Root Detection Lab (`lab/`)
- **Rule lab** — library rules run against 15 device scenarios (clean Samsung/Pixel, Magisk, KernelSU Next, SUSFS, APatch, ZygiskNext/ReZygisk, LSPosed, Frida server/gadget, ptrace, Hail/Shizuku)
- **Emulator lab** — CI boots real emulators and attacks the app (renamed frida-server, Frida attach, JDWP debugger)

## Bug Fixes

- **Scan could hang forever** — `su -c id` / `getprop` read stdout before the timeout applied; a `su` waiting on a root prompt blocked the whole scan
- **Host app crash** — `scan()` only caught `Exception` (`Error`s escaped); native strings could abort the app under CheckJNI
- **Frida port probe never matched** — `/proc/net/tcp` was parsed at the wrong `:`
- Typo'd root package names in the native FD scan (`com.rnfsd.ksunext`, `com.bmax.apatch`)
- Key Attestation parse errors reported as a CRITICAL "OID stripped" bypass; malformed DER could loop forever
- libc hook check ignored hooks living in `/data/app/<pkg>/lib/`
- Broken `gradlew` ("Could not find or load main class")

### False positives removed
- `ksu` / `apd` / `kali` matched as substrings (`emmc_checksum`, `snap_apd@1.0-service`) — now whole-token only
- Native maps scan flagged the host app's own data files (e.g. `ksu_ui_cache.bin`)
- Missing gyroscope alone flagged budget phones as emulators
- `/data/local/tmp/summary.txt` matched the `su` rule
- Kernel threads (`irq/…`, `khugepaged`) reported as unknown UID-0 processes
- KernelSU list double-counted APatch / Dreamland / Pine

## Changed
- One `getprop` snapshot per scan instead of ~15 subprocesses
- Logcat output is opt-in: `RootDetector.loggingEnabled = true` (demo app enables it)
- API: `RiskLevel.INFO` (first constant), `DetectorCategory.DEBUG` / `TOOLING` — exhaustive `when` must add them

## Test Results (CI emulator lab, google_apis x86_64)

| Scenario | API 30 | API 34 |
|---|---|---|
| Baseline (no attack) | Emulator detected, no Frida/debugger false positive | Emulator detected, no Frida/debugger false positive |
| Frida 17 attached to the app | ✅ `debug_frida_threads` + `debug_frida_maps` + `native_maps` | ✅ `debug_frida_threads` + `debug_frida_maps` |
| JDWP debugger (jdb) attached | — | ✅ `debug_jdwp` |
| frida-server only (renamed, not attached) | ❌ not detected — `/proc/net/tcp` is SELinux-blocked on Android 10+ | ❌ same |
| Rule lab (15 scenarios) | ✅ 15/15 pass | |
