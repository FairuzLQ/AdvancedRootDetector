# Changelog

## [1.6.1] — Real-Device False Positive Fixes + Inline Hook Detection

## What's New

### Inline hook detection (`native_inline_hook`)
The first bytes of critical libc functions (`open`, `openat`, `read`, `access`, `stat`, …) in
memory are compared with `libc.so` on disk (read through raw syscalls). Name-independent: it
catches Frida's Interceptor however the agent is named. Verified on emulators API 30/34/35 with
Frida 17 — `open()` in memory `e973…` (Frida's jump) vs disk `5541…`.

### Device lab (Firebase Test Lab)
The scan now runs on **real, stock phones** as a false-positive gate
(`CleanDeviceScanTest`, `.github/workflows/device-lab.yml`).

## Bug Fixes — false positives found on real phones
- **Samsung SC-51C (Android 16):** `ro.boot.selinux=permissive` alone was flagged CRITICAL
  "SELinux Not Enforcing" — the kernel still enforces. CRITICAL now needs
  `/sys/fs/selinux/enforce = 0`; the boot parameter alone is INFO
- **Nothing A069 (Android 16):** Key Attestation failing with an unlocked bootloader was HIGH
  "blocked by module" — it happens on stock hardware too; now INFO
- **Pixel 11 (Android 17):** a hardware-confirmed unlocked bootloader was HIGH; now MEDIUM, like
  `props_bootloader` (unlocked ≠ root)

## Performance
- `su -c id` is opt-in (`RootDetector.suExecutionEnabled`, default off): on rooted phones it
  popped up the root manager's prompt and added ~2 s to every scan
- MagiskDetector: one `pm list packages -u -f` instead of two `pm` calls (each starts a JVM,
  ~1 s on real phones), hidden-stub DEX scan limited to user APKs ≤1 MB, at most 25
  (MagiskDetector took 2–5 s on real phones)
- `DetectionResult.timingsMs`: per-detector scan time

## Lab
- Real Magisk on emulators (rootAVD), Frida hook scenario, API 28–35 matrix, libFuzzer over the
  native rules, weekly scheduled run
- API 28 "timeouts" were a lab bug, not an app hang: the result check used `run-as <pkg> test`,
  and Android 9 has no `/system/bin/test`. The scans themselves had finished correctly
- Rule lab: 17 scenarios incl. 2 captured from real Test Lab phones as regression fixtures

## Test Results

| Where | Scenario | Result |
|---|---|---|
| Emulator API 28/30/34/35 | Frida 17 attached + hook on `open()` | ✅ `native_inline_hook`, `debug_frida_threads`, `debug_frida_maps` |
| Emulator API 28/30/34/35 | JDWP debugger | ✅ `debug_jdwp` |
| Emulator API 30 | Magisk 26.4 (rootAVD) | ✅ 17 indicators |
| Emulator | Magisk + Zygisk + DenyList | ⚠️ not testable — Zygisk does not load on emulator images |
| Real phone (Test Lab) | Stock Google Pixel 11, Android 17 | ✅ no root indicator (only unlocked bootloader, MEDIUM) — scan 1.0 s |
| Real phone (Test Lab) | Stock Nothing A069, Android 16 | ✅ no root indicator (only unlocked bootloader, MEDIUM) — scan 1.7 s |
| Real phone (Test Lab) | Stock Samsung SC-51C, Android 16 | ✅ no root indicator (SELinux boot param now INFO) — scan 3.2 s |

MagiskDetector on the real phones: 0.46 s / 0.78 s / 2.2 s (was 2–5 s in 1.6.0).

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
