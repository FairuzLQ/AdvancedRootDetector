# Changelog

## [1.6.0] — 2026-09-25

### Fixed
- **Scan could hang forever**: `su -c id` and `getprop` read stdout before the timeout
  applied — a `su` waiting on a root prompt blocked the whole scan. All subprocesses now
  run through a timeout-safe helper.
- **Host app crash**: `scan()` only caught `Exception`; `Error`s (e.g. `LinkageError`)
  escaped. Native evidence strings are sanitised before `NewStringUTF` (CheckJNI abort)
  and JNI local refs are released.
- **Frida port probe never matched**: `/proc/net/tcp` was parsed at the wrong `:`.
- Typo'd root package names in the native FD scan (`com.rnfsd.ksunext`, `com.bmax.apatch`…).
- Key Attestation parser errors were reported as a CRITICAL "OID stripped" bypass;
  malformed DER lengths could loop forever.
- libc interposition check ignored hooks living in `/data/app/<pkg>/lib/`.
- Broken `gradlew` ("Could not find or load main class") — wrapper regenerated.

### False positives removed
- `ksu` / `apd` / `kali` matched as substrings (`emmc_checksum`, `snap_apd@1.0-service`…)
  — now whole-token matches only.
- Native maps scan flagged the host app's own data files (e.g. `ksu_ui_cache.bin`).
- Missing gyroscope alone flagged budget phones as emulators.
- `/data/local/tmp/summary.txt` matched the `su` rule.
- Kernel threads (`irq/…`, `khugepaged`) reported as unknown UID-0 processes.
- KernelSU list double-counted APatch / Dreamland / Pine packages.

### Added
- `DebugDetector`: JDWP debugger, ptrace `TracerPid`, Frida agent threads, frida-gadget
  repackaged into the APK.
- `ToolingDetector` + `RiskLevel.INFO`: Hail, Ice Box, Shizuku, Dhizuku, Hide My Applist,
  Lucky Patcher, MT Manager — reported, but never make `isRooted` true.
- `/proc/self/mountinfo` rule for magic-mount module bind mounts.
- `pm list packages -u`: root managers hidden/frozen with Hail / Ice Box are still found.
- SukiSU Ultra, `/data/adb/apd`, ZygiskNext (`zygisksu`), TrickyStore, Play Integrity Fix,
  SUSFS module paths; rw `/` on system-as-root devices.
- Root Detection Lab (`lab/`): rule lab on fixtures + real emulator scenarios in CI.

### Changed
- One `getprop` snapshot per scan instead of ~15 subprocesses.
- Logcat output is opt-in: `RootDetector.loggingEnabled = true` (the demo app enables it).
- API: `RiskLevel` gained `INFO` (first constant) and `DetectorCategory` gained `DEBUG`
  and `TOOLING` — exhaustive `when` expressions over these enums must add the new cases.
