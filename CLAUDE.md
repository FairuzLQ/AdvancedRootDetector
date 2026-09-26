# Advanced Root Detector — CLAUDE.md

## Project Overview
Android library + demo app for detecting next-generation rooting techniques.
Package: `id.jayatech.rootdetector`
Min SDK: 26 (Android 8.0)

## Module Structure
```
Detector/
├── rootdetector/          ← Library module (distribute as AAR)
│   └── src/main/
│       ├── java/.../detector/    ← One class per root technique
│       ├── java/.../model/       ← Data models
│       ├── java/.../rules/       ← Pure signature rules (no Android deps, shared with lab)
│       └── cpp/                  ← JNI C++ native layer (signatures.h = pure native rules)
├── app/                   ← Demo app showing results (+ lab mode: JSON output)
└── lab/                   ← Detection lab (see lab/README.md)
    ├── fixtures/          ← Per-scenario /proc, mounts, getprop... captures + `expect`
    ├── host/              ← JVM harness: runs rules on fixtures → lab/REPORT.md
    ├── native/            ← Host C++ runner for signatures.h
    └── emulator/          ← Real emulator scenarios (Frida, JDWP, Magisk) for CI
```

## Detection Coverage

| Detector | What it covers |
|---|---|
| `MagiskDetector` | Magisk stable/alpha/canary, stub APK, DenyList bypass, socket, overlay mounts |
| `KernelSUDetector` | KernelSU + KernelSU Next, kernel version string, module dirs, allow-list |
| `APatchDetector` | APatch (bmax121/APatch), KPM modules, apd daemon, kernel string |
| `ZygiskDetector` | Zygisk (built-in Magisk), ZygiskNext, ReZygisk, Shamiko, NeoZygisk |
| `XposedDetector` | LSPosed, LSPatch, EdXposed, Riru, Pine, Dreamland, class-loader probe |
| `BinaryDetector` | su binary, Magisk/KSU/APatch bins, Frida server (TCP port + file) |
| `FileSystemDetector` | Root APKs in /system, writable /system, /data/adb contents |
| `PropsDetector` | test-keys, ro.debuggable, ro.secure, SELinux permissive, bootloader state |
| `MountDetector` | OverlayFS on /system, rw /system, Magisk tmpfs, mount namespace diff |
| `NativeDetector` | /proc/self/maps (native), KSU syscall 0xDEADBEEF probe, dlopen probe, libc inline-hook check (memory vs disk) |
| `IntegrityDetector` | Hardware Key Attestation (TEE/StrongBox) boot state + bypass heuristics |
| `EmulatorDetector` | Build props, emulator device nodes, cpuinfo, missing sensors |
| `DebugDetector` | JDWP debugger, ptrace TracerPid, Frida agent threads + maps (incl. repackaged gadget) |
| `ToolingDetector` | Hail, Ice Box, Shizuku, Dhizuku, HMA, Lucky Patcher… — INFO only (not root proof) |
| `AccessibilityDetector` | Third-party accessibility services (scam/dropper vector); HIGH if a remote-control app holds a11y. **Device-safety axis** |
| `RemoteAccessDetector` | Remote-control (TeamViewer, AnyDesk, RustDesk…) + screen-mirror apps installed. **Device-safety axis** |
| `NetworkDetector` | MITM: user-installed CA (HIGH), system HTTP proxy (MEDIUM), active VPN/tunnel (INFO). **Device-safety axis** |
| `NotificationListenerDetector` | Third-party notification listeners (read OTP/2FA from notifications); HIGH if a remote app. **Device-safety axis** |
| `InputMethodDetector` | Non-system keyboard/IME — active (MEDIUM, keylogger risk) vs enabled (LOW). **Device-safety axis** |
| `DangerousPermissionDetector` | Non-system apps with overlay/`SYSTEM_ALERT_WINDOW` (tapjacking) or SMS-read (OTP intercept). **Device-safety axis** |

## Key Design Decisions

- **Never crash the host app**: `RootDetector.scan()` catches `Throwable` per detector; native
  strings go through `sig::jni_safe` before `NewStringUTF`
- **Risk scoring**: CRITICAL=50pts, HIGH=30, MEDIUM=15, LOW=5, INFO=0; capped at 100.
  INFO indicators never make `isRooted` true
- **Two axes**: root/tamper (`isRooted` + `riskScore`) vs device-safety (`isDeviceAtRisk` +
  `deviceThreatScore`). The device-safety categories (`ACCESSIBILITY`, `REMOTE_ACCESS`,
  `NETWORK`, `NOTIFICATION`, `INPUT_METHOD`, `OVERLAY`, `SMS`) describe a user in danger
  (scam/MITM), not a tampered OS, so they never flip `isRooted`.
  `RootDetector.DEVICE_THREAT_CATEGORIES` is the split; `CleanDeviceScanTest` ignores them
  (it is a *root* false-positive gate). System apps are filtered by `FLAG_SYSTEM`, not a
  hand-maintained package list, to keep these low-false-positive
- **Short keywords are tokens**: "ksu", "apd", "kali" must use `Rules.containsToken` /
  `sig::contains_token`, never substring (`ro.boot.emmc_checksum` contains "ksu")
- **One getprop per scan**: `PropSnapshot` is shared by all detectors
- **Logging off by default**: `RootDetector.loggingEnabled` (demo app turns it on)
- **Native layer**: bypasses Xposed/Zygisk Java hooks; uses raw syscalls and dlopen
- **Mount namespace delta**: self vs init mount count difference > 5 → DenyList active

## Build
```bash
./gradlew :rootdetector:assembleRelease   # Build library AAR
./gradlew :app:assembleDebug             # Build demo APK
```

## Release
1. Bump `versionCode` / `versionName` in `app/build.gradle.kts` and add a `CHANGELOG.md` section
2. Push tag `vX.Y.Z` (must equal `versionName`), or push a commit whose message contains
   `[release]` (tag = `v<versionName>`) → `.github/workflows/release.yml` builds the
   release APK + library AAR and publishes a GitHub Release with notes from `CHANGELOG.md`
3. Signing: repo secrets `RELEASE_KEYSTORE_BASE64` (base64 of the .jks), `RELEASE_KEYSTORE_PASSWORD`,
   `RELEASE_KEY_ALIAS`, `RELEASE_KEY_PASSWORD`. Without them the APK is signed with a CI debug key

## Lab
```bash
gradle -p lab/host test          # rules vs fixtures (no Android SDK) → lab/REPORT.md
```
CI (`.github/workflows/lab.yml`) also runs real scenarios on x86_64 emulators (API 28/30/34/35):
baseline, renamed frida-server, Frida attach, Frida hook (inline-hook check), JDWP debugger, and
Magisk via rootAVD (default / Zygisk / Zygisk + DenyList). Plus libFuzzer over `signatures.h`
and a weekly scheduled run.

## Adding New Detectors
1. Create `XxxDetector(context, props: PropSnapshot = PropSnapshot()) : BaseDetector(context, props)` in `detector/`
2. Put text matching in `rules/Rules.kt` (Kotlin) or `cpp/signatures.h` (native) — keep it I/O-free
3. Add it to the `detectors` list in `RootDetector.kt`
4. Add a new value to `DetectorCategory` enum if needed
5. Add a fixture scenario under `lab/fixtures/` (+ a clean scenario for false positives)

## Known Limitations
- Shamiko v0.7+ with MagiskHide can fool Java-layer checks → native layer is the fallback
- KSU syscall probe only works on arm64/arm; x86 emulators will skip it
- LSPatch injected into *other* apps won't be detected (only self-check)
