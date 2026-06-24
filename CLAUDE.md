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
│       └── cpp/                  ← JNI C++ native layer
└── app/                   ← Demo app showing results
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
| `NativeDetector` | /proc/self/maps (native), KSU syscall 0xDEADBEEF probe, dlopen probe |

## Key Design Decisions

- **Never crash the host app**: each detector is wrapped in try/catch in `RootDetector.scan()`
- **Risk scoring**: CRITICAL=50pts, HIGH=30, MEDIUM=15, LOW=5; capped at 100
- **Native layer**: bypasses Xposed/Zygisk Java hooks; uses raw syscalls and dlopen
- **Mount namespace delta**: self vs init mount count difference > 5 → DenyList active

## Build
```bash
./gradlew :rootdetector:assembleRelease   # Build library AAR
./gradlew :app:assembleDebug             # Build demo APK
```

## Adding New Detectors
1. Create `XxxDetector(context) : BaseDetector(context)` in `detector/`
2. Add it to the `detectors` list in `RootDetector.kt`
3. Add a new value to `DetectorCategory` enum if needed

## Known Limitations
- Shamiko v0.7+ with MagiskHide can fool Java-layer checks → native layer is the fallback
- KSU syscall probe only works on arm64/arm; x86 emulators will skip it
- LSPatch injected into *other* apps won't be detected (only self-check)
