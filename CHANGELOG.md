# Changelog

## [1.9.2] — Device-relative signer trust (OEM-app false-positive fix)

### Fix: first-party OEM apps flagged as overlay/SMS threats
On a clean Samsung A51, preinstalled apps delivered under `/data` (Samsung Browser, Voice Recorder,
Samsung Members) lack `FLAG_SYSTEM`, so the `FLAG_SYSTEM` filter missed them and they were reported
as MEDIUM "Apps Can Draw Over Other Apps" — a false positive. Fixed with **`SignerTrust`**: an app is
treated as first-party if its signing certificate matches that of **any `FLAG_SYSTEM` package on this
device** (no hardcoded cert list — works on any brand; verified that `com.sec.android.app.sbrowser`
shares signer `34df0e7a…` with the platform `android` package, while AnyDesk does not).

A capable first-party app is now reported as **INFO** (`overlay_firstparty_apps`,
`sms_reader_firstparty_apps`) — the capability is still shown for transparency, but a device-signed
app is not a threat. Genuinely third-party apps keep their real level: on the same device AnyDesk
stays MEDIUM (`remote_control_apps`) and a real third-party overlay app (Krom Staging) stays MEDIUM
(`overlay_capable_apps`). Root score unaffected (device-safety axis only).

## [1.9.1] — Hidden-Magisk (repackaged stub) detection + Android-10 crash fix

### New: catch a hidden/repackaged root manager (`magisk_hidden_stub`, `magisk_masquerade`)
"Hide the Magisk app" repackages the manager under a random, fully-obfuscated package (e.g.
`mp.douxd`, label "Settings"), and with DenyList the app's `/sbin` mounts are stripped from the
denylisted process's namespace — so the package, file, mount, socket and `su` checks all see
**nothing** (verified on-device: a fully-hidden Magisk dropped the scan from 19 Magisk indicators
to 0). The existing stub checks miss it because the label is custom and the DEX has no
`com.topjohnwu.magisk` strings. Two obfuscation-proof signals are added (permissions and the
visible label cannot be stripped by repackaging and survive DenyList):

- **`magisk_hidden_stub`** (CRITICAL) — a non-system app requesting the self-installing root-manager
  permission trio `REQUEST_INSTALL_PACKAGES` + `UPDATE_PACKAGES_WITHOUT_USER_ACTION` +
  `HIDE_OVERLAY_WINDOWS`. The stub downloads/installs the full manager and hides overlays during the
  superuser prompt; this exact trio is not requested by normal apps or even app stores (which never
  `HIDE_OVERLAY_WINDOWS`). Caught the obfuscated `mp.douxd` stub on-device.
- **`magisk_masquerade`** (HIGH) — a non-system app whose visible label is a core system label
  (Settings/Magisk/KernelSU/APatch) **and** which can install packages. The installer-permission
  requirement keeps the false-positive rate low.

Verified: fires on the hidden stub (emulator); **no false positive** on a real phone with banking /
store / keyboard apps installed.

### Fix: native scan crashed (SIGSEGV) on Android-10 execute-only memory
`check_inline_hooks` compared the first bytes of libc functions in memory vs on disk via
`memcpy(mem, sym, 16)`. On Android 10+ those `.text` pages are **execute-only (XOM, `--x`)**, so the
read faults with `SIGSEGV`/`SEGV_ACCERR` and the **entire native scan dies before completing** —
reproduced 5/5 on a real Redmi Note 8 (Android 10). The page is now made temporarily readable with
`mprotect` before the read (and the function skipped if that fails). Crash rate 5/5 → **0/5**, scan
completes. This affected every Android-10 device with XOM libc, not just this one.

## [1.9.0] — APatch + KPM Behavioral Detection

### New: catch kernel-level root hiding that static checks miss (`ApatchKpmDetector`)
A well-configured APatch (KernelPatch) install is nearly invisible to userspace. On a real
Redmi Note 8 (ginkgo, Android 10) the manager package is hidden, `/proc/version` is stock, there
is no `/dev/kp` node and the props are unreadable, so **every static APatch/KPM artifact check
produced zero indicators** and `isRooted()` returned false — the device looked clean. Instead of
looking for artifacts, these probes provoke the kernel hooks the KPM hide modules (panda-hide /
tphide) install and catch the kernel lying. Each probe carries its own control for ~zero false
positives and reports on the root axis (`DetectorCategory.APATCH`):

- **openat/faccessat honeypot** (`kpm_openat_hide`, CRITICAL) — a file this app creates via
  `rename` (not hooked) stats OK but `open()`/`access()` returns `ENOENT`. Impossible on a clean
  kernel: the `openat` hook that hides Frida/root paths is lying. A benign-named control file must
  open first, so the probe stays silent on a clean device.
- **PTRACE_TRACEME idempotency** (`kpm_ptrace_fake`, CRITICAL) — a clean kernel returns `EPERM`
  on the second `PTRACE_TRACEME`; tphide returns 0 twice. Run in a throwaway child and flagged
  only when both calls succeed, so an attached real debugger does not false-positive.
- **self-trace TracerPid / stat consistency** (`kpm_tracerpid_hide`, HIGH) — `PTRACE_ATTACH` a
  forked child; if the attach succeeds but the child's `/proc/<pid>/status` TracerPid reads 0 or
  its stat state is not `t`, the kernel is scrubbing ptrace evidence. Only evaluated when the
  attach truly succeeds (no Yama ptrace_scope false-positive).
- **APatch sucompat su-path divergence** (`apatch_supath`, CRITICAL) — `/system/bin/kp` stats OK
  (the sucompat hook redirects it to `/system/bin/sh` for su-allowed uids) while `open()` returns
  `ENOENT`. A unique APatch signature; silent for apps that were not granted root.
- **tphide interface scrub** (`kpm_zzz_iface`, HIGH) — tphide renames `tun*` to `zzz*` in
  `/proc/net/dev` and `/proc/net/route`; no legitimate interface is ever named `zzz*`.

The heavy lifting is native (new JNI `nativeKpmProbe(filesDir)`), so it bypasses Java-layer hooks.
These are root-axis signals: a positive here does mean the OS is tampered. `isRooted`/`riskScore`
keep their exact meaning; the device-safety axis from 1.7/1.8 is unchanged.

### Verified on-device (real Redmi Note 8, ginkgo, Android 10, APatch + panda-hide KPM)
With the panda-hide KPM loaded the scan goes from **2 indicators / score 45** (bootloader +
hardware attestation only — APatch otherwise invisible to an unprivileged app) to **4 / 100**,
firing `kpm_openat_hide` (CRITICAL) and `kpm_tracerpid_hide` (HIGH). With the KPM unloaded, on a
clean (unrooted) boot, and under Magisk, the new probes stay **silent — no false positive**. No
crash.

| Device state | score | APatch/KPM detected |
|---|---|---|
| Clean (unrooted, unlocked bootloader) | 45 | no (correct, no false positive) |
| APatch core only (KPM unloaded, app not granted root) | 45 | only via hardware attestation |
| APatch + panda-hide KPM loaded | 100 | yes — `kpm_openat_hide` + `kpm_tracerpid_hide` |
| Magisk (manager app visible) | 100 | yes — `magisk_pkg` |

## [1.8.0] — Runtime Screen Guard + Device-Admin Detection

### Bug fix — demo app crashed when its screen was torn down mid-scan
Rotating the phone or relaunching the app during a scan destroyed the activity, whose
`executor.shutdownNow()` interrupted the scan thread's progress `Thread.sleep` — the uncaught
`InterruptedException` killed the process. The scan thread now stops quietly. This was also the
cause of the intermittent "baseline timeout" in the emulator lab (first launch is relaunched).

### `DeviceSafetyGuard` — runtime protection for the live screen (new public API)
`RootDetector.scan()` reports what is installed/enabled; the guard protects a sensitive screen
(login, PIN, transfer confirmation, OTP) *while it is in use*:

- `protectFromOverlays(view)` + `classifyTouch(event)` — tapjacking defence: touches that arrive
  while another app's window covers yours are dropped, and can be reported (FULL / PARTIAL).
- `secureWindow(activity)` — `FLAG_SECURE`: no screenshots, screen recording, remote-control
  capture or casting of that window.
- `registerScreenCaptureListener(activity) { … }` — API 34+ screenshot callback (host declares
  the normal permission `DETECT_SCREEN_CAPTURE`; otherwise a safe no-op returning null).
- `mirroringDisplays(context)` — public presentation displays (Cast / Miracast / HDMI mirroring).
  The scan also reports this as `screen_mirroring_active` (REMOTE_ACCESS, MEDIUM).

The demo app uses the overlay filter and the screenshot listener.

### `DeviceAdminDetector` — device-admin / device-owner abuse (device-safety axis)
A non-system app holding device-administrator rights can lock or wipe the phone and cannot be
uninstalled until the right is revoked — the mechanism behind screen-locker ransomware and
stalkerware. Reports third-party active admins (MEDIUM), and escalates a non-system Device
Owner or a remote-control app with admin rights to HIGH. System MDM/"find my device" apps are
filtered by `FLAG_SYSTEM`. Permission-free; never flips `isRooted`.

## [1.7.0] — Device-Safety Detection

### New: device-safety detection (scam / remote-takeover / MITM) — a second axis
Detection is no longer only about "is the OS tampered by an attacker"; it now also flags a
**normal user in danger**, without any new permission and without ever flipping `isRooted`:

- **`AccessibilityDetector`** — a third-party Accessibility service (can read the screen and
  tap for you) is the #1 scam vector. Stock screen readers, Switch Access and password-manager
  autofill are filtered out; a remote-control app holding accessibility is escalated to HIGH.
- **`RemoteAccessDetector`** — remote-control (TeamViewer, AnyDesk, RustDesk, AirDroid…) and
  screen-mirroring apps installed. The "install AnyDesk so I can help you" refund/bank scam.
- **`NetworkDetector`** (MITM) — user-installed CA certificate (HIGH, the classic HTTPS
  interception setup), system HTTP proxy (MEDIUM), active VPN/tunnel (INFO).

More on-device scam vectors, same axis:

- **`NotificationListenerDetector`** — a third-party notification listener reads the text of
  every notification, including banking OTPs and 2FA codes (MEDIUM; HIGH if a remote-control app).
- **`InputMethodDetector`** — a non-system keyboard sees every keystroke. Active keyboard =
  MEDIUM (keylogger risk); merely enabled = LOW.
- **`DangerousPermissionDetector`** — non-system apps with overlay (`SYSTEM_ALERT_WINDOW`,
  tapjacking / fake-login overlays, MEDIUM) or SMS-read (OTP interception, LOW).

System vs third-party is decided by `FLAG_SYSTEM`, not a package list, so stock keyboards /
launchers / dialers do not false-positive. All permission-free. Instrumentation/test-harness
packages (Firebase Test Lab, Espresso) are excluded from the package scans so they are not
mistaken for a real overlay/SMS app.

Verified on real phones (Firebase Test Lab): stock Google Pixel 11, Nothing A069 and Samsung
SC-51C show **no** device-safety indicator; scan 1.1 / 1.9 / 3.2 s (device-safety detectors
add ~40–170 ms total).

New result fields `DetectionResult.isDeviceAtRisk` and `deviceThreatScore` carry this second
axis; `isRooted`/`riskScore` keep their exact old meaning (root/tamper only).

### Lab — Magisk detection is now a real gate (was report-only)
The three emulator Magisk scenarios (plain, +Zygisk, +Zygisk +DenyList) now assert the
indicators that must fire, so a regression that silently breaks Magisk detection fails the
check instead of passing quietly. The DenyList (hiding) scenario specifically asserts the
signals that survive Magisk's own hiding — the su binary via a raw `SYS_newfstatat` syscall
(`native_su_bin`) and the module bind-mounts left in `mountinfo` (`mount_module_bind`) —
which the Java/package layer cannot see once DenyList is enforced.

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
