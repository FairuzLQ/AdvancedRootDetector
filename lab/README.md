# Root Detection Lab

Two layers, both run in GitHub Actions (`.github/workflows/lab.yml`):

| Layer | What runs | Where | Speed |
|---|---|---|---|
| **Rule lab** (`host/`, `native/`) | The library's pure rules (`rules/Rules.kt`, `cpp/signatures.h`) against fixture captures of clean + rooted devices | Any JVM, no Android SDK | seconds |
| **Emulator lab** (`emulator/`) | The real demo app scan on a live x86_64 emulator while real attacks run | GitHub Actions (KVM) | ~15 min |

## Rule lab

```bash
gradle -p lab/host test     # builds lab/native with clang++, writes lab/REPORT.md
```

Each directory in `fixtures/` is one scenario. Files are raw captures (all optional):

| File | Source on device |
|---|---|
| `proc_version` | `/proc/version` |
| `getprop` | `getprop` |
| `mounts`, `mounts_init`, `mountinfo` | `/proc/self/mounts`, `/proc/1/mounts`, `/proc/self/mountinfo` |
| `maps`, `status`, `task_comm`, `fd_links` | `/proc/self/maps`, `/proc/self/status`, `/proc/self/task/*/comm`, `readlink /proc/self/fd/*` |
| `net_unix`, `net_tcp` | `/proc/net/unix`, `/proc/net/tcp` |
| `ps`, `comm`, `exe_ls`, `proc_status` | `ps -A`, `/proc/*/comm`, `ls -la /proc/*/exe`, `/proc/*/status` (blocks separated by `----`) |
| `pm_list`, `tmp_ls` | `pm list packages -u`, `ls /data/local/tmp` |

`expect` directives: `clean`, `noroot` (only INFO rules), `must <id>`, `mustnot <id>`,
`gap <text>` (documented blind spot — shown in the report, not asserted).

**The fixtures shipped here are reconstructions** of what each tool leaves behind, based on
the public behaviour of the tools and on the on-device lines already documented in the
detectors (e.g. the Redmi 5 / Magisk 28.1 zygisk mounts). Replace/extend them with real
captures: `emulator/capture_fixture.sh` pulls a scenario directory from a device.

## Emulator lab

`emulator/run_scenarios.sh <apk> [scenario...]` on any booted emulator/device with `adb`:

| Scenario | What is real |
|---|---|
| `baseline` | Stock `google_apis` emulator (userdebug, emulator props) |
| `frida_server` | Official frida-server, renamed to `fs64`, running as root |
| `frida_attach` | frida-server + Python client attached to the app process (agent injected) |
| `frida_hook` | Frida attached **and** an Interceptor hook on libc `open()` — verifies the inline-hook check |
| `jdwp_debugger` | `jdb` attached over JDWP |
| `magisk` | AVD rooted with [rootAVD](https://gitlab.com/newbit/rootAVD) + Magisk, default config |
| `magisk_zygisk` | Same, Zygisk enabled (app not on the DenyList) |
| `magisk_zygisk_denylist` | Same, Zygisk + DenyList enforced for the app — what survives Magisk's own hiding |

Emulator scenarios run on API 28, 30, 34 and 35 (Magisk on API 30). Each result JSON carries
per-detector scan times (`timingsMs`), shown in the job summary.

`fuzz-native` runs libFuzzer (ASan + UBSan) over `signatures.h` for 90 s per CI run, seeded
with the fixtures. The whole lab also runs weekly (schedule) to catch new Frida / Magisk
releases that break a detection.

Results are JSON (`emulator/out/*.json`), checked by `check.py` against
`expectations.json`, and rendered into the Actions job summary.

### Not reproducible in CI

KernelSU / KernelSU Next / SukiSU / APatch need a patched kernel, and LSPosed / Shamiko /
ZygiskNext / TrickyStore / SUSFS need Magisk or KSU plus a manual module install. Those stay
covered by fixtures until someone captures them from a real device with
`emulator/capture_fixture.sh`.
