package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

/**
 * JNI bridge to native C++ detection.
 *
 * Native layer bypasses Java-level hooks because:
 *  - Xposed/LSPosed can only hook Java methods and libc PLT/GOT entries
 *  - Direct Linux syscalls (SYS_openat, SYS_getuid, etc.) cannot be hooked in userspace
 *  - dl_iterate_phdr operates on the linker's internal state, not Java-visible state
 *
 * Each result is prefixed to indicate the detection type:
 *   MAPS:        — suspicious .so path in /proc/self/maps
 *   ANON_RWX:    — anonymous executable memory region (injected shellcode)
 *   GHOST_LIB:   — .so in maps but NOT registered with linker (manual mmap injection)
 *   KSU_SYSCALL: — KernelSU kernel hook responded to syscall 0xDEADBEEF
 *   APATCH_DEV:  — APatch /dev/kp or /dev/apatch device node present
 *   LOADED_LIB:  — root library already loaded (dlopen RTLD_NOLOAD hit)
 *   ROOT_SYMBOL: — known root framework symbol found via dlsym
 *   CAPABILITY:  — CapEff != 0 (process has elevated Linux capabilities)
 *   UID_ZERO:    — process runs as UID 0 (root) per kernel
 *   UID_HOOK:    — getuid() libc and SYS_getuid disagree (libc is hooked)
 *   FILE_HIDE:   — root path hidden by libc hook but visible via direct syscall
 *   FUNC_HOOK:   — libc function owned by non-system library (interposition)
 *   FD:          — open file descriptor pointing to root daemon
 *   UNIX_SOCKET: — root daemon socket in /proc/net/unix
 */
internal class NativeDetector(context: Context) : BaseDetector(context) {

    companion object {
        private var nativeAvailable = false
        init {
            nativeAvailable = try {
                System.loadLibrary("rootdetector_native")
                true
            } catch (_: UnsatisfiedLinkError) { false }
        }
    }

    private external fun nativeScan(): Array<String>
    private external fun nativeProbeKernelSU(): Boolean

    override fun detect(): List<RootIndicator> {
        if (!nativeAvailable) return emptyList()
        val rawResults = try { nativeScan() } catch (_: Exception) { emptyArray() }
        if (rawResults.isEmpty()) return emptyList()

        val byPrefix = rawResults.groupBy { it.substringBefore(':') }
            .mapValues { (_, v) -> v.map { it.substringAfter(':') } }

        val findings = mutableListOf<RootIndicator>()

        // Suspicious .so files in process maps (system paths already filtered in C++)
        byPrefix["MAPS"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_maps",
                category = DetectorCategory.NATIVE,
                title = "[Native] Root Libraries in Process Maps",
                detail = "Root/hook .so files found in /proc/self/maps — system paths pre-filtered",
                risk = RiskLevel.CRITICAL,
                evidence = it.take(6)
            )
        }

        // Anonymous RWX pages (injected shellcode)
        byPrefix["ANON_RWX"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_anon_rwx",
                category = DetectorCategory.NATIVE,
                title = "[Native] Anonymous Executable Memory",
                detail = "Large anonymous rwx mappings — likely injected code (not ART JIT)",
                risk = RiskLevel.HIGH,
                evidence = it
            )
        }

        // Ghost libraries (manually mmap'd, bypass linker)
        byPrefix["GHOST_LIB"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_ghost",
                category = DetectorCategory.NATIVE,
                title = "[Native] Ghost Library (Linker Bypass)",
                detail = ".so in process maps but not registered with linker — manually injected",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // KernelSU syscall probe
        byPrefix["KSU_SYSCALL"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_ksu_syscall",
                category = DetectorCategory.NATIVE,
                title = "[Native] KernelSU Syscall Probe Positive",
                detail = "Syscall 0xDEADBEEF responded without SIGSYS — KernelSU kernel hook active",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // APatch device node
        byPrefix["APATCH_DEV"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_apatch",
                category = DetectorCategory.NATIVE,
                title = "[Native] APatch Kernel Device Found",
                detail = "/dev/kp or /dev/apatch present — APatch kernel patcher active",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // Root libs loaded in process
        byPrefix["LOADED_LIB"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_loaded_lib",
                category = DetectorCategory.NATIVE,
                title = "[Native] Root Library Loaded in Process",
                detail = "Known root/hook library is already in process memory (RTLD_NOLOAD hit)",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // Known root framework symbols
        byPrefix["ROOT_SYMBOL"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_symbols",
                category = DetectorCategory.NATIVE,
                title = "[Native] Root Framework Symbol Found",
                detail = "Xposed/Zygisk/Riru-specific exported symbol found via dlsym",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // Elevated Linux capabilities
        byPrefix["CAPABILITY"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_capability",
                category = DetectorCategory.NATIVE,
                title = "[Native] Elevated Linux Capabilities",
                detail = "CapEff is non-zero — process received root-level capabilities. No stock app has this.",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // Process running as UID 0
        byPrefix["UID_ZERO"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_uid_zero",
                category = DetectorCategory.NATIVE,
                title = "[Native] Process Runs as Root (UID=0)",
                detail = "Direct kernel syscall confirms process UID is 0",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // getuid() hook — libc lies about UID
        byPrefix["UID_HOOK"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_uid_hook",
                category = DetectorCategory.NATIVE,
                title = "[Native] getuid() Is Hooked",
                detail = "libc getuid() and SYS_getuid syscall return different UIDs — libc is patched",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // File hiding (libc hides paths that kernel can still see)
        byPrefix["FILE_HIDE"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_file_hide",
                category = DetectorCategory.NATIVE,
                title = "[Native] Root Paths Hidden by Libc Hook",
                detail = "open() via libc returns ENOENT but direct SYS_openat sees the file — active hiding",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // Function interposition (LD_PRELOAD / RTLD_INTERPOSE)
        byPrefix["FUNC_HOOK"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_func_hook",
                category = DetectorCategory.NATIVE,
                title = "[Native] Libc Function Interposed",
                detail = "Critical libc function is owned by a non-system library — LD_PRELOAD or RTLD_INTERPOSE",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // Open FD pointing to root daemon
        byPrefix["FD"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_fd",
                category = DetectorCategory.NATIVE,
                title = "[Native] FD Connected to Root Daemon",
                detail = "Open file descriptor resolves to a root daemon path or device",
                risk = RiskLevel.CRITICAL,
                evidence = it.take(6)
            )
        }

        // Unix sockets
        byPrefix["UNIX_SOCKET"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_sockets",
                category = DetectorCategory.NATIVE,
                title = "[Native] Root Daemon Sockets",
                detail = "Root daemon UNIX sockets found in /proc/net/unix",
                risk = RiskLevel.HIGH,
                evidence = it.take(4)
            )
        }

        // Frida port 27042 — catches standalone frida-server even when binary is renamed
        byPrefix["FRIDA_PORT"]?.takeIf { it.isNotEmpty() }?.let {
            findings += RootIndicator(
                id = "native_frida_port",
                category = DetectorCategory.NATIVE,
                title = "[Native] Frida Server Port Open",
                detail = "TCP port 27042 is active — frida-server running (binary may be renamed to evade file-based detection)",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        return findings
    }
}
