package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

/**
 * Detects APatch (KernelPatch) + KPM hide-modules (panda-hide / tphide) that defeat the static
 * artifact checks in APatchDetector.
 *
 * A well-configured APatch install is nearly invisible to userspace: the manager package is
 * hidden, /proc/version is stock, there are no /dev/kp nodes, and props are unreadable — so the
 * static checks score 0. Instead of looking for artifacts, these probes provoke the kernel hooks
 * the KPM hide modules install and catch the kernel lying. Each has an internal control for
 * ~zero false positives. Root-axis category (APATCH): a positive here does mean the OS is tampered.
 *
 * The heavy lifting is native (bypasses Java-layer hooks). This class calls nativeKpmProbe(filesDir)
 * and maps the results, plus one pure-Kotlin check (tphide's tun->zzz interface scrub).
 *
 * Verified on-device (Redmi Note 8, Android 10) with panda-hide KPM loaded: fires kpm_openat_hide
 * (CRITICAL) + kpm_tracerpid_hide (HIGH); dormant with no false positives when the KPM is absent.
 */
internal class ApatchKpmDetector(context: Context, props: PropSnapshot = PropSnapshot()) :
    BaseDetector(context, props) {

    companion object {
        private var nativeAvailable = false
        init {
            nativeAvailable = try {
                System.loadLibrary("rootdetector_native")
                true
            } catch (_: UnsatisfiedLinkError) { false }
        }
    }

    private external fun nativeKpmProbe(filesDir: String): Array<String>

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()
        findings += nativeProbes()
        detectScrubbedVpnInterface()?.let { findings += it }
        return findings
    }

    private fun nativeProbes(): List<RootIndicator> {
        if (!nativeAvailable) return emptyList()
        val dir = try { context.filesDir.absolutePath } catch (_: Exception) { return emptyList() }
        val raw = try { nativeKpmProbe(dir) } catch (_: Throwable) { return emptyList() }
        if (raw.isEmpty()) return emptyList()

        val byPrefix = raw.groupBy { it.substringBefore(':') }
            .mapValues { (_, v) -> v.map { it.substringAfter(':') } }
        val out = mutableListOf<RootIndicator>()

        // A file this app created stats OK but open()/access() returns ENOENT — impossible on a
        // clean kernel, so a kernel openat hook (panda-hide style) is hiding paths.
        byPrefix["KPM_OPENAT_HIDE"]?.takeIf { it.isNotEmpty() }?.let {
            out += RootIndicator(
                id = "kpm_openat_hide",
                category = DetectorCategory.APATCH,
                title = "Kernel openat Hook Hiding Files",
                detail = "A file this app created stats OK but cannot be opened by name — the kernel is " +
                    "intercepting openat/faccessat to hide Frida/root paths (a KPM hide module).",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // PTRACE_TRACEME returns 0 twice (a clean kernel returns EPERM on the 2nd call) — the
        // ptrace syscall is hooked to fake anti-debug self-checks (tphide KPM).
        byPrefix["KPM_PTRACE_FAKE"]?.takeIf { it.isNotEmpty() }?.let {
            out += RootIndicator(
                id = "kpm_ptrace_fake",
                category = DetectorCategory.APATCH,
                title = "ptrace Syscall Faked (Anti-Debug Hook)",
                detail = "PTRACE_TRACEME succeeds twice, so the ptrace syscall is hooked to defeat " +
                    "anti-debug checks (tphide KPM).",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // An attached tracer is scrubbed from /proc/<pid>/status|stat — kernel /proc read hook.
        byPrefix["KPM_TRACERPID_HIDE"]?.takeIf { it.isNotEmpty() }?.let {
            out += RootIndicator(
                id = "kpm_tracerpid_hide",
                category = DetectorCategory.APATCH,
                title = "TracerPid Scrubbed by Kernel",
                detail = "An actively attached tracer is hidden from /proc/<pid>/status and stat — a " +
                    "kernel read/proc hook (tphide / panda-hide debugger-hide).",
                risk = RiskLevel.HIGH,
                evidence = it
            )
        }

        // /system/bin/kp stats OK (redirected to /system/bin/sh) but open() returns ENOENT —
        // APatch sucompat su-path signature (visible to su-allowed uids).
        byPrefix["APATCH_SUPATH"]?.takeIf { it.isNotEmpty() }?.let {
            out += RootIndicator(
                id = "apatch_supath",
                category = DetectorCategory.APATCH,
                title = "APatch su-path Redirect Detected",
                detail = "The APatch sucompat hook makes the su-path stat as /system/bin/sh while open() " +
                    "returns ENOENT — a definitive APatch signature.",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }
        return out
    }

    /**
     * tphide renames tun* -> zzz* in /proc/net/dev and /proc/net/route. No legitimate interface is
     * ever named "zzz...", so any such entry proves the tphide read hook. Only shows when a
     * tun/tunl interface exists, so it is corroboration, never a sole signal. Zero false positives.
     */
    private fun detectScrubbedVpnInterface(): RootIndicator? {
        val evidence = mutableListOf<String>()
        for (path in listOf("/proc/net/dev", "/proc/net/route")) {
            try {
                java.io.File(path).readLines().forEach { line ->
                    val iface = line.substringBefore(':', "").trim()
                        .ifEmpty { line.trim().substringBefore('\t').substringBefore(' ') }
                    if (iface.startsWith("zzz")) evidence += "$path: interface '$iface'"
                }
            } catch (_: Exception) {}
        }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "kpm_zzz_iface",
            category = DetectorCategory.APATCH,
            title = "Scrubbed Network Interface (tun->zzz)",
            detail = "An interface named 'zzz*' exists — tphide renames tun* to zzz* to hide VPN/tunnel " +
                "interfaces. Impossible on a clean device.",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }
}
