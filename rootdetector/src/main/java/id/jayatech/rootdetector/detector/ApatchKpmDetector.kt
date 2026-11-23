package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

/**
 * Detects APatch (KernelPatch) + KPM hide-modules (panda-hide / tphide) that defeat
 * the static artifact checks in APatchDetector.
 *
 * Strategy: provoke the kernel hooks and catch the kernel lying (behavioral), plus a
 * couple of impossible-artifact checks. Static props/paths/kernel-string checks all
 * MISS a well-configured APatch install (verified on Redmi Note 8, Android 10, 4.14).
 *
 * The heavy lifting is native (see native_kpm_probes.cpp). This class:
 *   - calls the new native entry nativeKpmProbe(filesDir) and maps its results, and
 *   - does one pure-Kotlin check (zzz interface) that needs no JNI.
 *
 * Register in RootDetector.scan(): add `ApatchKpmDetector(context)` to the detectors list.
 */
internal class ApatchKpmDetector(context: Context) : BaseDetector(context) {

    companion object {
        private var nativeAvailable = false
        init {
            nativeAvailable = try {
                System.loadLibrary("rootdetector_native")
                true
            } catch (_: UnsatisfiedLinkError) { false }
        }
    }

    // Add the matching JNI export in root_detector.cpp:
    //   Java_id_jayatech_rootdetector_detector_ApatchKpmDetector_nativeKpmProbe(env, obj, jstring dir)
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
        val raw = try { nativeKpmProbe(dir) } catch (_: Exception) { return emptyList() }
        if (raw.isEmpty()) return emptyList()

        val byPrefix = raw.groupBy { it.substringBefore(':') }
            .mapValues { (_, v) -> v.map { it.substringAfter(':') } }
        val out = mutableListOf<RootIndicator>()

        // Flagship: a file we created stats OK but open()/access() returns ENOENT.
        // Impossible on a clean kernel -> a kernel openat hook (panda-hide) is hiding paths.
        byPrefix["KPM_OPENAT_HIDE"]?.takeIf { it.isNotEmpty() }?.let {
            out += RootIndicator(
                id = "kpm_openat_hide",
                category = DetectorCategory.APATCH,
                title = "Kernel openat Hook Hiding Files",
                detail = "A file this app created stats OK but cannot be opened by name — " +
                         "kernel is intercepting openat/faccessat to hide Frida/root paths (KPM hide module)",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // PTRACE_TRACEME faked: returns 0 twice (clean kernels return EPERM on the 2nd call).
        byPrefix["KPM_PTRACE_FAKE"]?.takeIf { it.isNotEmpty() }?.let {
            out += RootIndicator(
                id = "kpm_ptrace_fake",
                category = DetectorCategory.APATCH,
                title = "ptrace Syscall Faked (Anti-Debug Hook)",
                detail = "PTRACE_TRACEME succeeds twice — the ptrace syscall is hooked to fake anti-debug " +
                         "self-checks (tphide KPM)",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // TracerPid / trace-stop state scrubbed while a real tracer is attached.
        byPrefix["KPM_TRACERPID_HIDE"]?.takeIf { it.isNotEmpty() }?.let {
            out += RootIndicator(
                id = "kpm_tracerpid_hide",
                category = DetectorCategory.APATCH,
                title = "TracerPid Scrubbed by Kernel",
                detail = "An attached tracer is hidden from /proc/<pid>/status|stat — kernel read/proc hook " +
                         "(tphide / panda-hide debugger-hide)",
                risk = RiskLevel.HIGH,
                evidence = it
            )
        }

        // APatch sucompat su-path redirect: stat(/system/bin/kp)=OK but open=ENOENT.
        byPrefix["APATCH_SUPATH"]?.takeIf { it.isNotEmpty() }?.let {
            out += RootIndicator(
                id = "apatch_supath",
                category = DetectorCategory.APATCH,
                title = "APatch su-path Redirect Detected",
                detail = "APatch sucompat hook makes the su-path stat as /system/bin/sh while open() returns " +
                         "ENOENT — definitive APatch signature",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }

        // Optional confirmation when a superkey was supplied to the native probe.
        byPrefix["APATCH_SUPERCALL"]?.takeIf { it.isNotEmpty() }?.let {
            out += RootIndicator(
                id = "apatch_supercall",
                category = DetectorCategory.APATCH,
                title = "KernelPatch Supercall Confirmed",
                detail = "syscall(45) returned the KernelPatch HELLO magic — APatch kernel is installed",
                risk = RiskLevel.CRITICAL,
                evidence = it
            )
        }
        return out
    }

    /**
     * tphide renames tun* -> zzz* in /proc/net/dev and /proc/net/route. No legitimate
     * interface is ever named "zzz...", so any such entry is proof of the tphide read hook.
     * Only shows when a tun/tunl interface exists (VPN up, or the standard tunl0 IPIP iface),
     * so it is corroboration, never a sole signal. Zero false positives.
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
