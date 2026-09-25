package id.jayatech.rootdetector.rules

/**
 * Pure signature-matching rules shared by the detectors.
 *
 * Everything here is plain Kotlin with NO Android dependencies, so the exact same code is
 * compiled into the library and into the host-side lab (`lab/`), where it is exercised
 * against fixtures captured from clean and rooted devices. Detectors do the I/O
 * (read /proc, run getprop/ps/pm) and hand the raw text to these functions.
 *
 * FALSE POSITIVE rule of thumb: short keywords ("ksu", "apd") must be matched as whole
 * tokens, never as substrings — "ro.boot.emmc_checksum" contains "ksu".
 */
internal object Rules {

    // -------------------------------------------------------------------------
    // Token matching
    // -------------------------------------------------------------------------

    /** True if [token] occurs in [hay] bounded by non-alphanumeric chars (or string edges). */
    fun containsToken(hay: String, token: String, ignoreCase: Boolean = true): Boolean {
        if (token.isEmpty()) return false
        var from = 0
        while (true) {
            val idx = hay.indexOf(token, from, ignoreCase)
            if (idx < 0) return false
            val before = if (idx == 0) ' ' else hay[idx - 1]
            val afterIdx = idx + token.length
            val after = if (afterIdx >= hay.length) ' ' else hay[afterIdx]
            if (!before.isLetterOrDigit() && !after.isLetterOrDigit()) return true
            from = idx + 1
        }
    }

    // -------------------------------------------------------------------------
    // /proc/version
    // -------------------------------------------------------------------------

    fun kernelSuInVersion(version: String): Boolean =
        version.contains("kernelsu", ignoreCase = true) ||
        version.contains("ksunext", ignoreCase = true) ||
        containsToken(version, "ksu")

    fun apatchInVersion(version: String): Boolean =
        version.contains("apatch", ignoreCase = true)

    // -------------------------------------------------------------------------
    // /proc/net/unix
    // -------------------------------------------------------------------------

    fun magiskSocketLines(lines: List<String>): List<String> = lines.filter { line ->
        val lower = line.lowercase().trim()
        lower.contains("@magisk") || lower.contains("/.magisk") ||
            lower.endsWith("magisk") || lower.contains("/magisk.")
    }.map { it.trim() }

    fun apatchSocketLines(lines: List<String>): List<String> = lines.filter { line ->
        line.contains("apatch", ignoreCase = true) ||
            line.contains("kpatch", ignoreCase = true) ||
            containsToken(line, "apd")
    }.map { it.trim() }

    // -------------------------------------------------------------------------
    // System properties
    // -------------------------------------------------------------------------

    private val GETPROP_LINE = Regex("""^\[(.+?)]: \[(.*)]$""")

    /** Parses `getprop` dump output ("[key]: [value]" per line). */
    fun parseGetprop(dump: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (line in dump.lineSequence()) {
            val m = GETPROP_LINE.matchEntire(line.trim()) ?: continue
            out[m.groupValues[1]] = m.groupValues[2]
        }
        return out
    }

    private val ROOT_PROP_KEYWORDS = listOf("magisk", "zygisk", "kitsune", "apatch", "kernelsu", "supersu")

    /** Props whose key or value names a root tool. Mirrors `getprop | grep -iE ...`. */
    fun rootRuntimeProps(props: Map<String, String>): List<String> =
        props.filter { (k, v) ->
            ROOT_PROP_KEYWORDS.any { k.contains(it, ignoreCase = true) || v.contains(it, ignoreCase = true) }
        }.map { (k, v) -> "[$k]: [$v]" }

    // -------------------------------------------------------------------------
    // Mounts (/proc/self/mounts format: device mountpoint fstype options ...)
    // -------------------------------------------------------------------------

    data class MountEntry(val device: String, val mountPoint: String, val fsType: String, val options: String, val raw: String)

    fun parseMounts(lines: List<String>): List<MountEntry> = lines.mapNotNull { line ->
        val p = line.trim().split(" ")
        if (p.size < 4) null else MountEntry(p[0], p[1], p[2], p[3], line.trim())
    }

    private val SYSTEM_TARGETS = listOf("/system", "/vendor", "/product", "/odm")

    private fun underSystem(mp: String) = SYSTEM_TARGETS.any { mp == it || mp.startsWith("$it/") }

    /** Overlay on a system partition whose options reference root-tool storage. */
    fun rootOverlayOnSystem(mounts: List<MountEntry>): List<String> = mounts.filter { m ->
        (m.fsType == "overlay" || m.fsType == "overlayfs") &&
            !m.mountPoint.startsWith("/apex") &&
            underSystem(m.mountPoint) &&
            (m.options.contains("/data/adb") || m.options.contains("magisk", ignoreCase = true) ||
                containsToken(m.options, "ksu") || m.device.equals("KSU", ignoreCase = true) ||
                m.device.equals("APatch", ignoreCase = true))
    }.map { it.raw }

    /**
     * /system mounted rw. On system-as-root devices /system is the root "/" mount,
     * so a rw "/" backed by a real block filesystem counts as well (rootfs/tmpfs "/" do not).
     */
    fun rwSystem(mounts: List<MountEntry>): List<String> = mounts.filter { m ->
        val rw = m.options.split(",").contains("rw")
        rw && (m.mountPoint == "/system" ||
            (m.mountPoint == "/" && m.fsType in setOf("ext4", "erofs", "f2fs", "squashfs")))
    }.map { it.raw }

    fun dataAdbMounts(mounts: List<MountEntry>): List<String> =
        mounts.filter { it.raw.contains("/data/adb") }.map { it.raw }

    fun magiskTmpfs(mounts: List<MountEntry>): List<String> = mounts.filter { m ->
        val deviceIsMagisk = m.device.equals("magisk", ignoreCase = true)
        val pathIsMagisk = m.mountPoint.contains("magisk", ignoreCase = true) || m.mountPoint.contains(".core")
        m.fsType == "tmpfs" && (deviceIsMagisk || pathIsMagisk) && !m.mountPoint.contains("libzygisk")
    }.map { it.raw }

    fun zygiskLibMount(mounts: List<MountEntry>): List<String> = mounts.filter { m ->
        m.device.equals("magisk", ignoreCase = true) && m.mountPoint.contains("libzygisk", ignoreCase = true)
    }.map { it.raw }

    fun ksuApMounts(mounts: List<MountEntry>): List<String> = mounts.filter { m ->
        m.raw.contains("/data/adb/ksu") || m.raw.contains("/data/adb/ksunext") || m.raw.contains("/data/adb/ap/") ||
            m.device.equals("KSU", ignoreCase = true) || m.device.equals("APatch", ignoreCase = true)
    }.map { it.raw }

    /**
     * /proc/self/mountinfo bind mounts sourced from root-tool storage.
     *
     * Magic-mount (Magisk / KernelSU / APatch modules) bind-mounts single files from
     * /data/adb/modules onto /system. /proc/mounts only shows the backing block device
     * (looks like any /data mount), but mountinfo's 4th column ("root" inside that
     * filesystem) reveals "/adb/modules/<id>/system/...".
     * Format: id parent maj:min root mountpoint opts [optional...] - fstype source superopts
     */
    fun mountinfoRootBinds(lines: List<String>): List<String> = lines.filter { l ->
        val f = l.trim().split(" ")
        if (f.size < 5) return@filter false
        val root = f[3]
        val mountPoint = f[4]
        val dash = f.indexOf("-")
        val source = if (dash >= 0) f.getOrNull(dash + 2).orEmpty() else ""
        val fromRootStorage = root.startsWith("/adb/modules") || root.startsWith("/adb/magisk") ||
            root.startsWith("/adb/ksu") || root.startsWith("/adb/ap/") ||
            root.startsWith("/data/adb/") ||
            source.equals("magisk", true) || source.equals("KSU", true) || source.equals("APatch", true)
        fromRootStorage && !mountPoint.startsWith("/data")
    }.map { it.trim() }

    private val DENYLIST_MARKERS = listOf(
        "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ksunext", "/data/adb/ap/",
        "/data/adb/modules", "/.magisk", "/sbin/.core", "/debug_ramdisk"
    )

    /** Root mount markers visible to init (PID 1) but hidden from our namespace. */
    fun denyListHidden(initMounts: String, selfMounts: String): List<String> =
        DENYLIST_MARKERS.filter { initMounts.contains(it) && !selfMounts.contains(it) }

    // -------------------------------------------------------------------------
    // /proc/self/maps
    // -------------------------------------------------------------------------

    private val ZYGISK_MAP_PATTERNS = listOf("zygisk", "shamiko", "rezygisk", "lspatch_loader", "zygisksu", "libzn_")
    private val XPOSED_MAP_PATTERNS = listOf("XposedBridge", "liblspd", "libedxp", "libriru", "lspatch_loader", "lspd.dex", "/lspd/")

    fun zygiskMapsLines(lines: List<String>): List<String> =
        lines.filter { l -> ZYGISK_MAP_PATTERNS.any { l.contains(it, ignoreCase = true) } }.map { it.trim() }

    fun xposedMapsLines(lines: List<String>): List<String> =
        lines.filter { l -> XPOSED_MAP_PATTERNS.any { l.contains(it) } }.map { it.trim() }

    // -------------------------------------------------------------------------
    // Process list (ps / comm / exe) — subprocess output
    // -------------------------------------------------------------------------

    private val ROOT_DAEMONS = listOf("magiskd", "magisk64", "magisk32", "ksud", "apd", "kpatch")

    /**
     * `ps -A` lines whose NAME column (last field, basename) IS a root daemon.
     * Matching tokens anywhere in the line is not enough: vendor services such as
     * "vendor.x.hardware.snap_apd@1.0-service" contain "apd" as a token.
     */
    fun rootDaemonPsLines(psOutput: String): List<String> = psOutput.lines().filter { l ->
        val name = l.trim().split(Regex("\\s+")).lastOrNull()?.substringAfterLast('/') ?: return@filter false
        ROOT_DAEMONS.any { name.equals(it, ignoreCase = true) }
    }

    /** Exact matches among /proc/<pid>/comm values. */
    fun rootDaemonComms(commOutput: String): List<String> =
        commOutput.lines().map { it.trim() }.filter { c -> ROOT_DAEMONS.any { c.equals(it, ignoreCase = true) } }.distinct()

    /** `ls -la /proc/<pid>/exe` lines whose link target is a root binary. */
    fun rootExeLines(lsOutput: String): List<String> = lsOutput.lines().filter { l ->
        if (l.isBlank()) return@filter false
        val target = l.substringAfter("->", "").trim()
        if (target.isEmpty()) return@filter false
        val base = target.substringAfterLast('/')
        target.contains("magisk", ignoreCase = true) || target.contains("kitsune", ignoreCase = true) ||
            base == "ksud" || base == "apd"
    }

    // -------------------------------------------------------------------------
    // Packages
    // -------------------------------------------------------------------------

    /** Root managers looked up in `pm list packages` subprocess output. */
    val ROOT_MANAGER_PACKAGES = listOf(
        "com.topjohnwu.magisk",
        "io.github.huskydg.magisk",
        "io.github.vvb2060.magisk",
        "io.github.huskydg.magisk.stub",
        "me.weishu.kernelsu",
        "com.rifsxd.ksunext",
        "com.sukisu.ultra",
        "me.bmax.apatch",
        "io.github.huskydg.shamiko",
        "io.github.rezygisk",
        "org.lsposed.manager",
    )

    fun rootPackagesInPmList(output: String): List<String> {
        val installed = packagesFromPmList(output)
        return ROOT_MANAGER_PACKAGES.filter { it in installed }
    }

    /** Privileged / tampering tools that do NOT prove root (reported as INFO). */
    val TOOLING_PACKAGES = linkedMapOf(
        "com.aistra.hail" to "Hail (app freezer — root/Shizuku/Dhizuku/Owner)",
        "com.catchingnow.icebox" to "Ice Box (app freezer)",
        "moe.shizuku.privileged.api" to "Shizuku (adb-level privileged API)",
        "com.rosan.dhizuku" to "Dhizuku (shared Device Owner)",
        "com.tsng.hidemyapplist" to "Hide My Applist (hides apps from other apps — needs LSPosed)",
        "org.frknkrc44.hma_oss" to "Hide My Applist OSS",
        "com.chelpus.lackypatch" to "Lucky Patcher (APK/licence tampering)",
        "bin.mt.plus" to "MT Manager (APK modding)",
        "com.gmail.heagoo.apkeditor.pro" to "APK Editor Pro",
    )

    /** Package names from `pm list packages` output. */
    fun packagesFromPmList(output: String): Set<String> =
        output.lines().map { it.trim() }.filter { it.startsWith("package:") }
            .map { it.removePrefix("package:").substringAfterLast('=') }.toSet()

    // -------------------------------------------------------------------------
    // Files in /data/local/tmp
    // -------------------------------------------------------------------------

    private val TMP_TOOL_NAMES = listOf("frida", "magisk", "ksud", "ksu", "apd", "su", "daemonsu", "objection")

    /** Name equals a tool name, or starts with it followed by a separator ("frida-server-16.5"). */
    fun isRootToolFileName(name: String): Boolean {
        val n = name.lowercase()
        return TMP_TOOL_NAMES.any { t ->
            n == t || (n.startsWith(t) && n.length > t.length && n[t.length] in "-_.") ||
                (t == "frida" && n.startsWith("frida"))
        }
    }

    // -------------------------------------------------------------------------
    // Debugging / instrumentation
    // -------------------------------------------------------------------------

    /** TracerPid from /proc/self/status (0 = not traced). */
    fun tracerPid(status: String): Int =
        status.lineSequence().firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0

    // Only Frida creates these thread names.
    private val FRIDA_THREADS = listOf("gum-js-loop", "pool-frida", "linjector", "pool-spawner")
    // GLib threads — Frida always has them, but so can any app bundling GLib/GStreamer,
    // so they are reported only alongside a Frida-specific thread.
    private val GLIB_THREADS = listOf("gmain", "gdbus")

    /** Thread names (from /proc/self/task/<tid>/comm) that belong to a Frida agent. */
    fun fridaThreadNames(names: List<String>): List<String> {
        val trimmed = names.map { it.trim() }
        val specific = trimmed.filter { n -> FRIDA_THREADS.any { n.equals(it, true) } || n.startsWith("frida", true) }
        if (specific.isEmpty()) return emptyList()
        return (specific + trimmed.filter { n -> GLIB_THREADS.any { n.equals(it, true) } }).distinct()
    }

    /** /proc/self/maps lines revealing a Frida agent/gadget, wherever it was loaded from. */
    fun fridaMapsLines(lines: List<String>): List<String> = lines.filter { l ->
        l.contains("frida-agent", true) || l.contains("frida-gadget", true) ||
            l.contains("libfrida", true) || l.contains("memfd:frida", true) || l.contains("gum-js", true)
    }.map { it.trim() }
}
