package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

internal class MagiskDetector(context: Context, props: PropSnapshot = PropSnapshot()) : BaseDetector(context, props) {

    private val magiskPackages = listOf(
        "com.topjohnwu.magisk",
        "com.topjohnwu.magisk.stub",
        "io.github.huskydg.magisk",           // Magisk Alpha (HuskyDG fork)
        "io.github.vvb2060.magisk",            // Magisk Alpha (vvb2060 fork)
        "io.github.huskydg.magisk.stub",
        "io.github.vvb2060.magisk.stub",
        "io.github.huskydg.shamiko",
        "com.github.topjohnwu.magisk",
    )

    private val magiskPaths = listOf(
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/magisk.img",
        "/data/adb/modules",
        "/data/adb/post-fs-data.d",
        "/data/adb/service.d",
        "/sbin/.magisk",
        "/sbin/.core/mirror",
        "/.magisk",
        "/debug_ramdisk/.magisk",
        "/data/adb/magisk_simple",
        "/dev/socket/zygisk",
        "/dev/socket/zygisk_0",
        "/dev/.magisk.unblock",
    )

    private val magiskBinaries = listOf(
        "/sbin/magisk",
        "/sbin/magiskinit",
        "/data/adb/magisk/magisk32",
        "/data/adb/magisk/magisk64",
        "/data/adb/magisk/magiskinit",
        "/data/adb/magisk/magiskpolicy",
        "/debug_ramdisk/magisk",
    )

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()

        // 1. Package detection — high specificity, very low FP chance
        val foundPkgs = magiskPackages.filter { isPackageInstalled(it) }
        if (foundPkgs.isNotEmpty()) {
            findings += RootIndicator(
                id = "magisk_pkg",
                category = DetectorCategory.MAGISK,
                title = "Magisk App Installed",
                detail = "Magisk manager or known variant found",
                risk = RiskLevel.CRITICAL,
                evidence = foundPkgs
            )
        }

        // 2. Filesystem paths — specific to Magisk runtime
        val foundPaths = magiskPaths.filter { fileExists(it) }
        if (foundPaths.isNotEmpty()) {
            findings += RootIndicator(
                id = "magisk_paths",
                category = DetectorCategory.MAGISK,
                title = "Magisk Filesystem Artifacts",
                detail = "Magisk runtime directories or sockets found",
                risk = RiskLevel.CRITICAL,
                evidence = foundPaths
            )
        }

        // 3. Binary detection
        val foundBins = magiskBinaries.filter { fileExists(it) || canExecute(it) }
        if (foundBins.isNotEmpty()) {
            findings += RootIndicator(
                id = "magisk_bins",
                category = DetectorCategory.MAGISK,
                title = "Magisk Binaries Present",
                detail = "Magisk executable files found",
                risk = RiskLevel.CRITICAL,
                evidence = foundBins
            )
        }

        // 4. Magisk daemon socket via /proc/net/unix
        detectMagiskSocket()?.let { findings += it }

        // 5. Magisk module directories
        detectMagiskModules()?.let { findings += it }

        // 6. Stub APK — NARROW: only label "Magisk" or "KernelSU", no launcher activity
        detectStubApk()?.let { findings += it }

        // 7. pm list packages subprocess — bypasses Zygisk Binder-level hiding.
        //    Zygisk hooks PackageManager IN OUR PROCESS. A subprocess running `pm`
        //    is exec'd fresh (no Zygote injection → no Zygisk), so it sees real packages.
        detectPackagesViaShell()?.let { findings += it }

        // 8. Renamed Magisk stub — "Hide Magisk" randomizes package name but DEX still
        //    contains Magisk class path strings. Scan via ZipFile directly on APK files.
        detectRenamedMagiskApk()?.let { findings += it }

        // 9. ps subprocess — alternative to native proc scan.
        detectRootDaemonsViaPs()?.let { findings += it }

        // 10. Shell exe scan — /proc/<pid>/exe is a kernel symlink resolved in root namespace.
        //     Even if /sbin is unmounted from our DenyList namespace, the exe symlink for a
        //     running magisk64 still points to "/sbin/magisk64" as seen by the kernel.
        detectRootProcessViaExeScan()?.let { findings += it }

        return findings
    }

    /**
     * Looks for Magisk daemon UNIX sockets in /proc/net/unix.
     * Socket names containing "magisk" are highly specific — no legitimate system
     * component uses this name. Zygisk sockets are handled by ZygiskDetector.
     */
    private fun detectMagiskSocket(): RootIndicator? {
        val evidence = try {
            Rules.magiskSocketLines(java.io.File("/proc/net/unix").readLines())
        } catch (_: Exception) { emptyList() }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "magisk_socket",
            category = DetectorCategory.MAGISK,
            title = "Magisk Daemon Socket Active",
            detail = "Magisk UNIX socket found in /proc/net/unix — daemon is running",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectMagiskModules(): RootIndicator? {
        val modulesDir = java.io.File("/data/adb/modules")
        if (!modulesDir.exists()) return null
        val evidence = mutableListOf<String>()
        try {
            modulesDir.listFiles()?.forEach { if (it.isDirectory) evidence += it.name }
        } catch (_: Exception) {}
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "magisk_modules",
            category = DetectorCategory.MAGISK,
            title = "Magisk Modules Found",
            detail = "Active Magisk module directories in /data/adb/modules",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }

    /**
     * Magisk can hide itself as a stub APK with a randomized package name.
     * The stub has:
     *   1. App label exactly "Magisk" or "KernelSU" (case-insensitive)
     *   2. No launcher activity
     *   3. Package name not in our known list
     *
     * FALSE POSITIVE prevention:
     *  - We only match EXACT labels "magisk" or "kernelsu", not "manager", "root", etc.
     *  - Millions of apps have "manager" in the label — that's not a signal.
     *  - The no-launcher check filters widget/service-only apps, combined with the
     *    very specific label requirement makes FP rate near zero.
     */
    private fun detectStubApk(): RootIndicator? {
        val pm = context.packageManager
        val exactLabels = setOf("magisk", "kernelsu", "ksu manager", "supersu", "superuser su")
        val evidence = mutableListOf<String>()
        try {
            @Suppress("DEPRECATION")
            val installedApps = pm.getInstalledApplications(0)
            for (app in installedApps) {
                if (magiskPackages.contains(app.packageName)) continue
                val label = pm.getApplicationLabel(app).toString().lowercase().trim()
                if (exactLabels.contains(label)) {
                    val launchIntent = pm.getLaunchIntentForPackage(app.packageName)
                    if (launchIntent == null) {
                        evidence += "${app.packageName} (label='$label', no launcher)"
                    }
                }
            }
        } catch (_: Exception) {}
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "magisk_stub",
            category = DetectorCategory.MAGISK,
            title = "Possible Magisk Stub APK",
            detail = "Hidden package with exact 'Magisk'/'KernelSU' label and no launcher",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }

    /**
     * Detect "Hide Magisk" (randomized package name) by scanning DEX content.
     *
     * When user renames Magisk to e.g. "Settings":
     * - Package name is randomized → known-name checks fail
     * - PackageManager API is Binder-hooked by Zygisk → isPackageInstalled() fails
     * - BUT the stub APK still contains Magisk class path strings in its DEX
     *
     * We get APK paths from `pm list packages -f` subprocess (no Zygisk hooks),
     * then open each small user APK directly via ZipFile (bypasses PackageManager),
     * and search the DEX for Magisk-specific strings in the string pool.
     */
    /**
     * One `pm list packages -u -f` for both package checks. Every `pm` call starts a new
     * app_process (JVM) — ~1 s each on real phones — so running it twice was the main cost
     * of this detector (2–5 s in Firebase Test Lab).
     *  -u: also packages hidden/frozen for the user (Hail, Ice Box)
     *  -f: APK path, used by the renamed-stub scan (user apps live under /data/app/)
     */
    private val pmPackagesWithPaths: String by lazy {
        runShellCommand("pm list packages -u -f 2>/dev/null", timeoutMs = 5000)
    }

    private fun detectRenamedMagiskApk(): RootIndicator? {
        val pmOutput = pmPackagesWithPaths
        if (pmOutput.isBlank()) return null

        val magiskSigs = listOf(
            // Tier 1 — DEX class descriptors (slash format, only in APK that CONTAINS the class)
            "Lcom/topjohnwu/magisk/",
            "Lio/github/huskydg/magisk/",
            "Lio/github/vvb2060/magisk/",
            // Tier 2 — Magisk-internal strings (RASP libs only have top-level package)
            "topjohnwu.magisk.core.su",
            "topjohnwu.magisk.core.app",
            "huskydg.magisk.core",
            "StubApk",
            "MagiskdService",
            // Tier 3 — Stub loader paths (appear in the loader code that bootstraps main APK)
            "/data/adb/magisk.apk",       // path Magisk/Kitsune stub uses to load main APK
            "MAGISKTMP",                  // internal env var name set by Magisk init
        )
        val selfPkg = context.packageName
        val evidence = mutableListOf<String>()

        // Parse all lines first, then sort by APK size ascending.
        // Magisk stub is always tiny (<2 MB); real apps are 5-100 MB.
        // Sorting ensures the stub is scanned FIRST even if 100+ apps are installed.
        data class Entry(val apkPath: String, val pkgName: String, val size: Long)

        // The hidden-Magisk stub is tiny; scanning up to 50 APKs of 5 MB took 2–5 s on real phones
        // (Firebase Test Lab), so only APKs up to 1 MB, at most 25, are opened.
        val MAX_APK_SIZE = 1L * 1024 * 1024
        val entries = pmOutput.lines()
            .filter { it.startsWith("package:") }
            .mapNotNull { line ->
                val rest = line.removePrefix("package:")
                val eqIdx = rest.lastIndexOf('=')
                if (eqIdx < 0) return@mapNotNull null
                val apkPath = rest.substring(0, eqIdx).trim()
                val pkgName = rest.substring(eqIdx + 1).trim()
                if (apkPath.isEmpty() || pkgName.isEmpty() || pkgName == selfPkg) return@mapNotNull null
                if (!apkPath.startsWith("/data/app/")) return@mapNotNull null  // third-party only
                val f = java.io.File(apkPath)
                if (!f.exists()) return@mapNotNull null
                val sz = f.length()
                if (sz > MAX_APK_SIZE) return@mapNotNull null
                Entry(apkPath, pkgName, sz)
            }
            .sortedBy { it.size }
            .take(25)

        for (e in entries) {
            try {
                java.util.zip.ZipFile(e.apkPath).use { zip ->
                    for (dexName in listOf("classes.dex", "classes2.dex")) {
                        val entry = zip.getEntry(dexName) ?: continue
                        if (streamContainsSig(zip.getInputStream(entry), magiskSigs)) {
                            evidence += "${e.pkgName} → Magisk signature in $dexName"
                            break
                        }
                    }
                }
            } catch (_: Exception) {}
        }

        return if (evidence.isNotEmpty()) RootIndicator(
            id = "magisk_renamed_stub",
            category = DetectorCategory.MAGISK,
            title = "Renamed Magisk Stub Detected",
            detail = "User APK contains Magisk class references — package hidden via 'Hide Magisk' feature",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectRootDaemonsViaPs(): RootIndicator? {
        val evidence = mutableListOf<String>()

        // Approach A: ps | grep — pipes filter output so even large process lists are fast.
        // Tested on emulator: UID=app can see magiskd in ps output.
        val psOutput = runShellCommand(
            "ps -A 2>/dev/null | grep -iE 'magiskd|magisk64|magisk32|ksud|apd|kpatch'",
            timeoutMs = 3000
        )
        Rules.rootDaemonPsLines(psOutput).take(5).forEach { evidence += "ps: $it" }

        // Approach B: cat /proc/*/comm via shell glob — one subprocess reads ALL comm files.
        // Even if native open() per-PID is slow, shell glob is batched efficiently.
        // Returns just the process name, one per line.
        val commOutput = runShellCommand(
            "cat /proc/[0-9]*/comm 2>/dev/null | grep -ixE 'magiskd|magisk64|magisk32|ksud|apd'",
            timeoutMs = 3000
        )
        Rules.rootDaemonComms(commOutput).take(5).forEach { evidence += "comm: $it" }

        return if (evidence.isNotEmpty()) RootIndicator(
            id = "magisk_proc_ps",
            category = DetectorCategory.MAGISK,
            title = "Root Daemon in Process List",
            detail = "Root daemon found via shell subprocess — not affected by Zygisk in-process hooks",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectRootProcessViaExeScan(): RootIndicator? {
        // ls -la /proc/*/exe resolves symlinks in KERNEL mount namespace.
        // Even with DenyList hiding /sbin from our namespace, the exe symlink
        // for /sbin/magisk64 still shows /sbin/magisk64 via kernel's view.
        val output = runShellCommand(
            "ls -la /proc/*/exe 2>/dev/null | grep -iE 'magisk|ksud|apd|kitsune'",  // coarse pre-filter
            timeoutMs = 3000
        )
        if (output.isBlank()) return null
        val found = Rules.rootExeLines(output).take(5)
        return if (found.isNotEmpty()) RootIndicator(
            id = "magisk_exe_proc",
            category = DetectorCategory.MAGISK,
            title = "Root Binary Found via /proc/exe",
            detail = "/proc/<pid>/exe reveals root binary path — kernel-resolved, DenyList cannot hide",
            risk = RiskLevel.CRITICAL,
            evidence = found
        ) else null
    }

    // Streaming string search — reads at most 128KB at a time regardless of file size.
    // Overlap ensures matches spanning chunk boundaries are not missed.
    private fun streamContainsSig(stream: java.io.InputStream, sigs: List<String>): Boolean {
        val chunkSize = 65536
        val maxSigLen = sigs.maxOf { it.length }
        val overlap = maxSigLen - 1
        val buf = ByteArray(chunkSize + overlap)
        var prevLen = 0
        return try {
            stream.use {
                while (true) {
                    val read = it.read(buf, prevLen, chunkSize)
                    if (read <= 0) break
                    val total = prevLen + read
                    val window = String(buf, 0, total, Charsets.ISO_8859_1)
                    for (sig in sigs) {
                        if (window.contains(sig)) return true
                    }
                    val newPrev = minOf(overlap, total)
                    System.arraycopy(buf, total - newPrev, buf, 0, newPrev)
                    prevLen = newPrev
                }
            }
            false
        } catch (_: Exception) { false }
    }

    private fun detectPackagesViaShell(): RootIndicator? {
        val output = pmPackagesWithPaths
        if (output.isBlank()) return null

        val found = Rules.rootPackagesInPmList(output)
        return if (found.isNotEmpty()) RootIndicator(
            id = "magisk_pkg_shell",
            category = DetectorCategory.MAGISK,
            title = "Root Package Found (Shell pm)",
            detail = "Root manager found via `pm list packages` subprocess — bypasses Zygisk Binder hook",
            risk = RiskLevel.CRITICAL,
            evidence = found
        ) else null
    }
}
