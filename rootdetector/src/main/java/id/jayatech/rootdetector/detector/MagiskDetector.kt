package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

internal class MagiskDetector(context: Context) : BaseDetector(context) {

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

        return findings
    }

    /**
     * Looks for Magisk daemon UNIX sockets in /proc/net/unix.
     * Socket names containing "magisk" are highly specific — no legitimate system
     * component uses this name. Zygisk sockets are handled by ZygiskDetector.
     */
    private fun detectMagiskSocket(): RootIndicator? {
        val evidence = mutableListOf<String>()
        try {
            val lines = java.io.File("/proc/net/unix").readLines()
            for (line in lines) {
                // Only match "magisk" specifically — avoid "zygisk" here (handled separately)
                // and avoid overly broad patterns
                val lower = line.lowercase()
                if (lower.contains("@magisk") || lower.contains("/.magisk") ||
                    lower.endsWith("magisk") || lower.contains("/magisk.")
                ) {
                    evidence += line.trim()
                }
            }
        } catch (_: Exception) {}
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
    private fun detectRenamedMagiskApk(): RootIndicator? {
        val pmOutput = try {
            val p = Runtime.getRuntime().exec(arrayOf("pm", "list", "packages", "-3", "-f"))
            p.inputStream.bufferedReader().readText()
        } catch (_: Exception) { return null }
        if (pmOutput.isBlank()) return null

        val magiskSigs = listOf("topjohnwu", "huskydg", "magisk.core", "magisk.ui", "MagiskSU")
        val evidence = mutableListOf<String>()

        for (line in pmOutput.lines()) {
            if (!line.startsWith("package:")) continue
            val rest = line.removePrefix("package:")
            val eqIdx = rest.lastIndexOf('=')
            if (eqIdx < 0) continue
            val apkPath = rest.substring(0, eqIdx).trim()
            val pkgName = rest.substring(eqIdx + 1).trim()
            if (apkPath.isEmpty() || pkgName.isEmpty()) continue

            val apkFile = java.io.File(apkPath)
            if (!apkFile.exists() || apkFile.length() > 40_000_000L) continue

            try {
                java.util.zip.ZipFile(apkPath).use { zip ->
                    for (dexName in listOf("classes.dex", "classes2.dex")) {
                        val entry = zip.getEntry(dexName) ?: continue
                        if (entry.size > 25_000_000L) continue
                        val bytes = zip.getInputStream(entry).readBytes()
                        val raw = String(bytes, Charsets.ISO_8859_1)
                        for (sig in magiskSigs) {
                            if (raw.contains(sig)) {
                                evidence += "$pkgName → '$sig' in $dexName"
                                break
                            }
                        }
                        if (evidence.any { it.startsWith(pkgName) }) break
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

    private fun detectPackagesViaShell(): RootIndicator? {
        val output = try {
            val p = Runtime.getRuntime().exec(arrayOf("pm", "list", "packages"))
            p.inputStream.bufferedReader().readText()
        } catch (_: Exception) { return null }
        if (output.isBlank()) return null

        val targets = listOf(
            "com.topjohnwu.magisk",
            "io.github.huskydg.magisk",
            "io.github.vvb2060.magisk",
            "io.github.huskydg.magisk.stub",
            "me.weishu.kernelsu",
            "io.github.huskydg.shamiko",
            "io.github.rezygisk",
        )
        val found = targets.filter { output.contains("package:$it") }
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
