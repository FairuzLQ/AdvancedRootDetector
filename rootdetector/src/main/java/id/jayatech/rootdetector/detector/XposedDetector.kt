package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

/**
 * Detects Xposed Framework variants:
 *  - LSPosed (Zygisk-based, most popular modern variant)
 *  - LSPatch (APK-level patching)
 *  - EdXposed (YAHFA/SANDHOOK engine)
 *  - Riru (Zygote injector, predecessor to Zygisk)
 *  - Pine / Dreamland
 */
internal class XposedDetector(context: Context) : BaseDetector(context) {

    private val xposedPackages = listOf(
        "org.lsposed.lspatch",
        "io.github.lsposed.manager",
        "org.lsposed.manager",
        "org.meowcat.edxposed.manager",
        "com.elderdrivers.riru.edxposed",
        "de.robv.android.xposed.installer",
        "top.canyie.pine.xposed",
        "com.canyie.dreamland",
        "com.canyie.dreamland.manager",
    )

    private val xposedPaths = listOf(
        "/system/framework/XposedBridge.jar",
        "/system/xposed.prop",
        // LSPosed — all known install path variants
        "/data/adb/modules/lsposed",
        "/data/adb/modules/zygisk_lsposed",      // most common Zygisk-based install
        "/data/adb/modules/Lsposed-MI",           // some custom builds
        "/data/misc/lspd",                        // LSPosed daemon data — accessible on Android 8
        "/data/adb/lspatch",
        "/system/framework/edxp.jar",
        "/data/adb/modules/edxposed",
        "/data/adb/modules/YAHFA",
        "/data/adb/riru",
        "/data/adb/modules/riru-core",
        "/data/adb/modules/pine",
        "/data/adb/modules/dreamland",
    )

    /**
     * Known XposedBridge class signatures — highly specific to Xposed framework.
     * No legitimate stock app or OEM service uses these class names.
     */
    private val bridgeClasses = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "de.robv.android.xposed.XC_MethodHook",
        "org.lsposed.lspd.service.ILSPApplicationService",
        "io.github.lsposed.lspd.service.ILSPApplicationService",
    )

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()

        val foundPkgs = xposedPackages.filter { isPackageInstalled(it) }
        if (foundPkgs.isNotEmpty()) {
            findings += RootIndicator(
                id = "xposed_pkg",
                category = DetectorCategory.XPOSED,
                title = "Xposed/LSPosed App Installed",
                detail = "Xposed framework variant manager found",
                risk = RiskLevel.CRITICAL,
                evidence = foundPkgs
            )
        }

        val foundPaths = xposedPaths.filter { fileExists(it) }
        if (foundPaths.isNotEmpty()) {
            findings += RootIndicator(
                id = "xposed_paths",
                category = DetectorCategory.XPOSED,
                title = "Xposed Framework Files",
                detail = "Xposed/LSPosed runtime files found",
                risk = RiskLevel.CRITICAL,
                evidence = foundPaths
            )
        }

        // Class loader probe — most reliable: if XposedBridge is in the classpath,
        // Xposed has hooked this process. No legitimate stock app has these classes.
        detectXposedBridgeClass()?.let { findings += it }

        detectRiru()?.let { findings += it }
        detectLSPatch()?.let { findings += it }
        detectXposedMaps()?.let { findings += it }

        // NOTE: Stack trace analysis was removed — it produced false positives
        // on GrapheneOS/LineageOS components with similar naming patterns and
        // was unreliable across different OEM classloader implementations.

        return findings
    }

    private fun detectXposedBridgeClass(): RootIndicator? {
        val evidence = mutableListOf<String>()
        for (cls in bridgeClasses) {
            try {
                Class.forName(cls)
                evidence += cls
            } catch (_: ClassNotFoundException) {
                // expected on clean devices
            } catch (e: Exception) {
                // class exists but failed to init — still evidence of presence
                evidence += "$cls (found but load error: ${e.javaClass.simpleName})"
            }
        }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "xposed_class",
            category = DetectorCategory.XPOSED,
            title = "XposedBridge Class in Classpath",
            detail = "Xposed framework classes are present in the class loader",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectRiru(): RootIndicator? {
        val riruPaths = listOf(
            "/data/adb/riru",
            "/data/adb/modules/riru-core",
            "/system/lib64/libriru.so",
        )
        val found = riruPaths.filter { fileExists(it) }
        return if (found.isNotEmpty()) RootIndicator(
            id = "xposed_riru",
            category = DetectorCategory.XPOSED,
            title = "Riru Injector Detected",
            detail = "Riru (Zygote injection framework) files found",
            risk = RiskLevel.HIGH,
            evidence = found
        ) else null
    }

    private fun detectLSPatch(): RootIndicator? {
        val evidence = mutableListOf<String>()
        val lspatchClasses = listOf(
            "org.lsposed.lspatch.loader.LSPApplication",
            "org.lsposed.lspatch.service.LocalApplicationService",
        )
        for (cls in lspatchClasses) {
            try {
                Class.forName(cls)
                evidence += cls
            } catch (_: Exception) {}
        }
        try {
            val apkDir = java.io.File(context.packageCodePath).parentFile
            if (apkDir != null && java.io.File(apkDir, ".lspatch").exists()) {
                evidence += "${apkDir.absolutePath}/.lspatch"
            }
        } catch (_: Exception) {}
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "lspatch",
            category = DetectorCategory.XPOSED,
            title = "LSPatch Injection Detected",
            detail = "LSPatch loader class or .lspatch directory found",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectXposedMaps(): RootIndicator? {
        // Only match unambiguous Xposed-specific library names in process maps
        val patterns = listOf("XposedBridge", "liblspd", "libedxp", "libriru", "lspatch_loader")
        val evidence = mutableListOf<String>()
        try {
            java.io.File("/proc/self/maps").readLines().forEach { line ->
                if (patterns.any { line.contains(it) }) evidence += line.trim()
            }
        } catch (_: Exception) {}
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "xposed_maps",
            category = DetectorCategory.XPOSED,
            title = "Xposed Library in Process Maps",
            detail = "Xposed/LSPosed native libraries injected into this process",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }
}
