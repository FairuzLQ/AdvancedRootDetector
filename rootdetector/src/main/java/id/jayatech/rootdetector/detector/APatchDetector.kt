package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

/**
 * Detects APatch — a kernel-level root solution similar to KernelSU.
 * APatch uses Kernel Patch Modules (KPM) instead of LKM.
 * GitHub: bmax121/APatch
 */
internal class APatchDetector(context: Context) : BaseDetector(context) {

    private val apatchPackages = listOf(
        "me.bmax.apatch",               // APatch manager (official)
        "me.bmax.apatch.debug",
        "me.bmax.apatch.stub",
    )

    private val apatchPaths = listOf(
        // APatch data root
        "/data/adb/ap",
        "/data/adb/ap/bin",
        "/data/adb/ap/modules",
        "/data/adb/ap/kpm",             // Kernel Patch Modules directory
        "/data/adb/ap/.version",
        "/data/adb/ap/package_config",  // per-app root grants
        // APatch binaries
        "/data/adb/ap/bin/apd",         // APatch daemon
        "/data/adb/ap/bin/kpatch",      // kernel patcher
        "/data/adb/ap/bin/resetprop",
        // APatch kernel module artifacts
        "/dev/apatch",
        "/dev/kp",
    )

    private val kpmPaths = listOf(
        "/data/adb/ap/kpm",
        "/data/adb/ap/modules",
    )

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()

        // 1. Manager package
        val foundPkgs = apatchPackages.filter { isPackageInstalled(it) }
        if (foundPkgs.isNotEmpty()) {
            findings += RootIndicator(
                id = "apatch_pkg",
                category = DetectorCategory.APATCH,
                title = "APatch Manager Installed",
                detail = "APatch manager application found",
                risk = RiskLevel.CRITICAL,
                evidence = foundPkgs
            )
        }

        // 2. Filesystem paths
        val foundPaths = apatchPaths.filter { fileExists(it) }
        if (foundPaths.isNotEmpty()) {
            findings += RootIndicator(
                id = "apatch_paths",
                category = DetectorCategory.APATCH,
                title = "APatch Filesystem Artifacts",
                detail = "APatch runtime directories or binaries found",
                risk = RiskLevel.CRITICAL,
                evidence = foundPaths
            )
        }

        // 3. KPM modules (Kernel Patch Modules)
        detectKpmModules()?.let { findings += it }

        // 4. APatch-specific system properties
        val apatchVersion = readProp("ro.apatch.version")
        val apatchEnabled = readProp("persist.ap.enabled")
        val evidence = mutableListOf<String>()
        if (apatchVersion.isNotEmpty()) evidence += "ro.apatch.version=$apatchVersion"
        if (apatchEnabled.isNotEmpty()) evidence += "persist.ap.enabled=$apatchEnabled"
        if (evidence.isNotEmpty()) {
            findings += RootIndicator(
                id = "apatch_props",
                category = DetectorCategory.APATCH,
                title = "APatch System Properties",
                detail = "APatch-specific system properties are set",
                risk = RiskLevel.CRITICAL,
                evidence = evidence
            )
        }

        // 5. APatch daemon socket
        detectApatchSocket()?.let { findings += it }

        // 6. /proc/version APatch signature
        detectApatchKernelString()?.let { findings += it }

        return findings
    }

    private fun detectKpmModules(): RootIndicator? {
        val evidence = mutableListOf<String>()
        for (dir in kpmPaths) {
            try {
                java.io.File(dir).listFiles()?.forEach { f ->
                    evidence += "${dir}/${f.name}"
                }
            } catch (_: Exception) {}
        }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "apatch_kpm",
            category = DetectorCategory.APATCH,
            title = "APatch KPM Modules Found",
            detail = "Kernel Patch Modules (KPM) or APatch modules loaded",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }

    private fun detectApatchSocket(): RootIndicator? {
        val evidence = mutableListOf<String>()
        try {
            val lines = java.io.File("/proc/net/unix").readLines()
            for (line in lines) {
                if (line.contains("apatch", ignoreCase = true) ||
                    line.contains("apd", ignoreCase = true) ||
                    line.contains("kpatch", ignoreCase = true)
                ) {
                    evidence += line.trim()
                }
            }
        } catch (_: Exception) {}
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "apatch_socket",
            category = DetectorCategory.APATCH,
            title = "APatch Daemon Socket",
            detail = "APatch daemon UNIX socket found in /proc/net/unix",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectApatchKernelString(): RootIndicator? {
        val evidence = mutableListOf<String>()
        try {
            val version = java.io.File("/proc/version").readText()
            if (version.contains("APatch", ignoreCase = true) ||
                version.contains("apatch", ignoreCase = true)
            ) {
                evidence += version.take(200)
            }
        } catch (_: Exception) {}
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "apatch_kernel",
            category = DetectorCategory.APATCH,
            title = "APatch Kernel String",
            detail = "Kernel version string contains APatch identifier",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }
}
