package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

/**
 * Detects Zygisk and standalone Zygisk variants:
 *  - Zygisk (built into Magisk v24+)
 *  - ZygiskNext (standalone, works with KernelSU)
 *  - ReZygisk (fork, works with KernelSU/APatch)
 *  - Shamiko (Zygisk module to hide Magisk from DenyList targets)
 *  - NeoZygisk
 */
internal class ZygiskDetector(context: Context, props: PropSnapshot = PropSnapshot()) : BaseDetector(context, props) {

    /**
     * FALSE POSITIVE notes on removed packages:
     *  - com.tsng.hidemyapplist was removed — it can work via Shizuku without root.
     */
    private val zygiskPackages = listOf(
        "io.github.huskydg.shamiko",
        "io.github.lsposed.manager",
        "org.lsposed.manager",
        "io.github.rezygisk",
        "io.github.zygnext",
    )

    private val zygiskPaths = listOf(
        // Zygisk sockets (Magisk built-in)
        "/dev/socket/zygisk",
        "/dev/socket/zygisk_0",
        "/dev/socket/zygisk_1",
        // ZygiskNext / ReZygisk module dirs
        "/data/adb/modules/zygisknext",
        "/data/adb/modules/zygisksu",          // ZygiskNext module id
        "/data/adb/zygisk",
        "/data/adb/modules/rezygisk",
        "/dev/socket/rezygisk",
        // NeoZygisk
        "/data/adb/modules/neozygisk",
        // Shamiko
        "/data/adb/modules/shamiko",
        "/data/adb/shamiko",
        // Note: /system/lib/zygisk is NOT checked — some OEM security
        // services use Zygote injection under similar paths legitimately.
    )

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()

        val foundPkgs = zygiskPackages.filter { isPackageInstalled(it) }
        if (foundPkgs.isNotEmpty()) {
            findings += RootIndicator(
                id = "zygisk_pkg",
                category = DetectorCategory.ZYGISK,
                title = "Zygisk-Related App Installed",
                detail = "Zygisk module manager or Shamiko found",
                risk = RiskLevel.CRITICAL,
                evidence = foundPkgs
            )
        }

        val foundPaths = zygiskPaths.filter { fileExists(it) }
        if (foundPaths.isNotEmpty()) {
            findings += RootIndicator(
                id = "zygisk_paths",
                category = DetectorCategory.ZYGISK,
                title = "Zygisk Runtime Paths Found",
                detail = "Zygisk sockets or module directories detected",
                risk = RiskLevel.CRITICAL,
                evidence = foundPaths
            )
        }

        detectZygiskMaps()?.let { findings += it }
        detectShamiko()?.let { findings += it }
        detectHideModules()?.let { findings += it }

        val prop = readProp("persist.sys.zygisk")
        if (prop == "true" || prop == "1") {
            findings += RootIndicator(
                id = "zygisk_prop",
                category = DetectorCategory.ZYGISK,
                title = "Zygisk Enabled Property",
                detail = "persist.sys.zygisk=$prop — Zygisk is active",
                risk = RiskLevel.CRITICAL,
                evidence = listOf("persist.sys.zygisk=$prop")
            )
        }

        return findings
    }

    private fun detectZygiskMaps(): RootIndicator? {
        val evidence = try {
            Rules.zygiskMapsLines(java.io.File("/proc/self/maps").readLines())
        } catch (_: Exception) { emptyList() }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "zygisk_maps",
            category = DetectorCategory.ZYGISK,
            title = "Zygisk Library in Process Maps",
            detail = "Zygisk .so injected into this process",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectShamiko(): RootIndicator? {
        val paths = listOf("/data/adb/shamiko", "/data/adb/modules/shamiko/module.prop")
        val found = paths.filter { fileExists(it) }
        return if (found.isNotEmpty()) RootIndicator(
            id = "zygisk_shamiko",
            category = DetectorCategory.ZYGISK,
            title = "Shamiko Hide Module Active",
            detail = "Shamiko is installed — Magisk is being actively hidden from DenyList targets",
            risk = RiskLevel.CRITICAL,
            evidence = found
        ) else null
    }

    /**
     * Integrity-spoofing / hiding modules that only exist on rooted devices.
     * Visible only when /data/adb leaks into our namespace, but zero false-positive risk.
     */
    private fun detectHideModules(): RootIndicator? {
        val paths = listOf(
            "/data/adb/tricky_store",                  // TrickyStore (keybox / attestation spoof)
            "/data/adb/modules/tricky_store",
            "/data/adb/modules/playintegrityfix",      // Play Integrity Fix
            "/data/adb/modules/playintegrityfork",
            "/data/adb/modules/susfs4ksu",             // SUSFS (KernelSU hiding)
            "/data/adb/susfs4ksu",
            "/data/adb/modules/zygisk_shamiko",
            "/data/adb/modules/treat_wheel",           // Treat Wheel (hiding)
        )
        val found = paths.filter { fileExists(it) }
        return if (found.isNotEmpty()) RootIndicator(
            id = "zygisk_hide_modules",
            category = DetectorCategory.ZYGISK,
            title = "Root-Hiding / Integrity-Spoof Module",
            detail = "TrickyStore, Play Integrity Fix, SUSFS or similar hiding module is installed",
            risk = RiskLevel.CRITICAL,
            evidence = found
        ) else null
    }
}
