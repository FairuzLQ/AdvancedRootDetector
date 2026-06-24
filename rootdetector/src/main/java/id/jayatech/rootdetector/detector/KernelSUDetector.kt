package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

internal class KernelSUDetector(context: Context) : BaseDetector(context) {

    private val ksuPackages = listOf(
        "me.weishu.kernelsu",           // KernelSU official manager
        "com.rifsxd.ksunext",           // KernelSU Next (rifsxd fork)
        "com.rifsxd.ksunext.stub",
        "me.weishu.kernelsu.debug",
        "io.github.tiann.kernelsu",
        "com.nextsu.manager",
        "com.canyie.dreamland.manager", // sometimes paired with KSU
        "top.canyie.pine.xposed",
        "me.bmax.apatch",               // APatch (often confused with KSU)
    )

    private val ksuPaths = listOf(
        // KernelSU data directory
        "/data/adb/ksu",
        "/data/adb/ksu/bin",
        "/data/adb/ksu/modules",
        "/data/adb/ksu/.version",
        // KernelSU Next
        "/data/adb/ksunext",
        "/data/adb/ksunext/modules",
        "/data/adb/ksunext/.version",
        // KernelSU binaries
        "/data/adb/ksu/bin/ksud",
        "/data/adb/ksu/bin/ksu",
        "/data/adb/ksunext/bin/ksud",
    )

    private val ksuBinaries = listOf(
        "/data/adb/ksu/bin/ksud",
        "/data/adb/ksunext/bin/ksud",
        "/sbin/ksu",
        "/dev/ksu",
    )

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()

        // 1. Manager app
        val foundPkgs = ksuPackages.filter { isPackageInstalled(it) }
        if (foundPkgs.isNotEmpty()) {
            findings += RootIndicator(
                id = "ksu_pkg",
                category = DetectorCategory.KERNELSU,
                title = "KernelSU Manager Installed",
                detail = "KernelSU or KernelSU Next manager package found",
                risk = RiskLevel.CRITICAL,
                evidence = foundPkgs
            )
        }

        // 2. Filesystem paths
        val foundPaths = ksuPaths.filter { fileExists(it) }
        if (foundPaths.isNotEmpty()) {
            findings += RootIndicator(
                id = "ksu_paths",
                category = DetectorCategory.KERNELSU,
                title = "KernelSU Filesystem Artifacts",
                detail = "KernelSU data directories or version files found",
                risk = RiskLevel.CRITICAL,
                evidence = foundPaths
            )
        }

        // 3. Binaries
        val foundBins = ksuBinaries.filter { fileExists(it) || canExecute(it) }
        if (foundBins.isNotEmpty()) {
            findings += RootIndicator(
                id = "ksu_bins",
                category = DetectorCategory.KERNELSU,
                title = "KernelSU Binaries Present",
                detail = "KernelSU daemon (ksud) or su binary found",
                risk = RiskLevel.CRITICAL,
                evidence = foundBins
            )
        }

        // 4. KernelSU custom syscall probe
        // KernelSU uses syscall number 0xDEADBEEF on arm64
        // We attempt via native; probe result comes from NativeDetector
        // Here we check kernel version string for KSU signature
        detectKernelVersion()?.let { findings += it }

        // 5. KernelSU module directories
        detectKsuModules()?.let { findings += it }

        // 6. SafeMode key prop (KernelSU sets this)
        val ksuprop = readProp("persist.sys.ksu.version")
        if (ksuprop.isNotEmpty()) {
            findings += RootIndicator(
                id = "ksu_prop",
                category = DetectorCategory.KERNELSU,
                title = "KernelSU Version Property Found",
                detail = "System property persist.sys.ksu.version is set",
                risk = RiskLevel.CRITICAL,
                evidence = listOf("persist.sys.ksu.version=$ksuprop")
            )
        }

        // 7. KSU uid 0 grant file
        detectKsuAllowList()?.let { findings += it }

        return findings
    }

    private fun detectKernelVersion(): RootIndicator? {
        val evidence = mutableListOf<String>()
        try {
            val version = java.io.File("/proc/version").readText()
            // KernelSU patches often add "KernelSU" or "ksu" to kernel version string
            if (version.contains("KernelSU", ignoreCase = true) ||
                version.contains("ksu", ignoreCase = true) ||
                version.contains("ksunext", ignoreCase = true)
            ) {
                evidence += version.take(200)
            }
        } catch (_: Exception) {}
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "ksu_kernel_version",
            category = DetectorCategory.KERNELSU,
            title = "KernelSU Kernel String",
            detail = "Kernel version string contains KernelSU identifier",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectKsuModules(): RootIndicator? {
        val dirs = listOf("/data/adb/ksu/modules", "/data/adb/ksunext/modules")
        val evidence = mutableListOf<String>()
        for (dir in dirs) {
            try {
                java.io.File(dir).listFiles()?.forEach { module ->
                    if (module.isDirectory) evidence += "${dir}/${module.name}"
                }
            } catch (_: Exception) {}
        }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "ksu_modules",
            category = DetectorCategory.KERNELSU,
            title = "KernelSU Modules Found",
            detail = "Active KernelSU module directories detected",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }

    private fun detectKsuAllowList(): RootIndicator? {
        val allowListPaths = listOf(
            "/data/adb/ksu/allow_list",
            "/data/adb/ksunext/allow_list",
            "/data/adb/ksu/uid_list",
        )
        val found = allowListPaths.filter { fileExists(it) }
        return if (found.isNotEmpty()) RootIndicator(
            id = "ksu_allowlist",
            category = DetectorCategory.KERNELSU,
            title = "KernelSU Allow-List File",
            detail = "KernelSU root grant database found",
            risk = RiskLevel.HIGH,
            evidence = found
        ) else null
    }
}
