package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

internal class FileSystemDetector(context: Context) : BaseDetector(context) {

    private val rootApkPaths = listOf(
        "/system/app/Superuser.apk",
        "/system/app/Superuser",
        "/system/app/SuperSU.apk",
        "/system/app/SuperSU",
        "/system/priv-app/Superuser.apk",
        "/system/priv-app/SuperSU.apk",
    )

    /**
     * Paths that are EXCLUSIVELY created by root tools — no stock ROM or OEM creates these.
     *
     * REMOVED from original list (false positives):
     *  - /data/local/tmp       — created by adb on every device, exists stock
     *  - /dev/mem              — exists on stock kernels (just not accessible)
     *  - /dev/kmem             — same
     *  - /proc/config.gz       — exists on many stock devices with kernel CONFIG_IKCONFIG
     *  - /sys/kernel/debug     — debugfs mounted on many stock/userdebug devices
     */
    private val rootExclusivePaths = listOf(
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/data/adb/ksunext",
        "/data/adb/ap",
        "/data/adb/modules",
        "/data/adb/post-fs-data.d",
        "/data/adb/service.d",
        "/sbin/.magisk",
    )

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()

        // 1. Root APKs baked into /system — very specific signal
        val foundApks = rootApkPaths.filter { fileExists(it) }
        if (foundApks.isNotEmpty()) {
            findings += RootIndicator(
                id = "fs_root_apks",
                category = DetectorCategory.FILESYSTEM,
                title = "Root APK in /system",
                detail = "SuperUser/SuperSU APK installed as a system app",
                risk = RiskLevel.CRITICAL,
                evidence = foundApks
            )
        }

        // 2. Root-exclusive paths — none of these exist on any stock ROM
        val foundPaths = rootExclusivePaths.filter { fileExists(it) }
        if (foundPaths.isNotEmpty()) {
            findings += RootIndicator(
                id = "fs_root_paths",
                category = DetectorCategory.FILESYSTEM,
                title = "Root Tool Directories",
                detail = "Paths exclusively created by Magisk/KSU/APatch — not present on stock devices",
                risk = RiskLevel.CRITICAL,
                evidence = foundPaths
            )
        }

        // 3. /system writable check — if we can create a file in /system, it's mounted rw
        detectWritableSystem()?.let { findings += it }

        // 4. /data/adb contents accessible — implies this process has root-level read
        detectDataAdbContents()?.let { findings += it }

        // 5. Root-named executables in /data/local/tmp (not tmp itself — just suspicious executables)
        detectRootExecutablesInTmp()?.let { findings += it }

        return findings
    }

    private fun detectWritableSystem(): RootIndicator? {
        val testFile = java.io.File("/system/.rw_probe_${System.currentTimeMillis()}")
        return try {
            if (testFile.createNewFile()) {
                testFile.delete()
                RootIndicator(
                    id = "fs_system_writable",
                    category = DetectorCategory.FILESYSTEM,
                    title = "/system Partition Writable",
                    detail = "Created a file in /system — partition is mounted read-write",
                    risk = RiskLevel.CRITICAL,
                    evidence = listOf("/system is writable")
                )
            } else null
        } catch (_: Exception) { null }
    }

    private fun detectDataAdbContents(): RootIndicator? {
        if (!fileExists("/data/adb")) return null
        val contents = mutableListOf<String>()
        try {
            java.io.File("/data/adb").listFiles()?.forEach { contents += it.name }
        } catch (_: Exception) {}
        return if (contents.isNotEmpty()) RootIndicator(
            id = "fs_data_adb_readable",
            category = DetectorCategory.FILESYSTEM,
            title = "/data/adb Directory Readable",
            detail = "Root data directory is accessible — confirms elevated privileges",
            risk = RiskLevel.CRITICAL,
            evidence = contents
        ) else null
    }

    /**
     * Checks /data/local/tmp ONLY for files whose names match known root tools.
     *
     * FALSE POSITIVE prevention:
     *  - /data/local/tmp ITSELF is NOT suspicious — adb creates it on every device.
     *  - We only flag files whose names contain specific root tool identifiers.
     *  - Legitimate app installers/OEM updaters use /data/local/tmp but won't
     *    name their files "frida-server", "magisk", "ksud", etc.
     */
    private fun detectRootExecutablesInTmp(): RootIndicator? {
        val rootToolNames = listOf(
            "frida", "frida-server", "magisk", "ksud", "ksu", "apd", "su",
            "daemonsu", "busybox_frida", "objection"
        )
        val evidence = mutableListOf<String>()
        try {
            java.io.File("/data/local/tmp").listFiles()?.forEach { f ->
                val name = f.name.lowercase()
                if (rootToolNames.any { name.startsWith(it) || name == it }) {
                    evidence += f.absolutePath
                }
            }
        } catch (_: Exception) {}
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "fs_root_executables_tmp",
            category = DetectorCategory.FILESYSTEM,
            title = "Root Tool Files in /data/local/tmp",
            detail = "Files named after known root/instrumentation tools found in temp directory",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }
}
