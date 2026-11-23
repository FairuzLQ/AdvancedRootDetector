package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

internal class MountDetector(context: Context, props: PropSnapshot = PropSnapshot()) : BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()
        val mountLines = Rules.parseMounts(readMounts())

        detectRootOverlayOnSystem(mountLines)?.let { findings += it }
        detectRwSystem(mountLines)?.let { findings += it }
        detectDataAdb(mountLines)?.let { findings += it }
        detectMagiskTmpfs(mountLines)?.let { findings += it }
        detectZygiskMount(mountLines)?.let { findings += it }
        detectKsuMounts(mountLines)?.let { findings += it }
        detectModuleBindMounts()?.let { findings += it }
        detectDenyListActive()?.let { findings += it }
        detectMountNamespaceIsolation()?.let { findings += it }

        return findings
    }

    private fun readMounts(): List<String> = try {
        java.io.File("/proc/self/mounts").readLines()
    } catch (_: Exception) {
        try { java.io.File("/proc/mounts").readLines() } catch (_: Exception) { emptyList() }
    }

    /**
     * Checks for overlayFS on /system or /vendor with a root-tool lowerdir.
     *
     * FALSE POSITIVE prevention:
     *  - Android 10+ ALWAYS uses overlayfs on /apex for APEX updates — exclude /apex entirely.
     *  - Virtual A/B (Android 11+) uses overlayfs on /system for OTA snapshots — these have
     *    lowerdir pointing to /dev/block or snapshot block devices, NOT /data/adb.
     *  - We only flag if the overlay lowerdir references /data/adb, which is exclusive to
     *    Magisk/KSU module injection.
     */
    private fun detectRootOverlayOnSystem(mounts: List<Rules.MountEntry>): RootIndicator? {
        val evidence = Rules.rootOverlayOnSystem(mounts)
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_overlay_system",
            category = DetectorCategory.MOUNT,
            title = "Root OverlayFS on System Partition",
            detail = "Overlay with /data/adb lowerdir on /system or /vendor — Magisk/KSU module injection",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectRwSystem(mounts: List<Rules.MountEntry>): RootIndicator? {
        val evidence = Rules.rwSystem(mounts)
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_rw_system",
            category = DetectorCategory.MOUNT,
            title = "/system Mounted Read-Write",
            detail = "/system (or system-as-root \"/\") mounted rw — indicates root-level modification",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectDataAdb(mounts: List<Rules.MountEntry>): RootIndicator? {
        val evidence = Rules.dataAdbMounts(mounts)
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_data_adb",
            category = DetectorCategory.MOUNT,
            title = "/data/adb Mount Present",
            detail = "/data/adb is mounted — active root tool storage",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }

    private fun detectMagiskTmpfs(mounts: List<Rules.MountEntry>): RootIndicator? {
        val evidence = Rules.magiskTmpfs(mounts)
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_magisk_tmpfs",
            category = DetectorCategory.MOUNT,
            title = "Magisk tmpfs Mount",
            detail = "Magisk runtime tmpfs mount found in /proc/self/mounts — device name or path shows Magisk origin",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    /**
     * Zygisk library injection via tmpfs bind-mount.
     *
     * When Zygisk (built-in Magisk) is active, Magisk mounts a custom libzygisk.so
     * into /system/lib64 and /system/lib from its tmpfs so Zygote picks it up at startup.
     * This mount entry is visible in /proc/self/mounts with device name "magisk"
     * — readable from any app without root, and not removable by DenyList (it's baked into
     * the Zygote mount namespace before the app forks).
     *
     * Confirmed on Magisk 28.1 / Android 8.1 (Redmi 5):
     *   magisk /system/lib64/libzygisk.so tmpfs ro,seclabel,relatime,...
     *   magisk /system/lib/libzygisk.so  tmpfs ro,seclabel,relatime,...
     */
    private fun detectZygiskMount(mounts: List<Rules.MountEntry>): RootIndicator? {
        val evidence = Rules.zygiskLibMount(mounts)
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_zygisk_lib",
            category = DetectorCategory.ZYGISK,
            title = "Zygisk Library Bind-Mount Detected",
            detail = "Magisk mounts libzygisk.so into /system/lib64 via tmpfs — Zygisk framework is active",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectKsuMounts(mounts: List<Rules.MountEntry>): RootIndicator? {
        val evidence = Rules.ksuApMounts(mounts)
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_ksu_ap",
            category = DetectorCategory.MOUNT,
            title = "KernelSU/APatch Module Mounts",
            detail = "KernelSU or APatch module directories are mounted",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }

    /**
     * Magic-mount module files bind-mounted onto /system — visible only in mountinfo's
     * "root" column (see Rules.mountinfoRootBinds). DenyList removes these for denied apps,
     * so this mainly catches apps that are not on the DenyList / KSU umount list.
     */
    private fun detectModuleBindMounts(): RootIndicator? {
        val evidence = try {
            Rules.mountinfoRootBinds(java.io.File("/proc/self/mountinfo").readLines())
        } catch (_: Exception) { emptyList() }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_module_bind",
            category = DetectorCategory.MOUNT,
            title = "Root Module Bind-Mounts",
            detail = "Files from /data/adb/modules are bind-mounted over system partitions (magic mount)",
            risk = RiskLevel.CRITICAL,
            evidence = evidence.take(6)
        ) else null
    }

    /**
     * DenyList mount namespace isolation — targeted check.
     *
     * When Magisk DenyList (or Shamiko) is active for our process:
     * - Magisk creates a new mount namespace for the app
     * - It unmounts root-specific paths (/data/adb/magisk, /.magisk, etc.) from our namespace
     * - These paths are still visible in PID 1's namespace (init)
     *
     * This is a kernel-level namespace operation, NOT a libc hook —
     * so SYS_openat also returns ENOENT. The ONLY reliable detection is
     * comparing PID 1's mounts against ours for root-exclusive markers.
     */
    private fun detectDenyListActive(): RootIndicator? {
        val initContent = try {
            java.io.File("/proc/1/mounts").readText()
        } catch (_: Exception) { return null }
        val selfContent = try {
            java.io.File("/proc/self/mounts").readText()
        } catch (_: Exception) { return null }

        val hiddenFromUs = Rules.denyListHidden(initContent, selfContent)

        if (hiddenFromUs.isEmpty()) return null

        return RootIndicator(
            id = "mount_denylist",
            category = DetectorCategory.MOUNT,
            title = "Magisk DenyList Mount Isolation Detected",
            detail = "Root mount paths visible to PID 1 are hidden from our process — DenyList is actively isolating our mount namespace",
            risk = RiskLevel.CRITICAL,
            evidence = hiddenFromUs.map { "In /proc/1/mounts but NOT /proc/self/mounts: $it" }
        )
    }

    /**
     * Fallback count-based delta.
     * Threshold >10 catches large Magisk module sets; below that is normal APEX/user-ns variance.
     */
    private fun detectMountNamespaceIsolation(): RootIndicator? {
        return try {
            val selfCount = java.io.File("/proc/self/mounts").readLines().size
            val initCount = java.io.File("/proc/1/mounts").readLines().size
            val delta = initCount - selfCount
            if (delta > 10) {
                RootIndicator(
                    id = "mount_ns_isolation",
                    category = DetectorCategory.MOUNT,
                    title = "Mount Namespace Delta (DenyList Heuristic)",
                    detail = "Init has $initCount mounts vs self $selfCount (delta=$delta) — large gap suggests DenyList or Magisk module isolation",
                    risk = RiskLevel.MEDIUM,
                    evidence = listOf(
                        "init mount count: $initCount",
                        "self mount count: $selfCount",
                        "delta: +$delta (threshold >10)"
                    )
                )
            } else null
        } catch (_: Exception) { null }
    }
}
