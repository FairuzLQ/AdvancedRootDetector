package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

internal class MountDetector(context: Context) : BaseDetector(context) {

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()
        val mountLines = readMounts()

        detectRootOverlayOnSystem(mountLines)?.let { findings += it }
        detectRwSystem(mountLines)?.let { findings += it }
        detectDataAdb(mountLines)?.let { findings += it }
        detectMagiskTmpfs(mountLines)?.let { findings += it }
        detectZygiskMount(mountLines)?.let { findings += it }
        detectKsuMounts(mountLines)?.let { findings += it }
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
    private fun detectRootOverlayOnSystem(mounts: List<String>): RootIndicator? {
        val evidence = mutableListOf<String>()
        val targetPaths = listOf("/system", "/vendor", "/product", "/odm")

        for (line in mounts) {
            val parts = line.split(" ")
            if (parts.size < 4) continue
            val fsType = parts.getOrNull(2) ?: continue
            val mountPoint = parts.getOrNull(1) ?: continue
            val options = parts.getOrNull(3) ?: ""

            if (fsType != "overlay" && fsType != "overlayfs") continue
            // Skip /apex — stock Android always uses overlayfs here
            if (mountPoint.startsWith("/apex")) continue
            if (!targetPaths.any { mountPoint == it || mountPoint.startsWith("$it/") }) continue

            // Only flag if lowerdir points to root-tool directories
            if (options.contains("/data/adb") || options.contains("magisk") || options.contains("ksu")) {
                evidence += line.trim()
            }
        }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_overlay_system",
            category = DetectorCategory.MOUNT,
            title = "Root OverlayFS on System Partition",
            detail = "Overlay with /data/adb lowerdir on /system or /vendor — Magisk/KSU module injection",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectRwSystem(mounts: List<String>): RootIndicator? {
        val evidence = mutableListOf<String>()
        for (line in mounts) {
            val parts = line.split(" ")
            if (parts.size < 4) continue
            val mountPoint = parts[1]
            val options = parts[3].split(",")
            if (mountPoint == "/system" && options.contains("rw")) {
                evidence += line.trim()
            }
        }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_rw_system",
            category = DetectorCategory.MOUNT,
            title = "/system Mounted Read-Write",
            detail = "/system partition mounted rw — indicates root-level modification",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectDataAdb(mounts: List<String>): RootIndicator? {
        val evidence = mutableListOf<String>()
        for (line in mounts) {
            if (line.contains("/data/adb")) evidence += line.trim()
        }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_data_adb",
            category = DetectorCategory.MOUNT,
            title = "/data/adb Mount Present",
            detail = "/data/adb is mounted — active root tool storage",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }

    private fun detectMagiskTmpfs(mounts: List<String>): RootIndicator? {
        val evidence = mutableListOf<String>()
        for (line in mounts) {
            val parts = line.split(" ")
            if (parts.size < 3) continue
            val device     = parts[0]
            val mountPoint = parts[1]
            val fsType     = parts[2]
            // Match by device name "magisk" (e.g. "magisk /sbin tmpfs") OR by mount-point keyword
            val deviceIsMagisk = device.equals("magisk", ignoreCase = true)
            val pathIsMagisk   = mountPoint.contains("magisk", ignoreCase = true) ||
                                 mountPoint == "/.magisk" ||
                                 mountPoint.contains(".core")
            if (fsType == "tmpfs" && (deviceIsMagisk || pathIsMagisk) &&
                !mountPoint.contains("libzygisk")) {  // libzygisk handled by detectZygiskMount
                evidence += line.trim()
            }
        }
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
    private fun detectZygiskMount(mounts: List<String>): RootIndicator? {
        val evidence = mutableListOf<String>()
        for (line in mounts) {
            val parts = line.split(" ")
            if (parts.size < 3) continue
            val device     = parts[0]
            val mountPoint = parts[1]
            if (device.equals("magisk", ignoreCase = true) &&
                mountPoint.contains("libzygisk", ignoreCase = true)) {
                evidence += line.trim()
            }
        }
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "mount_zygisk_lib",
            category = DetectorCategory.ZYGISK,
            title = "Zygisk Library Bind-Mount Detected",
            detail = "Magisk mounts libzygisk.so into /system/lib64 via tmpfs — Zygisk framework is active",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectKsuMounts(mounts: List<String>): RootIndicator? {
        val evidence = mutableListOf<String>()
        for (line in mounts) {
            if (line.contains("/data/adb/ksu") ||
                line.contains("/data/adb/ksunext") ||
                line.contains("/data/adb/ap/")
            ) {
                evidence += line.trim()
            }
        }
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

        val rootMountMarkers = listOf(
            "/data/adb/magisk",
            "/data/adb/ksu",
            "/data/adb/ksunext",
            "/data/adb/ap",
            "/data/adb/modules",
            "/.magisk",
            "/sbin/.core"
        )

        val hiddenFromUs = rootMountMarkers.filter { marker ->
            initContent.contains(marker) && !selfContent.contains(marker)
        }

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
