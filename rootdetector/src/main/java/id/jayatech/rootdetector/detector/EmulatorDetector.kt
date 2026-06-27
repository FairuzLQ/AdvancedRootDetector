package id.jayatech.rootdetector.detector

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

internal class EmulatorDetector(context: Context) : BaseDetector(context) {

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()
        detectBuildProps()?.let { findings += it }
        detectEmulatorFiles()?.let { findings += it }
        detectEmulatorCpuInfo()?.let { findings += it }
        detectMissingSensors()?.let { findings += it }
        return findings
    }

    /**
     * Android Build.* constants are set at boot from system props — Magisk cannot change them
     * at runtime without a reboot. Emulators always expose these; real devices never do.
     */
    private fun detectBuildProps(): RootIndicator? {
        val evidence = mutableListOf<String>()

        val fp = Build.FINGERPRINT.lowercase()
        // "generic" fingerprint means AOSP build — no real OEM/device
        if (fp.startsWith("generic") || fp.contains(":sdk/") ||
            fp.contains("emulator") || fp.contains("unknown/unknown")) {
            evidence += "FINGERPRINT=${Build.FINGERPRINT}"
        }

        when {
            Build.MODEL.equals("Android SDK built for x86", true) ||
            Build.MODEL.equals("Android SDK built for x86_64", true) ||
            Build.MODEL.equals("Android SDK built for arm64", true) ||
            Build.MODEL.equals("Emulator", true) ||
            Build.MODEL.equals("google_sdk", true) -> evidence += "MODEL=${Build.MODEL}"
        }

        if (Build.MANUFACTURER.equals("Genymotion", true)) {
            evidence += "MANUFACTURER=${Build.MANUFACTURER}"
        }

        if (Build.HARDWARE.equals("goldfish", true) ||
            Build.HARDWARE.equals("ranchu", true) ||
            Build.HARDWARE.startsWith("vbox", true)) {
            evidence += "HARDWARE=${Build.HARDWARE}"
        }

        // PRODUCT contains "sdk" exactly (not just any sdk string to avoid false positives
        // on legitimate devices with "sdk" in product name)
        if (Build.PRODUCT == "sdk" || Build.PRODUCT == "sdk_google" ||
            Build.PRODUCT == "google_sdk" || Build.PRODUCT == "sdk_x86" ||
            Build.PRODUCT == "sdk_x86_64" || Build.PRODUCT == "vbox86p") {
            evidence += "PRODUCT=${Build.PRODUCT}"
        }

        if (Build.DEVICE.equals("generic", true) ||
            Build.DEVICE.equals("emulator", true) ||
            Build.DEVICE.startsWith("vbox", true) ||
            Build.DEVICE.startsWith("generic_", true)) {
            evidence += "DEVICE=${Build.DEVICE}"
        }

        val qemu = readProp("ro.kernel.qemu")
        if (qemu == "1") evidence += "ro.kernel.qemu=1"

        val characteristics = readProp("ro.build.characteristics")
        if (characteristics.contains("emulator")) {
            evidence += "ro.build.characteristics=$characteristics"
        }

        return if (evidence.isNotEmpty()) RootIndicator(
            id = "emulator_build_props",
            category = DetectorCategory.EMULATOR,
            title = "Emulator Build Properties",
            detail = "Device build fingerprint/hardware properties match Android emulator — " +
                     "these are set at boot and cannot be changed by Magisk at runtime",
            risk = RiskLevel.HIGH,
            evidence = evidence
        ) else null
    }

    /**
     * Hardware device nodes exist only on emulators. They are in /dev which is a real tmpfs —
     * DenyList cannot hide /dev entries the same way it hides /system overlays.
     */
    private fun detectEmulatorFiles(): RootIndicator? {
        val paths = listOf(
            "/dev/socket/qemud",           // QEMU daemon socket (Goldfish)
            "/dev/qemu_pipe",              // QEMU pipe (older AVD)
            "/dev/goldfish_pipe",          // Goldfish pipe (newer Ranchu AVD)
            "/dev/goldfish_audio",         // Goldfish audio HAL
            "/dev/goldfish_sync",          // Goldfish sync driver
            "/dev/vboxguest",              // VirtualBox guest additions
            "/dev/vboxuser",               // VirtualBox user-mode
            "/dev/bst_bide",               // BlueStacks anti-detection driver
            "/.nox/",                      // Nox Player
            "/data/youwave_id",            // YouWave emulator
            "/sdcard/windows/BstSharedFolder",  // BlueStacks Windows shared dir
        )
        val found = paths.filter { fileExists(it) }
        return if (found.isNotEmpty()) RootIndicator(
            id = "emulator_files",
            category = DetectorCategory.EMULATOR,
            title = "Emulator Hardware Device Nodes",
            detail = "Device nodes in /dev that only exist in emulator environments — " +
                     "these are created by the hypervisor kernel module, not patchable by Magisk",
            risk = RiskLevel.HIGH,
            evidence = found
        ) else null
    }

    /**
     * /proc/cpuinfo hardware field is set by the kernel and cannot be changed from userspace.
     * Goldfish/Ranchu are QEMU virtual CPU names.
     */
    private fun detectEmulatorCpuInfo(): RootIndicator? {
        return try {
            val cpuInfo = java.io.File("/proc/cpuinfo").readText()
            val evidence = mutableListOf<String>()
            if (cpuInfo.contains("Goldfish", ignoreCase = true))
                evidence += "Hardware: Goldfish (QEMU/AVD)"
            if (cpuInfo.contains("Ranchu", ignoreCase = true))
                evidence += "Hardware: Ranchu (QEMU/AVD)"
            if (evidence.isNotEmpty()) RootIndicator(
                id = "emulator_cpu",
                category = DetectorCategory.EMULATOR,
                title = "Emulator CPU in /proc/cpuinfo",
                detail = "/proc/cpuinfo hardware field reveals QEMU virtual CPU — kernel-reported, unforgeable",
                risk = RiskLevel.HIGH,
                evidence = evidence
            ) else null
        } catch (_: Exception) { null }
    }

    /**
     * Real physical Android devices (especially Android 8+) always have accelerometer +
     * gyroscope. Most emulators either have zero sensors or fake sensors with telltale
     * vendor/name strings.
     *
     * This is a MEDIUM signal only — some emulators now ship good sensor simulation.
     * Use in combination with other indicators.
     */
    private fun detectMissingSensors(): RootIndicator? {
        return try {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
                ?: return null
            val evidence = mutableListOf<String>()

            if (sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) == null)
                evidence += "No accelerometer (all real Android 8+ devices have one)"

            if (sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE) == null)
                evidence += "No gyroscope (all real Android 8+ devices have one)"

            // Emulator sensors often have vendor="unknown" or "AOSP" rather than real chip names
            val accel = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
            if (accel != null && (accel.vendor.equals("unknown", true) ||
                accel.vendor.equals("AOSP", true))) {
                evidence += "Accelerometer vendor='${accel.vendor}' (real chip has manufacturer name)"
            }

            if (evidence.isNotEmpty()) RootIndicator(
                id = "emulator_sensors",
                category = DetectorCategory.EMULATOR,
                title = "Missing or Fake Hardware Sensors",
                detail = "Physical sensors absent or fake — consistent with emulator environment",
                risk = RiskLevel.MEDIUM,
                evidence = evidence
            ) else null
        } catch (_: Exception) { null }
    }
}
