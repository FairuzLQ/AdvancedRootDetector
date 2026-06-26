package id.jayatech.rootdetector.detector

import android.content.Context
import android.os.Build
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

internal class PropsDetector(context: Context) : BaseDetector(context) {

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()
        detectTestKeys()?.let { findings += it }
        detectInsecureBuild()?.let { findings += it }
        detectSeLinux()?.let { findings += it }
        detectBootloaderState()?.let { findings += it }
        detectRootRuntimeProps()?.let { findings += it }
        return findings
    }

    /**
     * test-keys = device signed with Android test signing keys instead of OEM release keys.
     *
     * FALSE POSITIVE notes:
     *  - MIUI/Xiaomi beta/userdebug builds, some OEM dev editions ship with test-keys.
     *  - GrapheneOS and some hardened ROMs use test-keys (not root related).
     *  - Risk is MEDIUM alone; escalate only when combined with other indicators.
     */
    private fun detectTestKeys(): RootIndicator? {
        val tags = Build.TAGS ?: ""
        val fingerprint = Build.FINGERPRINT ?: ""
        if (tags.contains("test-keys") || fingerprint.contains("test-keys")) {
            return RootIndicator(
                id = "props_test_keys",
                category = DetectorCategory.PROPS,
                title = "Test-Keys Build Signature",
                detail = "Device signed with test keys — suspicious but also seen on some OEM beta builds",
                risk = RiskLevel.MEDIUM,
                evidence = listOf(
                    "ro.build.tags=$tags",
                    "ro.build.fingerprint=${fingerprint.take(80)}"
                )
            )
        }
        return null
    }

    /**
     * FALSE POSITIVE notes:
     *  - ro.debuggable=1: common on MIUI userdebug, OnePlus OxygenOS beta, Samsung dev editions.
     *  - ro.secure=0: more definitive — rarely set on stock release builds.
     *  - ro.build.type=userdebug/eng: MIUI ships this on some regions; Pixel factory images have it.
     *  - We only flag ro.debuggable alone as LOW; ro.secure=0 remains HIGH.
     */
    private fun detectInsecureBuild(): RootIndicator? {
        val evidence = mutableListOf<String>()
        var maxRisk = RiskLevel.LOW

        val secure = readProp("ro.secure")
        if (secure == "0") {
            evidence += "ro.secure=0 (no security enforced)"
            maxRisk = RiskLevel.HIGH
        }

        val debuggable = readProp("ro.debuggable")
        if (debuggable == "1") {
            evidence += "ro.debuggable=1"
            if (maxRisk < RiskLevel.MEDIUM) maxRisk = RiskLevel.MEDIUM
        }

        val buildType = Build.TYPE
        if (buildType == "userdebug" || buildType == "eng") {
            evidence += "ro.build.type=$buildType (also common on OEM beta/dev builds)"
            if (maxRisk < RiskLevel.MEDIUM) maxRisk = RiskLevel.MEDIUM
        }

        return if (evidence.isNotEmpty()) RootIndicator(
            id = "props_insecure_build",
            category = DetectorCategory.PROPS,
            title = "Insecure Build Properties",
            detail = "Build properties suggest debug/insecure system — also present on some stock OEM builds",
            risk = maxRisk,
            evidence = evidence
        ) else null
    }

    /**
     * SELinux permissive mode is a strong root indicator.
     * Clean devices ALWAYS run SELinux in enforcing mode.
     * Permissive is only seen after explicit `setenforce 0` which requires root,
     * or on devices where the kernel was patched to disable it.
     */
    private fun detectSeLinux(): RootIndicator? {
        val evidence = mutableListOf<String>()
        try {
            val enforce = java.io.File("/sys/fs/selinux/enforce").readText().trim()
            if (enforce == "0") evidence += "SELinux enforce=0 (permissive)"
        } catch (_: Exception) {}

        val bootSelinux = readProp("ro.boot.selinux")
        if (bootSelinux == "permissive") evidence += "ro.boot.selinux=permissive"

        return if (evidence.isNotEmpty()) RootIndicator(
            id = "props_selinux",
            category = DetectorCategory.PROPS,
            title = "SELinux Not Enforcing",
            detail = "SELinux is permissive — root exploits run unrestricted. Not seen on any stock ROM.",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    /**
     * Bootloader state detection.
     *
     * FALSE POSITIVE notes:
     *  - "yellow" = custom key, seen on some OEM devices with special signing (not root).
     *  - "orange" = unlocked bootloader. Many developers unlock legally without root.
     *  - Unlocked bootloader ≠ rooted, but is a prerequisite for most root methods.
     *  - Risk: MEDIUM (bootloader unlocked is suspicious context, not proof).
     *  - "green" = fully locked and verified — safe.
     */
    /**
     * Magisk/Kitsune/KSU set runtime props during init scripts.
     * DenyList only isolates mount namespaces — it does NOT clean system props.
     * Props live in kernel shared memory (/dev/__properties__) and are immune to DenyList.
     *
     * We use a subprocess for getprop because Zygisk/Shamiko hooks prop access
     * IN OUR PROCESS, but the subprocess (exec'd fresh) has no Zygisk injection.
     */
    private fun detectRootRuntimeProps(): RootIndicator? {
        val directProps = listOf(
            "ro.magisk.version",
            "persist.sys.zygisk",
            "ro.build.selinux",
        )
        val evidence = mutableListOf<String>()

        // One subprocess dumps all props — parse directly instead of N getprop calls.
        // getprop piped to grep is fast; 3 s timeout is generous for old devices.
        val grepOut = runShellCommand(
            "getprop | grep -iE 'magisk|zygisk|kitsune|apatch|ksu|supersu'",
            timeoutMs = 3000
        )
        grepOut.lines().filter { it.isNotBlank() }.take(8).forEach { evidence += it.trim() }

        // Also check specific keys in case grep fails or prop has unusual format
        for (key in directProps) {
            val v = readProp(key)
            if (v.isNotEmpty() && !evidence.any { it.contains(key) }) evidence += "$key=$v"
        }

        return if (evidence.isNotEmpty()) RootIndicator(
            id = "props_root_runtime",
            category = DetectorCategory.PROPS,
            title = "Root Runtime Properties",
            detail = "Magisk/Kitsune/Zygisk system props found — DenyList cannot remove these",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    private fun detectBootloaderState(): RootIndicator? {
        val evidence = mutableListOf<String>()
        var risk = RiskLevel.LOW

        val bootState = readProp("ro.boot.verifiedbootstate")
        when (bootState) {
            "orange" -> {
                evidence += "ro.boot.verifiedbootstate=orange (bootloader unlocked)"
                risk = RiskLevel.MEDIUM
            }
            "yellow" -> {
                evidence += "ro.boot.verifiedbootstate=yellow (custom signing key)"
                risk = RiskLevel.LOW
            }
        }

        val vbmeta = readProp("ro.boot.vbmeta.device_state")
        if (vbmeta == "unlocked") {
            evidence += "ro.boot.vbmeta.device_state=unlocked"
            if (risk < RiskLevel.MEDIUM) risk = RiskLevel.MEDIUM
        }

        // Xiaomi-specific bootloader state
        val miuiLock = readProp("ro.secureboot.lockstate")
        if (miuiLock == "unlocked") {
            evidence += "ro.secureboot.lockstate=unlocked (Xiaomi bootloader)"
            if (risk < RiskLevel.MEDIUM) risk = RiskLevel.MEDIUM
        }

        return if (evidence.isNotEmpty() && risk >= RiskLevel.MEDIUM) RootIndicator(
            id = "props_bootloader",
            category = DetectorCategory.PROPS,
            title = "Bootloader Unlocked",
            detail = "Bootloader is not locked — prerequisite for most root methods (not proof alone)",
            risk = risk,
            evidence = evidence
        ) else null
    }
}

