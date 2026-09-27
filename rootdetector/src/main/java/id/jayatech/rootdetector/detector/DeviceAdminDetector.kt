package id.jayatech.rootdetector.detector

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

/**
 * Device-administrator / device-owner abuse.
 *
 * A Device Admin can lock or wipe the phone and, crucially, cannot be uninstalled until its
 * admin right is revoked — which is exactly why screen-locker ransomware and stalkerware ask
 * for it. A Device Owner is even stronger (full management, silent installs). Legitimate MDM
 * and "Find my device" apps use these too, and they ship as system apps on managed hardware,
 * so system admins (FLAG_SYSTEM) are filtered out and only third-party ones are reported.
 *
 * Escalations: a non-system Device Owner, or a device admin that is also a known remote-control
 * app, is HIGH. Device-safety axis: never sets isRooted. No permission required.
 */
internal class DeviceAdminDetector(context: Context, props: PropSnapshot = PropSnapshot()) :
    BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val dpm = try {
            context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
                ?: return emptyList()
        } catch (_: Exception) {
            return emptyList()
        }

        val admins = try { dpm.activeAdmins } catch (_: Exception) { null } ?: return emptyList()

        val thirdParty = admins
            .map { it.packageName }
            .filter { it.isNotEmpty() && !isSystemPackage(it) }
            .distinct()
        if (thirdParty.isEmpty()) return emptyList()

        val deviceOwner = thirdParty.filter {
            try { dpm.isDeviceOwnerApp(it) } catch (_: Exception) { false }
        }
        val remote = thirdParty.filter { it in Rules.REMOTE_CONTROL_PACKAGES }

        val out = mutableListOf<RootIndicator>()

        val severe = (deviceOwner + remote).distinct()
        if (severe.isNotEmpty()) {
            out += RootIndicator(
                id = "device_admin_privileged",
                category = DetectorCategory.DEVICE_ADMIN,
                title = "High-Privilege Device Administrator",
                detail = "A non-system app is a Device Owner or a remote-control app with device-admin " +
                    "rights — it can lock/wipe the device and resist removal. Remove it unless it is your " +
                    "own management/MDM tool.",
                risk = RiskLevel.HIGH,
                evidence = severe.map { "$it — ${label(it)}${if (it in deviceOwner) " (device owner)" else ""}" }
            )
        }
        val ordinary = thirdParty - severe.toSet()
        if (ordinary.isNotEmpty()) {
            out += RootIndicator(
                id = "device_admin_active",
                category = DetectorCategory.DEVICE_ADMIN,
                title = "Third-Party Device Administrator Active",
                detail = "A non-system app holds device-administrator rights (can lock the screen and cannot " +
                    "be uninstalled until revoked). Common in locker ransomware and stalkerware — review it.",
                risk = RiskLevel.MEDIUM,
                evidence = ordinary.map { "$it — ${label(it)}" }
            )
        }
        return out
    }

    private fun isSystemPackage(pkg: String): Boolean = try {
        val ai = context.packageManager.getApplicationInfo(pkg, 0)
        (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
    } catch (_: Exception) {
        false
    }

    private fun label(pkg: String): String =
        Rules.REMOTE_CONTROL_PACKAGES[pkg] ?: try {
            val pm = context.packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        } catch (_: Exception) { "third-party app" }
}
