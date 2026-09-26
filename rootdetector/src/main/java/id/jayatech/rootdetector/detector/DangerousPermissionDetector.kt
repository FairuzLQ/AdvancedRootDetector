package id.jayatech.rootdetector.detector

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

/**
 * Non-system apps holding permissions that enable on-device fraud. One pass over the installed
 * packages (with granted permissions) feeds two device-safety signals:
 *
 * - **OVERLAY** (SYSTEM_ALERT_WINDOW granted): can draw over other apps — tapjacking and
 *   fake-login / fake-PIN overlays on top of the real banking screen.
 * - **SMS** (RECEIVE_SMS / READ_SMS granted): can read incoming SMS, i.e. intercept one-time
 *   passwords.
 *
 * System apps (FLAG_SYSTEM) are excluded, so pre-installed launchers/dialers/SystemUI do not
 * show up. Device-safety axis: never sets isRooted.
 */
internal class DangerousPermissionDetector(context: Context, props: PropSnapshot = PropSnapshot()) :
    BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val packages = try {
            context.packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (_: Exception) {
            return emptyList()
        }

        val overlay = mutableListOf<String>()
        val smsReaders = mutableListOf<String>()
        val self = context.packageName

        for (pi in packages) {
            val ai = pi.applicationInfo ?: continue
            if (pi.packageName == self) continue
            if ((ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0) continue

            if (isGranted(pi, "android.permission.SYSTEM_ALERT_WINDOW")) {
                overlay += "${pi.packageName} — ${label(ai)}"
            }
            if (isGranted(pi, "android.permission.RECEIVE_SMS") ||
                isGranted(pi, "android.permission.READ_SMS")
            ) {
                smsReaders += "${pi.packageName} — ${label(ai)}"
            }
        }

        val out = mutableListOf<RootIndicator>()
        if (overlay.isNotEmpty()) {
            out += RootIndicator(
                id = "overlay_capable_apps",
                category = DetectorCategory.OVERLAY,
                title = "Apps Can Draw Over Other Apps",
                detail = "Non-system apps hold the \"display over other apps\" permission — used for " +
                    "tapjacking and fake-login overlays placed on top of the real screen.",
                risk = RiskLevel.MEDIUM,
                evidence = overlay.take(15)
            )
        }
        if (smsReaders.isNotEmpty()) {
            out += RootIndicator(
                id = "sms_reader_apps",
                category = DetectorCategory.SMS,
                title = "Apps Can Read Incoming SMS",
                detail = "Non-system apps can read incoming text messages, which is how banking OTPs and " +
                    "2FA codes get intercepted. Confirm each app has a reason to read SMS.",
                risk = RiskLevel.LOW,
                evidence = smsReaders.take(15)
            )
        }
        return out
    }

    private fun isGranted(pi: PackageInfo, permission: String): Boolean {
        val requested = pi.requestedPermissions ?: return false
        val flags = pi.requestedPermissionsFlags
        val idx = requested.indexOf(permission)
        if (idx < 0) return false
        // If the flags array is present, require the granted bit; otherwise fall back to "requested".
        if (flags != null && idx < flags.size) {
            return (flags[idx] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
        }
        return true
    }

    private fun label(ai: ApplicationInfo): String = try {
        context.packageManager.getApplicationLabel(ai).toString()
    } catch (_: Exception) { "app" }
}
