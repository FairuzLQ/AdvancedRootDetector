package id.jayatech.rootdetector.detector

import android.content.Context
import android.content.pm.ApplicationInfo
import android.provider.Settings
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

/**
 * Notification-listener abuse — a quiet way to steal one-time passwords.
 *
 * A notification listener receives the full text of every notification, so a malicious one
 * reads banking OTPs, 2FA codes and message previews without any SMS permission. Stock
 * listeners (Android System Intelligence, Wear/Auto companions, the launcher) are system apps
 * and are filtered out via FLAG_SYSTEM; only third-party listeners are reported. A listener
 * that is also a known remote-control app is escalated. Device-safety axis: never sets isRooted.
 */
internal class NotificationListenerDetector(context: Context, props: PropSnapshot = PropSnapshot()) :
    BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val setting = try {
            Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
        } catch (_: Exception) {
            return emptyList()
        }

        val thirdParty = Rules.parseFlattenedComponents(setting)
            .map { Rules.flattenedComponentPackage(it) }
            .filter { it.isNotEmpty() && !isSystemPackage(it) }
            .distinct()
        if (thirdParty.isEmpty()) return emptyList()

        val out = mutableListOf<RootIndicator>()
        val remote = thirdParty.filter { it in Rules.REMOTE_CONTROL_PACKAGES || it in Rules.SCREEN_SHARE_PACKAGES }
        if (remote.isNotEmpty()) {
            out += RootIndicator(
                id = "notif_remote_access",
                category = DetectorCategory.NOTIFICATION,
                title = "Remote-Control App Reads Your Notifications",
                detail = "A remote-control app is allowed to read every notification, including banking " +
                    "OTPs and 2FA codes. Revoke notification access unless you set this up yourself.",
                risk = RiskLevel.HIGH,
                evidence = remote.map { "$it — ${label(it)}" }
            )
        }
        val others = thirdParty - remote.toSet()
        if (others.isNotEmpty()) {
            out += RootIndicator(
                id = "notif_thirdparty_listener",
                category = DetectorCategory.NOTIFICATION,
                title = "Third-Party Notification Listener Enabled",
                detail = "A non-system app can read the text of all notifications — including one-time " +
                    "passwords and 2FA codes. Legitimate for some apps, but a common OTP-theft vector.",
                risk = RiskLevel.MEDIUM,
                evidence = others.map { "$it — ${label(it)}" }
            )
        }
        return out
    }

    private fun isSystemPackage(pkg: String): Boolean = try {
        val ai = context.packageManager.getApplicationInfo(pkg, 0)
        (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
    } catch (_: Exception) {
        false // unknown package: treat as third-party (report rather than hide)
    }

    private fun label(pkg: String): String =
        Rules.REMOTE_CONTROL_PACKAGES[pkg] ?: Rules.SCREEN_SHARE_PACKAGES[pkg]
            ?: try {
                val pm = context.packageManager
                pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
            } catch (_: Exception) { "third-party app" }
}
