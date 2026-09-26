package id.jayatech.rootdetector.detector

import android.content.Context
import android.provider.Settings
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

/**
 * Accessibility abuse — the #1 on-device scam vector.
 *
 * An Accessibility service can read everything on screen and inject taps/gestures, so
 * "refund"/bank scams talk the victim into enabling one for a remote-control or dropper app.
 * Stock screen readers (TalkBack), Switch Access and password-manager autofill also use
 * accessibility, so those are filtered out (see Rules) and only third-party services are
 * reported. A third-party service that is *also* a known remote-control app is escalated —
 * that combination (e.g. AnyDesk with accessibility granted) is an active takeover setup.
 *
 * Reported on the device-safety axis: it never makes isRooted true.
 */
internal class AccessibilityDetector(context: Context, props: PropSnapshot = PropSnapshot()) :
    BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val setting = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        } catch (_: Exception) {
            return emptyList()
        }

        val thirdParty = Rules.thirdPartyAccessibilityPackages(setting)
        if (thirdParty.isEmpty()) return emptyList()

        val out = mutableListOf<RootIndicator>()

        val remoteWithA11y = thirdParty.filter {
            it in Rules.REMOTE_CONTROL_PACKAGES || it in Rules.SCREEN_SHARE_PACKAGES
        }
        if (remoteWithA11y.isNotEmpty()) {
            out += RootIndicator(
                id = "a11y_remote_access",
                category = DetectorCategory.ACCESSIBILITY,
                title = "Remote-Control App Holds Accessibility Access",
                detail = "A remote-control / screen-sharing app can read the screen and tap for you — " +
                    "the classic remote-takeover scam setup. Revoke it if you did not enable it yourself.",
                risk = RiskLevel.HIGH,
                evidence = remoteWithA11y.map { "$it — ${label(it)}" }
            )
        }

        val others = thirdParty - remoteWithA11y.toSet()
        if (others.isNotEmpty()) {
            out += RootIndicator(
                id = "a11y_thirdparty_service",
                category = DetectorCategory.ACCESSIBILITY,
                title = "Third-Party Accessibility Service Enabled",
                detail = "A non-system app can observe the whole screen and perform gestures. Legitimate " +
                    "for some tools, but also how scam/dropper apps operate — review what enabled it.",
                risk = RiskLevel.MEDIUM,
                evidence = others.map { "$it — ${label(it)}" }
            )
        }
        return out
    }

    private fun label(pkg: String): String =
        Rules.REMOTE_CONTROL_PACKAGES[pkg] ?: Rules.SCREEN_SHARE_PACKAGES[pkg]
            ?: try {
                val pm = context.packageManager
                pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
            } catch (_: Exception) { "third-party app" }
}
