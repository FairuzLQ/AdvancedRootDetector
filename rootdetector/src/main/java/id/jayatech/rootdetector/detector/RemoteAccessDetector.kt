package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

/**
 * Remote-control and screen-sharing apps installed on the device.
 *
 * These are legitimate for IT support, but their presence during a banking/checkout flow is a
 * strong fraud signal: scammers get victims to install AnyDesk/TeamViewer to drive the phone,
 * or a screen-mirror app to watch OTPs. Reported on the device-safety axis (MEDIUM, does not
 * make isRooted true) so a host app can, for example, block transfers while one is installed.
 * The AccessibilityDetector escalates to HIGH when such an app also holds accessibility access.
 */
internal class RemoteAccessDetector(context: Context, props: PropSnapshot = PropSnapshot()) :
    BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val out = mutableListOf<RootIndicator>()

        val remote = Rules.REMOTE_CONTROL_PACKAGES.filterKeys { isPackageInstalled(it) }
            .map { (pkg, name) -> "$pkg — $name" }
        if (remote.isNotEmpty()) {
            out += RootIndicator(
                id = "remote_control_apps",
                category = DetectorCategory.REMOTE_ACCESS,
                title = "Remote-Control App Installed",
                detail = "An app that lets someone else operate this phone is installed. Common in " +
                    "\"tech support\"/refund scams — be sure you installed it and know who is connected.",
                risk = RiskLevel.MEDIUM,
                evidence = remote
            )
        }

        val share = Rules.SCREEN_SHARE_PACKAGES.filterKeys { isPackageInstalled(it) }
            .map { (pkg, name) -> "$pkg — $name" }
        if (share.isNotEmpty()) {
            out += RootIndicator(
                id = "screen_share_apps",
                category = DetectorCategory.REMOTE_ACCESS,
                title = "Screen-Sharing / Mirroring App Installed",
                detail = "An app that can mirror this screen to another device is installed — a way for " +
                    "an attacker to watch passwords and one-time codes as you type them.",
                risk = RiskLevel.MEDIUM,
                evidence = share
            )
        }
        return out
    }
}
