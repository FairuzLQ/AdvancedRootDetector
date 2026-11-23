package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

/**
 * Privileged / tampering tools that do NOT prove root on their own.
 *
 * Hail, Ice Box and friends freeze apps through root OR through Shizuku (adb-level
 * privileges), Dhizuku or Device Owner — all available on unrooted devices. They are
 * reported as INFO so the host app can see them without them flipping isRooted.
 */
internal class ToolingDetector(context: Context, props: PropSnapshot = PropSnapshot()) : BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val found = Rules.TOOLING_PACKAGES.filterKeys { isPackageInstalled(it) }.map { (pkg, name) -> "$pkg — $name" }
        return if (found.isEmpty()) emptyList() else listOf(
            RootIndicator(
                id = "tooling_privileged_apps",
                category = DetectorCategory.TOOLING,
                title = "Privileged / Tampering Tools Installed",
                detail = "Not proof of root — these also work via Shizuku, Dhizuku or Device Owner",
                risk = RiskLevel.INFO,
                evidence = found
            )
        )
    }
}
