package id.jayatech.rootdetector.detector

import android.content.Context
import android.content.pm.ApplicationInfo
import android.provider.Settings
import android.view.inputmethod.InputMethodManager
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

/**
 * Third-party input method (keyboard) — a keyboard is a legitimate keylogger.
 *
 * A custom IME sees every keystroke, including passwords and card numbers, and can send them
 * off-device. Pre-installed keyboards (Gboard, Samsung Keyboard, the AOSP IME) are system apps
 * and fine; this reports only non-system IMEs, distinguishing an *enabled* one (LOW) from the
 * *active* one (MEDIUM — it is receiving your keystrokes now). Device-safety axis: never sets
 * isRooted. Detected via InputMethodManager + Settings.Secure, no permission required.
 */
internal class InputMethodDetector(context: Context, props: PropSnapshot = PropSnapshot()) :
    BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val imm = try {
            context.getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
                ?: return emptyList()
        } catch (_: Exception) {
            return emptyList()
        }

        val enabled = try { imm.enabledInputMethodList } catch (_: Exception) { emptyList() }
        val thirdParty = enabled.filter { imi ->
            val flags = imi.serviceInfo?.applicationInfo?.flags ?: 0
            (flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) == 0
        }
        if (thirdParty.isEmpty()) return emptyList()

        val defaultId = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)
        } catch (_: Exception) { null }.orEmpty()

        val active = thirdParty.firstOrNull { defaultId.startsWith(it.packageName + "/") || defaultId == it.id }
        if (active != null) {
            return listOf(
                RootIndicator(
                    id = "ime_active_thirdparty",
                    category = DetectorCategory.INPUT_METHOD,
                    title = "Third-Party Keyboard Is Active",
                    detail = "A non-system keyboard is your current input method, so it sees everything you " +
                        "type — passwords, card numbers, messages. Only use keyboards you trust.",
                    risk = RiskLevel.MEDIUM,
                    evidence = listOf("${active.packageName} — ${label(active.packageName)}")
                )
            )
        }
        return listOf(
            RootIndicator(
                id = "ime_thirdparty_enabled",
                category = DetectorCategory.INPUT_METHOD,
                title = "Third-Party Keyboard Enabled",
                detail = "A non-system keyboard is enabled (not currently active). A keyboard can log every " +
                    "keystroke if selected — review whether you trust it.",
                risk = RiskLevel.LOW,
                evidence = thirdParty.map { "${it.packageName} — ${label(it.packageName)}" }
            )
        )
    }

    private fun label(pkg: String): String = try {
        val pm = context.packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
    } catch (_: Exception) { "third-party keyboard" }
}
