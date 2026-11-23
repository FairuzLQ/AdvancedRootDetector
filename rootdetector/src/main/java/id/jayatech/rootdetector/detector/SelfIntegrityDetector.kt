package id.jayatech.rootdetector.detector

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import id.jayatech.rootdetector.RootDetector
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Self-integrity / anti-tamper — detects that THIS app was repackaged or re-signed.
 *
 * The Frida/debugger/hook checks (DebugDetector, NativeDetector) defend the running process, but an
 * attacker who patches the APK (apktool, smali edits to short-circuit the scan) and re-signs it gets
 * a build whose checks were removed. The one thing a patched build cannot keep is the original
 * signing certificate — re-signing always changes it. So:
 *
 *  1. **Signature pin** (`integrity_resigned`, CRITICAL): if the host app pins its release signer via
 *     [RootDetector.expectedSignaturesSha256] and the running app's signer is not in that set, the
 *     APK was repackaged and re-signed. Zero false positives when configured — the app knows its own
 *     signer. (No pin set → this check is skipped.)
 *  2. **Debug-keystore signature** (`integrity_debug_signed`, INFO): the cert subject is
 *     `CN=Android Debug` — a testing/repackaged build (most casual repackaging re-signs with the
 *     default debug keystore), never a production release. Reported as INFO so a legitimate debug
 *     build is noted but not treated as an attack.
 *
 * Root/tamper axis (INTEGRITY): a re-signed app is tampering and sets isRooted.
 */
internal class SelfIntegrityDetector(context: Context, props: PropSnapshot = PropSnapshot()) :
    BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val certs = try { ownCerts() } catch (_: Throwable) { return emptyList() }
        if (certs.isEmpty()) return emptyList()

        val out = mutableListOf<RootIndicator>()
        val sha = certs.map { sha256Hex(it) }
        val subjects = certs.mapNotNull { x509Subject(it) }

        val expected = RootDetector.expectedSignaturesSha256
        if (expected.isNotEmpty() && sha.none { s -> expected.any { it.equals(s, ignoreCase = true) } }) {
            out += RootIndicator(
                id = "integrity_resigned",
                category = DetectorCategory.INTEGRITY,
                title = "App Repackaged / Re-signed",
                detail = "The running app's signing certificate does not match the release signer the " +
                    "app expects — the APK was repackaged and re-signed (tampered build).",
                risk = RiskLevel.CRITICAL,
                evidence = listOf("actual signer sha256=${sha.firstOrNull()?.take(32)}…")
            )
        }

        val debugSubjects = subjects.filter { it.contains("Android Debug", ignoreCase = true) }
        if (debugSubjects.isNotEmpty()) {
            out += RootIndicator(
                id = "integrity_debug_signed",
                category = DetectorCategory.INTEGRITY,
                title = "Debug-Keystore Signature",
                detail = "The app is signed with an Android debug keystore (CN=Android Debug) — a " +
                    "testing or repackaged build, not a production release.",
                risk = RiskLevel.INFO,
                evidence = debugSubjects.take(2)
            )
        }
        return out
    }

    private fun ownCerts(): List<ByteArray> {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val flag = if (Build.VERSION.SDK_INT >= 28)
            PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        val pi = pm.getPackageInfo(context.packageName, flag)
        val sigs: Array<Signature>? = if (Build.VERSION.SDK_INT >= 28) {
            val si = pi.signingInfo ?: return emptyList()
            if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        } else {
            @Suppress("DEPRECATION") pi.signatures
        }
        return sigs?.map { it.toByteArray() } ?: emptyList()
    }

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun x509Subject(b: ByteArray): String? = try {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(b.inputStream()) as X509Certificate
        cert.subjectDN.name
    } catch (_: Throwable) { null }
}
