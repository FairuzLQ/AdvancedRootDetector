package id.jayatech.rootdetector.detector

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest

/**
 * Device-relative platform/OEM trust — no hardcoded certificate list.
 *
 * An app is "platform-signed" if its signing certificate matches the certificate of ANY
 * FLAG_SYSTEM package on this device, i.e. it is signed by the device's own platform/OEM key.
 * This recognises a first-party app even when it is delivered under /data (no FLAG_SYSTEM) — the
 * common case on Samsung/Xiaomi, where many preinstalled apps are updated out of band and lose the
 * FLAG_SYSTEM bit. Works on any brand: Samsung signs the platform and its apps with one key, and
 * preinstalled Google/OEM apps on other devices are FLAG_SYSTEM so their signer is included too.
 *
 * Used by the device-safety detectors to downgrade a *capable* first-party app (e.g. Samsung
 * Browser holding SYSTEM_ALERT_WINDOW) from a MEDIUM concern to an INFO note: the capability is
 * still reported (transparency), but a trusted OEM app is not a false alarm. A genuinely
 * third-party app (AnyDesk, etc.) does not match and keeps its real risk level.
 *
 * Verified on a Samsung A51: com.sec.android.app.sbrowser (/data, no FLAG_SYSTEM) shares its signer
 * (SHA-256 34df0e7a…) with the platform "android" package; AnyDesk does not.
 */
internal object SignerTrust {

    @Volatile private var cache: Set<String>? = null

    private val SIGNING_FLAG =
        if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES
        else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES

    /** True if [pkg] is signed by the same certificate as some FLAG_SYSTEM package on this device. */
    fun isPlatformSigned(context: Context, pkg: String): Boolean {
        val trusted = trustedSigners(context)
        if (trusted.isEmpty()) return false
        return try {
            val pi = context.packageManager.getPackageInfo(pkg, SIGNING_FLAG)
            certSha256(pi).any { it in trusted }
        } catch (_: Throwable) { false }
    }

    /** SHA-256 (hex) of every signing cert used by a FLAG_SYSTEM package. Computed once, cached. */
    private fun trustedSigners(context: Context): Set<String> {
        cache?.let { return it }
        val out = HashSet<String>()
        try {
            val pm = context.packageManager
            @Suppress("DEPRECATION")
            val pkgs = pm.getInstalledPackages(SIGNING_FLAG)
            for (pi in pkgs) {
                val ai = pi.applicationInfo ?: continue
                if ((ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) == 0) continue
                out += certSha256(pi)
            }
        } catch (_: Throwable) {}
        cache = out
        return out
    }

    private fun certSha256(pi: PackageInfo): List<String> {
        val certs: Array<Signature>? = try {
            if (Build.VERSION.SDK_INT >= 28) {
                val si = pi.signingInfo ?: return emptyList()
                if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
            } else {
                @Suppress("DEPRECATION") pi.signatures
            }
        } catch (_: Throwable) { null }
        if (certs.isNullOrEmpty()) return emptyList()
        val md = MessageDigest.getInstance("SHA-256")
        return certs.map { s -> md.digest(s.toByteArray()).joinToString("") { "%02x".format(it) } }
    }
}
