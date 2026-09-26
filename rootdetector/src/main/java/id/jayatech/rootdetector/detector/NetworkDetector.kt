package id.jayatech.rootdetector.detector

import android.content.Context
import android.provider.Settings
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules
import java.net.NetworkInterface
import java.security.KeyStore
import java.util.Collections

/**
 * Man-in-the-middle / traffic-interception signals — all readable without any permission.
 *
 * - **User-installed CA** (HIGH): a certificate the user added to the trust store. Since
 *   Android 7 apps do not trust user CAs by default, but its presence is the hallmark of a
 *   traffic-intercepting proxy (Burp/mitmproxy/Charles) or a corporate/MDM inspection setup.
 * - **System HTTP proxy** (MEDIUM): a global proxy is configured, so traffic that honours it
 *   is routed through another host — combined with a user CA this is full TLS interception.
 * - **Active VPN tunnel** (INFO): a tun/ppp/wg interface is up. Usually benign, but relevant
 *   context: all traffic is flowing through another endpoint.
 *
 * Device-safety axis: none of these make isRooted true.
 */
internal class NetworkDetector(context: Context, props: PropSnapshot = PropSnapshot()) :
    BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val out = mutableListOf<RootIndicator>()

        userInstalledCas()?.let { out += it }
        httpProxy()?.let { out += it }
        vpnTunnel()?.let { out += it }

        return out
    }

    /** Aliases in the AndroidCAStore prefixed "user:" are CAs the user (or an MDM) added. */
    private fun userInstalledCas(): RootIndicator? {
        val userCaCount = try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            Collections.list(ks.aliases()).count { Rules.isUserCaAlias(it) }
        } catch (_: Exception) {
            return null
        }
        if (userCaCount == 0) return null
        return RootIndicator(
            id = "net_user_ca",
            category = DetectorCategory.NETWORK,
            title = "User-Installed CA Certificate",
            detail = "A user-added root certificate is trusted on this device — the classic setup for " +
                "TLS interception (a proxy that decrypts HTTPS). Expected only if you knowingly installed it.",
            risk = RiskLevel.HIGH,
            evidence = listOf("$userCaCount user CA certificate(s) in AndroidCAStore")
        )
    }

    /** Global HTTP proxy from JVM system properties and Settings.Global.HTTP_PROXY. */
    private fun httpProxy(): RootIndicator? {
        val evidence = mutableListOf<String>()

        val host = System.getProperty("http.proxyHost")
        val port = System.getProperty("http.proxyPort")
        if (Rules.proxyIsSet(host, port)) evidence += "system property http.proxyHost=$host:$port"

        val global = try {
            Settings.Global.getString(context.contentResolver, "http_proxy")
        } catch (_: Exception) { null }
        Rules.parseHttpProxySetting(global)?.let { (h, p) -> evidence += "Settings.Global.http_proxy=$h:$p" }

        if (evidence.isEmpty()) return null
        return RootIndicator(
            id = "net_http_proxy",
            category = DetectorCategory.NETWORK,
            title = "System HTTP Proxy Configured",
            detail = "Network traffic is routed through a proxy host. With a user CA installed this allows " +
                "full HTTPS interception; on its own it can still capture or redirect plaintext traffic.",
            risk = RiskLevel.MEDIUM,
            evidence = evidence
        )
    }

    /** A tun/ppp/wireguard interface that is up means a VPN/tunnel is active. */
    private fun vpnTunnel(): RootIndicator? {
        val tunnels = try {
            Collections.list(NetworkInterface.getNetworkInterfaces())
                .filter { it.isUp && Rules.isVpnInterfaceName(it.name) }
                .map { it.name }
        } catch (_: Exception) {
            return null
        }
        if (tunnels.isEmpty()) return null
        return RootIndicator(
            id = "net_vpn",
            category = DetectorCategory.NETWORK,
            title = "Active VPN / Tunnel Interface",
            detail = "A VPN or tunnel interface is up, so traffic is flowing through another endpoint. " +
                "Usually benign — reported as context alongside proxy / CA signals.",
            risk = RiskLevel.INFO,
            evidence = tunnels.map { "interface $it is up" }
        )
    }
}
