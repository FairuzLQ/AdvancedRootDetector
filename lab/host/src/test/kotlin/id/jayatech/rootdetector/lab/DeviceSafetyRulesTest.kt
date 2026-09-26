package id.jayatech.rootdetector.lab

import id.jayatech.rootdetector.rules.Rules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit coverage for the device-safety pure rules (accessibility abuse, MITM proxy/VPN/CA).
 * These signals come from Android APIs, not /proc captures, so they are unit-tested here
 * rather than as fixture scenarios in RuleLabTest.
 */
class DeviceSafetyRulesTest {

    @Test fun parsesEnabledAccessibilityServices() {
        val s = "com.foo/.A:com.bar/com.bar.B: :bad"
        assertEquals(listOf("com.foo/.A", "com.bar/com.bar.B"), Rules.parseEnabledAccessibilityServices(s))
        assertTrue(Rules.parseEnabledAccessibilityServices(null).isEmpty())
        assertTrue(Rules.parseEnabledAccessibilityServices("").isEmpty())
    }

    @Test fun stockAccessibilityServicesAreNotThreats() {
        // TalkBack + a password manager enabled: both are legitimate, so nothing is reported.
        val stock = "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService" +
            ":com.bitwarden/com.x8bit.bitwarden.Accessibility"
        assertTrue(Rules.thirdPartyAccessibilityPackages(stock).isEmpty())
    }

    @Test fun thirdPartyAccessibilityIsReported() {
        val s = "com.google.android.marvin.talkback/.TalkBackService:com.anydesk.anydeskandroid/.AdControlService"
        assertEquals(listOf("com.anydesk.anydeskandroid"), Rules.thirdPartyAccessibilityPackages(s))
        // and that package is a known remote-control app → the detector escalates it to HIGH
        assertTrue("com.anydesk.anydeskandroid" in Rules.REMOTE_CONTROL_PACKAGES)
    }

    @Test fun httpProxyDetection() {
        assertTrue(Rules.proxyIsSet("10.0.0.2", "8080"))
        assertFalse(Rules.proxyIsSet(null, "8080"))
        assertFalse(Rules.proxyIsSet("", "8080"))
        assertFalse(Rules.proxyIsSet("10.0.0.2", "0"))
        assertFalse(Rules.proxyIsSet("10.0.0.2", "notaport"))

        assertEquals("proxy.local" to "3128", Rules.parseHttpProxySetting("proxy.local:3128"))
        assertEquals(null, Rules.parseHttpProxySetting(":0"))
        assertEquals(null, Rules.parseHttpProxySetting(""))
        assertEquals(null, Rules.parseHttpProxySetting(null))
    }

    @Test fun vpnInterfaceNames() {
        listOf("tun0", "ppp0", "tap1", "ipsec0", "wg0").forEach {
            assertTrue(it, Rules.isVpnInterfaceName(it))
        }
        listOf("wlan0", "eth0", "rmnet0", "lo", "dummy0").forEach {
            assertFalse(it, Rules.isVpnInterfaceName(it))
        }
    }

    @Test fun userCaAliasVsSystem() {
        assertTrue(Rules.isUserCaAlias("user:1234"))
        assertFalse(Rules.isUserCaAlias("system:1234"))
    }
}
