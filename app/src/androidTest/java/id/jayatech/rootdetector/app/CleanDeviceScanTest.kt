package id.jayatech.rootdetector.app

import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import id.jayatech.rootdetector.RootDetector
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * False-positive gate for real devices (Firebase Test Lab — see lab/firebase/README.md).
 *
 * Test Lab devices are stock and not rooted, so any root indicator here is a false positive.
 * Allowed: INFO indicators (e.g. the test APK is debuggable), the EMULATOR category on virtual
 * devices, and bootloader-unlocked signals — Test Lab's farm phones are unlocked (verified by
 * hardware attestation on a Pixel), which is a true fact about the device, not root.
 */
@RunWith(AndroidJUnit4::class)
class CleanDeviceScanTest {

    @Test
    fun stockDeviceHasNoRootIndicators() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val result = RootDetector.scan(context)

        val device = "${Build.MANUFACTURER} ${Build.MODEL} (API ${Build.VERSION.SDK_INT}, ${Build.FINGERPRINT})"
        Log.i(TAG, "device: $device")
        Log.i(TAG, "timingsMs: ${result.timingsMs} total=${result.timingsMs.values.sum()}")
        result.indicators.forEach { Log.i(TAG, "[${it.risk}] ${it.id} ${it.evidence.take(3)}") }

        val unexpected = result.indicators.filter {
            it.risk > RiskLevel.INFO && it.category != DetectorCategory.EMULATOR &&
                it.category !in DEVICE_THREAT_CATEGORIES && it.id !in UNLOCKED_BOOTLOADER
        }
        assertTrue(
            "False positive on stock device $device:\n" + unexpected.joinToString("\n") {
                "  [${it.risk}] ${it.id}: ${it.title} — ${it.evidence.take(3)}"
            },
            unexpected.isEmpty()
        )
    }

    private companion object {
        const val TAG = "RDLAB"
        val UNLOCKED_BOOTLOADER = setOf("props_bootloader", "integrity_key_attest")

        // Device-safety axis (scam/MITM signals about the environment, not a tampered OS).
        // This test is a *root* false-positive gate, so these categories are out of scope here.
        val DEVICE_THREAT_CATEGORIES = setOf(
            DetectorCategory.ACCESSIBILITY,
            DetectorCategory.REMOTE_ACCESS,
            DetectorCategory.NETWORK,
            DetectorCategory.NOTIFICATION,
            DetectorCategory.INPUT_METHOD,
            DetectorCategory.OVERLAY,
            DetectorCategory.SMS
        )
    }
}
