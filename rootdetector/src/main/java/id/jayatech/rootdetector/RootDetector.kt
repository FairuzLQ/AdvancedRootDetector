package id.jayatech.rootdetector

import android.content.Context
import id.jayatech.rootdetector.detector.*
import id.jayatech.rootdetector.model.DetectionResult
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

/**
 * Entry point for advanced root detection.
 *
 * Usage (call from a background thread — the scan forks subprocesses and generates a
 * hardware-backed key, which can take a few seconds on slow devices):
 *   val result = RootDetector.scan(context)
 *   if (result.isRooted) { ... }
 */
object RootDetector {

    private val RISK_WEIGHTS = mapOf(
        RiskLevel.INFO to 0,
        RiskLevel.LOW to 5,
        RiskLevel.MEDIUM to 15,
        RiskLevel.HIGH to 30,
        RiskLevel.CRITICAL to 50
    )

    /**
     * Device-safety categories: scam/fraud signals about the user's environment, not a tampered
     * OS. They are scored on a separate axis (deviceThreatScore) and never make isRooted true —
     * a phone with a legitimate remote-support app or a corporate VPN is not "rooted".
     */
    private val DEVICE_THREAT_CATEGORIES = setOf(
        DetectorCategory.ACCESSIBILITY,
        DetectorCategory.REMOTE_ACCESS,
        DetectorCategory.NETWORK
    )

    /**
     * Log every indicator to logcat (tag "RootDetector"). Off by default: in a production
     * app the log tells an attacker exactly which checks fired and what to hide next.
     */
    @JvmStatic
    var loggingEnabled: Boolean = false

    /**
     * Actually execute `su -c id`. Off by default: on a rooted device this pops up the root
     * manager's superuser prompt in front of the host app's user and blocks the scan for
     * ~2 s (measured in the lab). The su binary itself is still detected without executing it.
     */
    @JvmStatic
    var suExecutionEnabled: Boolean = false

    fun scan(context: Context): DetectionResult {
        // One getprop snapshot shared by every detector in this scan.
        val props = PropSnapshot()
        val detectors = listOf(
            MagiskDetector(context, props),
            KernelSUDetector(context, props),
            APatchDetector(context, props),
            ZygiskDetector(context, props),
            XposedDetector(context, props),
            BinaryDetector(context, props),
            FileSystemDetector(context, props),
            PropsDetector(context, props),
            MountDetector(context, props),
            NativeDetector(context, props),
            IntegrityDetector(context, props),
            EmulatorDetector(context, props),
            DebugDetector(context, props),
            ToolingDetector(context, props),
            AccessibilityDetector(context, props),
            RemoteAccessDetector(context, props),
            NetworkDetector(context, props)
        )

        val allIndicators = mutableListOf<RootIndicator>()
        val timings = linkedMapOf<String, Long>()
        for (detector in detectors) {
            val start = System.nanoTime()
            try {
                allIndicators += detector.detect()
            } catch (_: Throwable) {
                // never crash the host app — Errors too (LinkageError, StackOverflowError, ...)
            }
            timings[detector.javaClass.simpleName] = (System.nanoTime() - start) / 1_000_000
        }

        val (deviceIndicators, rootIndicators) =
            allIndicators.partition { it.category in DEVICE_THREAT_CATEGORIES }

        // Root/tamper score (unchanged meaning): only root-axis indicators feed it.
        val score = rootIndicators
            .sumOf { RISK_WEIGHTS[it.risk] ?: 0 }
            .coerceAtMost(100)

        val deviceScore = deviceIndicators
            .sumOf { RISK_WEIGHTS[it.risk] ?: 0 }
            .coerceAtMost(100)

        val summary = allIndicators.groupBy { it.category }

        // Logcat export — read with: adb logcat -s RootDetector:I
        if (loggingEnabled) {
            android.util.Log.i("RootDetector", "=== SCAN COMPLETE: ${allIndicators.size} indicators, score=$score ===")
            allIndicators.forEach { ind ->
                android.util.Log.i("RootDetector", "[${ind.risk}] ${ind.category} | ${ind.id} | ${ind.title}")
                ind.evidence.take(3).forEach { ev -> android.util.Log.i("RootDetector", "   evidence: $ev") }
            }
        }

        return DetectionResult(
            // Root verdict is root-axis only: device-safety signals never flip it.
            isRooted = rootIndicators.any { it.risk > RiskLevel.INFO },
            riskScore = score,
            indicators = allIndicators,
            summary = summary,
            timingsMs = timings,
            deviceThreatScore = deviceScore,
            isDeviceAtRisk = deviceIndicators.any { it.risk > RiskLevel.INFO }
        )
    }

    /**
     * Strict check — true only if a HIGH/CRITICAL indicator was found.
     * Note: [DetectionResult.isRooted] is broader (any LOW+ indicator, e.g. unlocked bootloader).
     */
    fun isRooted(context: Context): Boolean =
        scan(context).indicators.any {
            it.risk >= RiskLevel.HIGH && it.category !in DEVICE_THREAT_CATEGORIES
        }
}
