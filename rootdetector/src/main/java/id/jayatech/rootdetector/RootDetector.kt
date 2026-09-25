package id.jayatech.rootdetector

import android.content.Context
import id.jayatech.rootdetector.detector.*
import id.jayatech.rootdetector.model.DetectionResult
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
     * Log every indicator to logcat (tag "RootDetector"). Off by default: in a production
     * app the log tells an attacker exactly which checks fired and what to hide next.
     */
    @JvmStatic
    var loggingEnabled: Boolean = false

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
            ToolingDetector(context, props)
        )

        val allIndicators = mutableListOf<RootIndicator>()
        for (detector in detectors) {
            try {
                allIndicators += detector.detect()
            } catch (_: Throwable) {
                // never crash the host app — Errors too (LinkageError, StackOverflowError, ...)
            }
        }

        val score = allIndicators
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
            isRooted = allIndicators.any { it.risk > RiskLevel.INFO },
            riskScore = score,
            indicators = allIndicators,
            summary = summary
        )
    }

    /**
     * Strict check — true only if a HIGH/CRITICAL indicator was found.
     * Note: [DetectionResult.isRooted] is broader (any LOW+ indicator, e.g. unlocked bootloader).
     */
    fun isRooted(context: Context): Boolean =
        scan(context).indicators.any { it.risk >= RiskLevel.HIGH }
}
