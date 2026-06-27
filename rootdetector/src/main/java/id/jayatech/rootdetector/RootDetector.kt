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
 * Usage:
 *   val result = RootDetector.scan(context)
 *   if (result.isRooted) { ... }
 */
object RootDetector {

    private val RISK_WEIGHTS = mapOf(
        RiskLevel.LOW to 5,
        RiskLevel.MEDIUM to 15,
        RiskLevel.HIGH to 30,
        RiskLevel.CRITICAL to 50
    )

    fun scan(context: Context): DetectionResult {
        val detectors = listOf(
            MagiskDetector(context),
            KernelSUDetector(context),
            APatchDetector(context),
            ZygiskDetector(context),
            XposedDetector(context),
            BinaryDetector(context),
            FileSystemDetector(context),
            PropsDetector(context),
            MountDetector(context),
            NativeDetector(context),
            IntegrityDetector(context),
            EmulatorDetector(context)
        )

        val allIndicators = mutableListOf<RootIndicator>()
        for (detector in detectors) {
            try {
                allIndicators += detector.detect()
            } catch (_: Exception) { /* never crash the host app */ }
        }

        val score = allIndicators
            .sumOf { RISK_WEIGHTS[it.risk] ?: 0 }
            .coerceAtMost(100)

        val summary = allIndicators.groupBy { it.category }

        return DetectionResult(
            isRooted = allIndicators.isNotEmpty(),
            riskScore = score,
            indicators = allIndicators,
            summary = summary
        )
    }

    /** Quick check — returns true if any HIGH/CRITICAL indicator found. */
    fun isRooted(context: Context): Boolean =
        scan(context).indicators.any { it.risk >= RiskLevel.HIGH }
}
