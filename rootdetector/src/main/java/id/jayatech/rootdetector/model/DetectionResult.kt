package id.jayatech.rootdetector.model

data class DetectionResult(
    val isRooted: Boolean,
    val riskScore: Int,
    val indicators: List<RootIndicator>,
    val summary: Map<DetectorCategory, List<RootIndicator>>,
    /** Wall-clock time per detector (simple class name → ms) for the scan that produced this. */
    val timingsMs: Map<String, Long> = emptyMap(),
    /**
     * Device-safety score (0–100) on a separate axis from root: accessibility abuse, remote
     * control / screen sharing, and MITM (proxy / user CA / VPN). A benign phone with a legit
     * remote-support app scores here without being flagged as rooted.
     */
    val deviceThreatScore: Int = 0,
    /** True if any device-safety indicator above INFO fired (does not imply [isRooted]). */
    val isDeviceAtRisk: Boolean = false
) {
    val riskLevel: RiskLevel
        get() = when {
            riskScore >= 80 -> RiskLevel.CRITICAL
            riskScore >= 50 -> RiskLevel.HIGH
            riskScore >= 20 -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }

    companion object {
        fun empty() = DetectionResult(
            isRooted = false,
            riskScore = 0,
            indicators = emptyList(),
            summary = emptyMap()
        )
    }
}
