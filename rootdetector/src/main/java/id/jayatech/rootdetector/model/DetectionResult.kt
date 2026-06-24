package id.jayatech.rootdetector.model

data class DetectionResult(
    val isRooted: Boolean,
    val riskScore: Int,
    val indicators: List<RootIndicator>,
    val summary: Map<DetectorCategory, List<RootIndicator>>
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
