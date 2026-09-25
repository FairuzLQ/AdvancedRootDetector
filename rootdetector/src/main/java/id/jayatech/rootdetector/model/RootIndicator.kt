package id.jayatech.rootdetector.model

/**
 * INFO = context only (e.g. Shizuku/Hail installed): reported, but adds 0 to the score and
 * does not make [DetectionResult.isRooted] true.
 */
enum class RiskLevel { INFO, LOW, MEDIUM, HIGH, CRITICAL }

enum class DetectorCategory {
    MAGISK,
    KERNELSU,
    APATCH,
    ZYGISK,
    XPOSED,
    BINARY,
    FILESYSTEM,
    PROPS,
    MOUNT,
    NATIVE,
    INTEGRITY,
    EMULATOR,
    DEBUG,
    TOOLING
}

data class RootIndicator(
    val id: String,
    val category: DetectorCategory,
    val title: String,
    val detail: String,
    val risk: RiskLevel,
    val evidence: List<String> = emptyList()
)
