package id.jayatech.rootdetector.model

enum class RiskLevel { LOW, MEDIUM, HIGH, CRITICAL }

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
    EMULATOR
}

data class RootIndicator(
    val id: String,
    val category: DetectorCategory,
    val title: String,
    val detail: String,
    val risk: RiskLevel,
    val evidence: List<String> = emptyList()
)
