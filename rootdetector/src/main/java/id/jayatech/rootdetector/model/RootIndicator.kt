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
    TOOLING,

    // ---- Device-safety axis (not root/tamper of the OS, but the user in danger) ----
    // These never make DetectionResult.isRooted true; they feed deviceThreatScore instead.
    ACCESSIBILITY,   // scam apps abusing an Accessibility service (read screen / auto-tap)
    REMOTE_ACCESS,   // remote control / screen-sharing apps (TeamViewer, AnyDesk, screen-mirror)
    NETWORK,         // MITM: system HTTP proxy, user-installed CA, active VPN tunnel
    NOTIFICATION,    // notification listener services (can read OTP codes in notifications)
    INPUT_METHOD,    // third-party keyboard / IME (a keylogger sees everything typed)
    OVERLAY,         // apps able to draw over others (tapjacking / fake-login overlays)
    SMS              // non-system apps that can read incoming SMS (OTP interception)
}

data class RootIndicator(
    val id: String,
    val category: DetectorCategory,
    val title: String,
    val detail: String,
    val risk: RiskLevel,
    val evidence: List<String> = emptyList()
)
