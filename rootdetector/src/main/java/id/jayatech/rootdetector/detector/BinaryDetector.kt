package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator

internal class BinaryDetector(context: Context) : BaseDetector(context) {

    private val suPaths = listOf(
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/system/sbin/su", "/vendor/bin/su", "/product/bin/su",
        "/system/bin/.ext/su", "/data/local/su",
        "/data/local/bin/su", "/data/local/xbin/su",
    )

    /**
     * Root binaries that are EXCLUSIVELY created by root tools.
     *
     * REMOVED from original list (false positives):
     *  - busybox: present on many clean custom ROMs (LineageOS, GrapheneOS, etc.)
     *             and some stock Samsung/Xiaomi builds for system utilities.
     *
     * KEPT: Only binaries with no legitimate stock Android presence.
     */
    private val rootOnlyBinaries = listOf(
        "magisk", "magiskinit", "magiskpolicy", "magiskboot",
        "ksud", "ksu",
        "apd", "kpatch",
        "daemonsu",
        "frida-server",
        "resetprop", "resetprop_new",
    )

    private val searchPaths = listOf(
        "/sbin", "/system/bin", "/system/xbin", "/system/sbin",
        "/vendor/bin", "/product/bin", "/data/local/bin",
        "/data/local/xbin", "/data/local", "/data/adb",
    )

    private val fridaPaths = listOf(
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/data/frida-server",
        "/system/bin/frida-server",
    )

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()

        // 1. su binary in known locations
        val foundSu = suPaths.filter { fileExists(it) }
        if (foundSu.isNotEmpty()) {
            findings += RootIndicator(
                id = "binary_su",
                category = DetectorCategory.BINARY,
                title = "su Binary Found",
                detail = "Root shell (su) binary present in standard locations",
                risk = RiskLevel.CRITICAL,
                evidence = foundSu
            )
        }

        // 2. Root-exclusive binaries in PATH directories
        val foundBins = mutableListOf<String>()
        for (dir in searchPaths) {
            for (bin in rootOnlyBinaries) {
                val path = "$dir/$bin"
                if (fileExists(path) || canExecute(path)) foundBins += path
            }
        }
        if (foundBins.isNotEmpty()) {
            findings += RootIndicator(
                id = "binary_root_bins",
                category = DetectorCategory.BINARY,
                title = "Root Tool Binaries Found",
                detail = "Magisk/KSU/APatch or Frida binaries found in PATH directories",
                risk = RiskLevel.HIGH,
                evidence = foundBins
            )
        }

        // 3. Frida — file-based only (TCP port check removed: unreliable, any service on port 27042 would FP)
        detectFridaFiles()?.let { findings += it }

        // 4. su via PATH — `which su` returning a path is stronger than file existence alone
        detectSuViaWhich()?.let { findings += it }

        // 5. Actually execute su and observe result — most reliable test
        detectSuExecution()?.let { findings += it }

        return findings
    }

    private fun detectFridaFiles(): RootIndicator? {
        val evidence = mutableListOf<String>()
        for (path in fridaPaths) {
            if (fileExists(path)) evidence += path
        }
        // Also scan /data/local/tmp for files starting with "frida"
        try {
            java.io.File("/data/local/tmp").listFiles()?.forEach { f ->
                if (f.name.startsWith("frida", ignoreCase = true)) evidence += f.absolutePath
            }
        } catch (_: Exception) {}
        return if (evidence.isNotEmpty()) RootIndicator(
            id = "frida_file",
            category = DetectorCategory.BINARY,
            title = "Frida Server Binary Found",
            detail = "Frida dynamic instrumentation server file found — device under analysis",
            risk = RiskLevel.CRITICAL,
            evidence = evidence
        ) else null
    }

    /**
     * `which su` — if the shell can find su in PATH, root shell is available.
     *
     * FALSE POSITIVE note: on GrapheneOS/CalyxOS, su may exist as a restricted
     * stub that returns an error even when called. We check executable permission too.
     */
    private fun detectSuViaWhich(): RootIndicator? {
        val output = runShellCommand("which su").trim()
        if (output.isEmpty()) return null
        // Verify the path is actually executable
        val suFile = java.io.File(output)
        if (!suFile.canExecute() && !fileExists(output)) return null
        return RootIndicator(
            id = "binary_which_su",
            category = DetectorCategory.BINARY,
            title = "su Found in PATH",
            detail = "`which su` returned a path: $output",
            risk = RiskLevel.HIGH,
            evidence = listOf(output)
        )
    }

    private fun detectSuExecution(): RootIndicator? {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val output = process.inputStream.bufferedReader().readLine() ?: ""
            val exitCode = process.waitFor()
            if (output.contains("uid=0") || exitCode == 0) {
                RootIndicator(
                    id = "binary_su_exec",
                    category = DetectorCategory.BINARY,
                    title = "su Execution Succeeded",
                    detail = "su -c id returned uid=0 — fully functional root shell",
                    risk = RiskLevel.CRITICAL,
                    evidence = listOf(output.ifEmpty { "exit=$exitCode" })
                )
            } else null
        } catch (_: Exception) { null }
    }
}
