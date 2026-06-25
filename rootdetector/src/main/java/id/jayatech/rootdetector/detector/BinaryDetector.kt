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

        // 3. Frida — file-based (by known name)
        detectFridaFiles()?.let { findings += it }

        // 3b. Renamed Frida binary — large ELF in temp dirs (Frida server is 30-60MB, hard to fake)
        detectRenamedLargeElf()?.let { findings += it }

        // 4. su via PATH — shell subprocess is not affected by Zygisk in-process hooks
        detectSuViaWhich()?.let { findings += it }

        // 4b. Other root-exclusive binaries via `which` — same subprocess isolation
        detectRootBinsViaWhich()?.let { findings += it }

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
     * Scan /data/local/tmp for large ELF executables that don't have "frida" in the name.
     * Frida-server is ~30-60MB. Legitimate tools in this dir are small (<5MB).
     * An unknown large ELF there is strongly suspicious — renamed Frida or other root tool.
     */
    private fun detectRenamedLargeElf(): RootIndicator? {
        val elfMagic = byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
        val minSizeBytes = 20L * 1024 * 1024 // 20MB lower bound
        val searchDirs = listOf("/data/local/tmp", "/data/local")
        val evidence = mutableListOf<String>()

        for (dir in searchDirs) {
            val d = java.io.File(dir)
            if (!d.exists() || !d.isDirectory) continue
            d.listFiles()?.forEach { f ->
                if (!f.isFile) return@forEach
                if (f.name.startsWith("frida", ignoreCase = true)) return@forEach // already caught
                if (f.length() < minSizeBytes) return@forEach
                try {
                    java.io.RandomAccessFile(f, "r").use { raf ->
                        val magic = ByteArray(4)
                        if (raf.read(magic) == 4 && magic.contentEquals(elfMagic)) {
                            evidence += "${f.absolutePath} (${f.length() / 1024 / 1024}MB, ELF)"
                        }
                    }
                } catch (_: Exception) {}
            }
        }

        return if (evidence.isNotEmpty()) RootIndicator(
            id = "frida_renamed_elf",
            category = DetectorCategory.BINARY,
            title = "Large Unknown ELF in Temp Dir",
            detail = "Large ELF binary (>20MB) in /data/local/tmp with non-Frida name — likely renamed Frida server or other root tool",
            risk = RiskLevel.MEDIUM,
            evidence = evidence
        ) else null
    }

    /**
     * `which su` — spawns a separate shell process (not in our Zygisk-injected address space).
     * Zygisk's PLT/GOT hooks stay in our process memory; the forked shell has clean Bionic.
     * If the shell finds su, it genuinely exists in the current mount namespace.
     * DO NOT verify via Java File API — those go through hooked libc and will return false.
     */
    private fun detectSuViaWhich(): RootIndicator? {
        val output = runShellCommand("which su").trim()
        if (output.isEmpty() || !output.startsWith("/")) return null
        return RootIndicator(
            id = "binary_which_su",
            category = DetectorCategory.BINARY,
            title = "su Found in PATH",
            detail = "`which su` → $output",
            risk = RiskLevel.HIGH,
            evidence = listOf(output)
        )
    }

    // `which <bin>` for root-only tools — same logic as detectSuViaWhich
    private fun detectRootBinsViaWhich(): RootIndicator? {
        val bins = listOf("magisk", "magiskpolicy", "magiskinit", "ksud", "kitsune", "apd")
        val found = mutableListOf<String>()
        for (bin in bins) {
            val path = runShellCommand("which $bin").trim()
            if (path.startsWith("/")) found += "$bin → $path"
        }
        return if (found.isNotEmpty()) RootIndicator(
            id = "binary_which_root_bins",
            category = DetectorCategory.BINARY,
            title = "Root Tool in PATH",
            detail = "Root-exclusive binary found via `which` in separate shell process",
            risk = RiskLevel.CRITICAL,
            evidence = found
        ) else null
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
