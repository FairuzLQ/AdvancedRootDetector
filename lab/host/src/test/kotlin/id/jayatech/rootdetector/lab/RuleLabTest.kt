package id.jayatech.rootdetector.lab

import id.jayatech.rootdetector.rules.Rules
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Runs every scenario in lab/fixtures through the library's pure rules (Kotlin) and the
 * native rules (lab/native/lab_native), checks each scenario's `expect` file and writes a
 * coverage matrix to lab/REPORT.md.
 *
 * expect directives:
 *   clean            no rule at all may fire
 *   noroot           only INFO rules may fire
 *   must <id>        rule must fire
 *   mustnot <id>     rule must not fire
 *   gap <text>       documented blind spot (reported, not asserted)
 */
class RuleLabTest {

    private val fixtures = File(System.getProperty("lab.fixtures") ?: "../fixtures")
    private val nativeRunner = System.getProperty("lab.nativeRunner")?.let(::File)
    private val reportFile = System.getProperty("lab.report")?.let(::File)

    /** Rules that are context only (RiskLevel.INFO in the library). */
    private val infoRules = setOf("tooling_privileged_apps", "debug_app_debuggable", "props_selinux_boot_param")

    private fun File.linesOrNull(name: String): List<String>? =
        File(this, name).takeIf { it.isFile }?.readLines()

    private fun File.textOrNull(name: String): String? =
        File(this, name).takeIf { it.isFile }?.readText()

    /** Mirrors how each detector feeds its raw input into Rules. Keep in sync with the detectors. */
    private fun evaluateKotlin(dir: File): Map<String, List<String>> {
        val fired = linkedMapOf<String, List<String>>()
        fun add(id: String, ev: List<String>) { if (ev.isNotEmpty()) fired[id] = ev }

        dir.textOrNull("proc_version")?.let { v ->
            if (Rules.kernelSuInVersion(v)) add("ksu_kernel_version", listOf(v.trim()))
            if (Rules.apatchInVersion(v)) add("apatch_kernel", listOf(v.trim()))
        }
        dir.linesOrNull("net_unix")?.let { l ->
            add("magisk_socket", Rules.magiskSocketLines(l))
            add("apatch_socket", Rules.apatchSocketLines(l))
        }
        dir.textOrNull("getprop")?.let { dump ->
            val props = Rules.parseGetprop(dump)
            add("props_root_runtime", Rules.rootRuntimeProps(props))
            val unlocked = listOfNotNull(
                props["ro.boot.verifiedbootstate"]?.takeIf { it == "orange" }?.let { "verifiedbootstate=$it" },
                props["ro.boot.vbmeta.device_state"]?.takeIf { it == "unlocked" }?.let { "vbmeta=$it" },
                props["ro.secureboot.lockstate"]?.takeIf { it == "unlocked" }?.let { "lockstate=$it" },
            )
            add("props_bootloader", unlocked)
            val enforce = dir.textOrNull("selinux_enforce").orEmpty()
            when (Rules.selinuxVerdict(enforce, props["ro.boot.selinux"].orEmpty())) {
                Rules.SelinuxVerdict.PERMISSIVE -> add("props_selinux", listOf("enforce=0"))
                Rules.SelinuxVerdict.BOOT_PARAM_ONLY -> add("props_selinux_boot_param", listOf("ro.boot.selinux=permissive"))
                Rules.SelinuxVerdict.OK -> {}
            }
        }
        dir.linesOrNull("mounts")?.let { l ->
            val m = Rules.parseMounts(l)
            add("mount_overlay_system", Rules.rootOverlayOnSystem(m))
            add("mount_rw_system", Rules.rwSystem(m))
            add("mount_data_adb", Rules.dataAdbMounts(m))
            add("mount_magisk_tmpfs", Rules.magiskTmpfs(m))
            add("mount_zygisk_lib", Rules.zygiskLibMount(m))
            add("mount_ksu_ap", Rules.ksuApMounts(m))
            dir.textOrNull("mounts_init")?.let { init ->
                add("mount_denylist", Rules.denyListHidden(init, l.joinToString("\n")))
            }
        }
        dir.linesOrNull("mountinfo")?.let { add("mount_module_bind", Rules.mountinfoRootBinds(it)) }
        dir.linesOrNull("maps")?.let { l ->
            add("zygisk_maps", Rules.zygiskMapsLines(l))
            add("xposed_maps", Rules.xposedMapsLines(l))
            add("debug_frida_maps", Rules.fridaMapsLines(l))
        }
        val ps = dir.textOrNull("ps")?.let { Rules.rootDaemonPsLines(it).map { l -> "ps: $l" } }.orEmpty()
        val comm = dir.textOrNull("comm")?.let { Rules.rootDaemonComms(it).map { c -> "comm: $c" } }.orEmpty()
        add("magisk_proc_ps", ps + comm)
        dir.textOrNull("exe_ls")?.let { add("magisk_exe_proc", Rules.rootExeLines(it)) }
        dir.textOrNull("pm_list")?.let { out ->
            add("magisk_pkg_shell", Rules.rootPackagesInPmList(out))
            val pkgs = Rules.packagesFromPmList(out)
            add("tooling_privileged_apps", Rules.TOOLING_PACKAGES.keys.filter { it in pkgs })
        }
        dir.linesOrNull("tmp_ls")?.let { l -> add("fs_root_executables_tmp", l.filter(Rules::isRootToolFileName)) }
        dir.textOrNull("status")?.let { s ->
            val pid = Rules.tracerPid(s)
            if (pid != 0) add("debug_tracer", listOf("TracerPid=$pid"))
        }
        dir.linesOrNull("task_comm")?.let { add("debug_frida_threads", Rules.fridaThreadNames(it)) }
        return fired
    }

    private fun evaluateNative(dir: File): Map<String, List<String>> {
        val runner = nativeRunner?.takeIf { it.canExecute() } ?: return emptyMap()
        val proc = ProcessBuilder(runner.absolutePath, dir.absolutePath).redirectErrorStream(true).start()
        val out = proc.inputStream.bufferedReader().readText()
        check(proc.waitFor(30, TimeUnit.SECONDS) && proc.exitValue() == 0) { "lab_native failed on $dir:\n$out" }
        return out.lines().filter { '\t' in it }
            .groupBy({ it.substringBefore('\t') }, { it.substringAfter('\t') })
    }

    private data class Outcome(
        val name: String,
        val fired: Map<String, List<String>>,
        val violations: List<String>,
        val gaps: List<String>,
        val expected: List<String>,
    )

    @Test
    fun scenarios() {
        val dirs = fixtures.listFiles { f -> f.isDirectory && File(f, "expect").isFile }
            ?.sortedBy { it.name }.orEmpty()
        check(dirs.isNotEmpty()) { "no scenarios found in $fixtures" }
        if (nativeRunner?.canExecute() != true) println("WARN: native runner missing — native:* rules skipped")

        val outcomes = dirs.map { dir ->
            val fired = evaluateKotlin(dir) + evaluateNative(dir)
            val violations = mutableListOf<String>()
            val gaps = mutableListOf<String>()
            val expected = mutableListOf<String>()
            for (raw in File(dir, "expect").readLines()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                val directive = line.substringBefore(' ')
                val arg = line.substringAfter(' ', "").trim()
                when (directive) {
                    "clean" -> fired.keys.forEach { violations += "clean scenario but '$it' fired: ${fired[it]}" }
                    "noroot" -> fired.keys.filter { it !in infoRules }
                        .forEach { violations += "noroot scenario but '$it' fired: ${fired[it]}" }
                    "must" -> { expected += arg; if (arg !in fired) violations += "expected '$arg' to fire" }
                    "mustnot" -> if (arg in fired) violations += "'$arg' must not fire: ${fired[arg]}"
                    "gap" -> gaps += arg
                    else -> violations += "unknown directive '$line'"
                }
            }
            Outcome(dir.name, fired, violations, gaps, expected)
        }

        reportFile?.let { writeReport(it, outcomes) }

        val failures = outcomes.filter { it.violations.isNotEmpty() }
        if (failures.isNotEmpty()) {
            fail(failures.joinToString("\n\n") { o -> "[${o.name}]\n  " + o.violations.joinToString("\n  ") })
        }
    }

    private fun writeReport(file: File, outcomes: List<Outcome>) {
        val sb = StringBuilder()
        sb.appendLine("# Rule Lab Report")
        sb.appendLine()
        sb.appendLine("Generated by `lab/host` (`gradle test`). Do not edit by hand.")
        sb.appendLine()
        sb.appendLine("| Scenario | Result | Rules fired | Documented gaps |")
        sb.appendLine("|---|---|---|---|")
        for (o in outcomes) {
            val result = if (o.violations.isEmpty()) "PASS" else "FAIL (${o.violations.size})"
            val fired = o.fired.keys.joinToString(", ") { "`$it`" }.ifEmpty { "—" }
            sb.appendLine("| ${o.name} | $result | $fired | ${o.gaps.size} |")
        }
        sb.appendLine()
        for (o in outcomes) {
            sb.appendLine("## ${o.name}")
            sb.appendLine()
            File(fixtures, "${o.name}/README").takeIf { it.isFile }?.readText()?.trim()?.let {
                sb.appendLine(it.lines().joinToString("\n") { l -> "> $l" })
                sb.appendLine()
            }
            if (o.fired.isEmpty()) sb.appendLine("No rule fired.")
            for ((id, ev) in o.fired) {
                sb.appendLine("- `$id`")
                ev.take(3).forEach { sb.appendLine("  - `${it.trim().replace("`", "'").take(160)}`") }
            }
            if (o.violations.isNotEmpty()) {
                sb.appendLine()
                sb.appendLine("**Violations**")
                o.violations.forEach { sb.appendLine("- $it") }
            }
            if (o.gaps.isNotEmpty()) {
                sb.appendLine()
                sb.appendLine("**Known gaps**")
                o.gaps.forEach { sb.appendLine("- $it") }
            }
            sb.appendLine()
        }
        file.writeText(sb.toString())
    }
}
