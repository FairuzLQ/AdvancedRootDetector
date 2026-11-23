package id.jayatech.rootdetector.detector

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import id.jayatech.rootdetector.model.DetectorCategory
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

/**
 * Debugging and dynamic-instrumentation checks for THIS process:
 *  - JDWP debugger attached (Android Studio, jdb, JEB)
 *  - ptrace tracer attached (gdb/lldb, strace, frida-inject during injection)
 *  - Frida agent/gadget threads and mappings — including a gadget repackaged into the
 *    app's own /data/app lib dir, which the native maps scan skips on purpose
 *  - App running as debuggable (INFO — normal for dev builds, suspicious in release)
 *
 * Frida's TCP port is reported by NativeDetector (FRIDA_PORT); not duplicated here.
 */
internal class DebugDetector(context: Context, props: PropSnapshot = PropSnapshot()) : BaseDetector(context, props) {

    override fun detect(): List<RootIndicator> {
        val findings = mutableListOf<RootIndicator>()
        detectJdwpDebugger()?.let { findings += it }
        detectTracer()?.let { findings += it }
        detectFridaThreads()?.let { findings += it }
        detectFridaMaps()?.let { findings += it }
        detectDebuggableApp()?.let { findings += it }
        return findings
    }

    private fun detectJdwpDebugger(): RootIndicator? {
        if (!Debug.isDebuggerConnected()) return null
        return RootIndicator(
            id = "debug_jdwp",
            category = DetectorCategory.DEBUG,
            title = "Java Debugger Attached",
            detail = "A JDWP debugger is connected to this process",
            risk = RiskLevel.HIGH,
            evidence = listOf("Debug.isDebuggerConnected() = true")
        )
    }

    private fun detectTracer(): RootIndicator? {
        val pid = try { Rules.tracerPid(java.io.File("/proc/self/status").readText()) } catch (_: Exception) { 0 }
        if (pid == 0) return null
        val tracer = try { java.io.File("/proc/$pid/comm").readText().trim() } catch (_: Exception) { "" }
        return RootIndicator(
            id = "debug_tracer",
            category = DetectorCategory.DEBUG,
            title = "Process Is Being Traced (ptrace)",
            detail = "TracerPid is non-zero — a native debugger, strace or injector is attached",
            risk = RiskLevel.HIGH,
            evidence = listOf("TracerPid=$pid" + if (tracer.isNotEmpty()) " ($tracer)" else "")
        )
    }

    private fun detectFridaThreads(): RootIndicator? {
        val names = try {
            java.io.File("/proc/self/task").listFiles()?.mapNotNull { t ->
                try { java.io.File(t, "comm").readText() } catch (_: Exception) { null }
            }.orEmpty()
        } catch (_: Exception) { emptyList() }
        val hits = Rules.fridaThreadNames(names)
        return if (hits.isNotEmpty()) RootIndicator(
            id = "debug_frida_threads",
            category = DetectorCategory.DEBUG,
            title = "Frida Agent Threads Running",
            detail = "Thread names created by the Frida agent/gadget exist in this process",
            risk = RiskLevel.CRITICAL,
            evidence = hits
        ) else null
    }

    private fun detectFridaMaps(): RootIndicator? {
        val hits = try {
            Rules.fridaMapsLines(java.io.File("/proc/self/maps").readLines())
        } catch (_: Exception) { emptyList() }
        return if (hits.isNotEmpty()) RootIndicator(
            id = "debug_frida_maps",
            category = DetectorCategory.DEBUG,
            title = "Frida Library Mapped in Process",
            detail = "frida-agent / frida-gadget is loaded into this process (possibly repackaged into the APK)",
            risk = RiskLevel.CRITICAL,
            evidence = hits.take(4)
        ) else null
    }

    private fun detectDebuggableApp(): RootIndicator? {
        if (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) return null
        return RootIndicator(
            id = "debug_app_debuggable",
            category = DetectorCategory.DEBUG,
            title = "App Is Debuggable",
            detail = "Expected for development builds; in a release build it means the APK was repackaged",
            risk = RiskLevel.INFO,
            evidence = listOf("ApplicationInfo.FLAG_DEBUGGABLE set")
        )
    }
}
