package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.RootIndicator
import java.util.concurrent.TimeUnit

internal abstract class BaseDetector(protected val context: Context) {
    abstract fun detect(): List<RootIndicator>

    protected fun fileExists(path: String): Boolean = try {
        java.io.File(path).exists()
    } catch (_: Exception) { false }

    protected fun canExecute(path: String): Boolean = try {
        java.io.File(path).canExecute()
    } catch (_: Exception) { false }

    // 1-second timeout prevents hanging on a slow property service (common on Android 8).
    protected fun readProp(key: String): String = try {
        val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
        val value = process.inputStream.bufferedReader().readLine()?.trim() ?: ""
        val exited = process.waitFor(1L, TimeUnit.SECONDS)
        if (!exited) process.destroyForcibly()
        if (exited) value else ""
    } catch (_: Exception) { "" }

    protected fun isPackageInstalled(pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (_: Exception) { false }

    /**
     * Run shell command via /system/bin/sh so PATH includes /sbin.
     * Hard timeout (default 2 s) prevents any single command from blocking the entire scan.
     * On slow devices (Redmi 5 / Android 8) subprocesses are expensive — callers that
     * need more time (pm list packages, ps) must pass a larger timeoutMs explicitly.
     */
    protected fun runShellCommand(cmd: String, timeoutMs: Long = 2000): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("/system/bin/sh", "-c", cmd))
            val sb = StringBuilder()
            val reader = Thread {
                try { sb.append(process.inputStream.bufferedReader().readText()) }
                catch (_: Exception) {}
            }
            reader.isDaemon = true
            reader.start()
            reader.join(timeoutMs)
            if (reader.isAlive) {
                process.destroyForcibly()
                return ""
            }
            sb.toString().trim()
        } catch (_: Exception) { "" }
    }
}
