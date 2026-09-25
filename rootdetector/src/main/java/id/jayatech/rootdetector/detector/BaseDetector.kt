package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.RootIndicator
import id.jayatech.rootdetector.rules.Rules

internal abstract class BaseDetector(
    protected val context: Context,
    protected val props: PropSnapshot = PropSnapshot()
) {
    abstract fun detect(): List<RootIndicator>

    protected fun fileExists(path: String): Boolean = try {
        java.io.File(path).exists()
    } catch (_: Exception) { false }

    protected fun canExecute(path: String): Boolean = try {
        java.io.File(path).canExecute()
    } catch (_: Exception) { false }

    /**
     * Reads a system property from a per-scan snapshot of `getprop` (one subprocess for the
     * whole scan instead of one per key). The subprocess is exec'd fresh, so Zygisk hooks on
     * __system_property_get in our process do not affect it.
     */
    protected fun readProp(key: String): String = props.get(key)

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
    protected fun runShellCommand(cmd: String, timeoutMs: Long = 2000): String =
        execWithTimeout(arrayOf("/system/bin/sh", "-c", cmd), timeoutMs)

    companion object {
        /**
         * Executes [argv] and returns its trimmed stdout, or "" on error/timeout.
         * stdout is drained on a separate thread so a child that never closes stdout
         * (e.g. `su` waiting for the user to approve a prompt) cannot block the caller.
         */
        fun execWithTimeout(argv: Array<String>, timeoutMs: Long): String {
            val process = try { Runtime.getRuntime().exec(argv) } catch (_: Exception) { return "" }
            return try {
                val sb = StringBuilder()
                val reader = Thread {
                    try { process.inputStream.bufferedReader().use { sb.append(it.readText()) } }
                    catch (_: Exception) {}
                }
                reader.isDaemon = true
                reader.start()
                reader.join(timeoutMs)
                if (reader.isAlive) "" else sb.toString().trim()
            } catch (_: Exception) {
                ""
            } finally {
                process.destroy()
            }
        }
    }
}

/**
 * Lazily captured `getprop` dump shared by all detectors of one scan.
 * Falls back to a per-key `getprop <key>` if the dump could not be read.
 */
internal class PropSnapshot {
    private val all: Map<String, String> by lazy {
        Rules.parseGetprop(BaseDetector.execWithTimeout(arrayOf("getprop"), 3000))
    }

    fun get(key: String): String {
        val snapshot = all
        if (snapshot.isNotEmpty()) return snapshot[key].orEmpty()
        return BaseDetector.execWithTimeout(arrayOf("getprop", key), 1000)
    }

    fun asMap(): Map<String, String> = all
}
