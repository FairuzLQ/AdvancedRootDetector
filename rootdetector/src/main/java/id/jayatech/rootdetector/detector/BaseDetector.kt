package id.jayatech.rootdetector.detector

import android.content.Context
import id.jayatech.rootdetector.model.RootIndicator

internal abstract class BaseDetector(protected val context: Context) {
    abstract fun detect(): List<RootIndicator>

    protected fun fileExists(path: String): Boolean = try {
        java.io.File(path).exists()
    } catch (_: Exception) { false }

    protected fun canExecute(path: String): Boolean = try {
        java.io.File(path).canExecute()
    } catch (_: Exception) { false }

    protected fun readProp(key: String): String = try {
        val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
        process.inputStream.bufferedReader().readLine()?.trim() ?: ""
    } catch (_: Exception) { "" }

    protected fun isPackageInstalled(pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (_: Exception) { false }

    protected fun runShellCommand(cmd: String): String = try {
        val process = Runtime.getRuntime().exec(cmd)
        process.inputStream.bufferedReader().readText().trim()
    } catch (_: Exception) { "" }
}
