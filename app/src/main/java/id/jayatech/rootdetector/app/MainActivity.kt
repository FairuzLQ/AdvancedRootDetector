package id.jayatech.rootdetector.app

import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import id.jayatech.rootdetector.RootDetector
import id.jayatech.rootdetector.model.DetectionResult
import id.jayatech.rootdetector.model.RiskLevel
import id.jayatech.rootdetector.model.RootIndicator
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildLoadingLayout())
    }

    // -------------------------------------------------------------------------
    // Initial loading screen
    // -------------------------------------------------------------------------

    private fun buildLoadingLayout(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#121212"))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT
            )
            setPadding(48, 0, 48, 0)
        }

        val icon = TextView(this).apply {
            text = "🔍"
            textSize = 56f
            gravity = Gravity.CENTER
        }
        root.addView(icon)

        val title = TextView(this).apply {
            text = "Advanced Root Detector"
            textSize = 20f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
            setPadding(0, 24, 0, 8)
        }
        root.addView(title)

        val subtitle = TextView(this).apply {
            text = "Scanning for Magisk, KernelSU Next,\nAPatch, Zygisk, LSPosed & more…"
            textSize = 13f
            setTextColor(Color.LTGRAY)
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 40)
        }
        root.addView(subtitle)

        val spinner = ProgressBar(this).apply {
            isIndeterminate = true
        }
        root.addView(spinner)

        val statusLabel = TextView(this).apply {
            id = android.R.id.text1
            text = "Initializing scan…"
            textSize = 12f
            setTextColor(Color.parseColor("#90A4AE"))
            gravity = Gravity.CENTER
            setPadding(0, 20, 0, 0)
        }
        root.addView(statusLabel)

        // Run scan off main thread
        executor.execute {
            val steps = listOf(
                "Checking root binaries…",
                "Scanning Magisk artifacts…",
                "Probing KernelSU / APatch…",
                "Inspecting Zygisk / LSPosed…",
                "Analyzing mount namespaces…",
                "Running native JNI checks…",
                "Compiling results…"
            )
            steps.forEachIndexed { i, msg ->
                mainHandler.post { statusLabel.text = msg }
                Thread.sleep(180L + i * 40L)
            }

            val result = try {
                RootDetector.scan(this)
            } catch (e: Throwable) {
                mainHandler.post { showCrashDialog(e) }
                return@execute
            }

            mainHandler.post { showResult(result) }
        }

        return root
    }

    // -------------------------------------------------------------------------
    // Result screen
    // -------------------------------------------------------------------------

    private fun showResult(result: DetectionResult) {
        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#121212"))
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 56, 28, 56)
        }
        scroll.addView(root)
        setContentView(scroll)

        // Header
        val header = TextView(this).apply {
            text = "Advanced Root Detector"
            textSize = 20f
            setTextColor(Color.WHITE)
            setPadding(0, 0, 0, 4)
        }
        root.addView(header)

        val sub = TextView(this).apply {
            text = "Magisk Alpha · KernelSU Next · APatch · Zygisk · LSPosed"
            textSize = 11f
            setTextColor(Color.parseColor("#607D8B"))
            setPadding(0, 0, 0, 24)
        }
        root.addView(sub)

        // Verdict card
        val verdictBg = when (result.riskLevel) {
            RiskLevel.CRITICAL -> Color.parseColor("#B71C1C")
            RiskLevel.HIGH     -> Color.parseColor("#BF360C")
            RiskLevel.MEDIUM   -> Color.parseColor("#F57F17")
            RiskLevel.LOW      -> Color.parseColor("#1B5E20")
        }
        val verdictCard = cardView(root, verdictBg, padV = 28)

        val verdictEmoji = if (result.isRooted) "⚠" else "✓"
        val verdictText = if (result.isRooted) "ROOTED / COMPROMISED" else "DEVICE IS CLEAN"
        val verdictLabel = TextView(this).apply {
            text = "$verdictEmoji  $verdictText"
            textSize = 18f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
        }
        verdictCard.addView(verdictLabel)

        val scoreText = TextView(this).apply {
            text = "Risk Score: ${result.riskScore}/100   •   Level: ${result.riskLevel}   •   ${result.indicators.size} indicators"
            textSize = 12f
            setTextColor(Color.parseColor("#FFCCBC"))
            gravity = Gravity.CENTER
            setPadding(0, 10, 0, 0)
        }
        verdictCard.addView(scoreText)

        if (result.indicators.isEmpty()) {
            val clean = TextView(this).apply {
                text = "No root artifacts detected on this device."
                textSize = 14f
                setTextColor(Color.parseColor("#A5D6A7"))
                gravity = Gravity.CENTER
                setPadding(0, 32, 0, 0)
            }
            root.addView(clean)
            return
        }

        // Per-category sections
        for ((category, indicators) in result.summary) {
            val sectionCount = indicators.size
            val sectionColor = when {
                indicators.any { it.risk == RiskLevel.CRITICAL } -> Color.parseColor("#EF5350")
                indicators.any { it.risk == RiskLevel.HIGH }     -> Color.parseColor("#FF7043")
                indicators.any { it.risk == RiskLevel.MEDIUM }   -> Color.parseColor("#FFA726")
                else                                              -> Color.parseColor("#66BB6A")
            }

            val sectionHeader = TextView(this).apply {
                text = "▸  ${category.name}  ($sectionCount)"
                textSize = 13f
                setTextColor(sectionColor)
                setPadding(4, 28, 0, 10)
            }
            root.addView(sectionHeader)

            for (indicator in indicators) {
                root.addView(indicatorCard(indicator))
            }
        }

        // Footer
        val footer = TextView(this).apply {
            text = "Scan completed  •  ${result.indicators.size} indicator(s) found"
            textSize = 11f
            setTextColor(Color.parseColor("#546E7A"))
            gravity = Gravity.CENTER
            setPadding(0, 32, 0, 0)
        }
        root.addView(footer)
    }

    // -------------------------------------------------------------------------
    // Crash / error dialog — shown instead of force closing
    // -------------------------------------------------------------------------

    private fun showCrashDialog(e: Throwable) {
        if (isFinishing || isDestroyed) return
        AlertDialog.Builder(this)
            .setTitle("Scan Error")
            .setMessage(
                "Root scan encountered an error and was stopped safely.\n\n" +
                "This may happen on heavily restricted devices.\n\n" +
                "Error: ${e.javaClass.simpleName}: ${e.message?.take(200)}"
            )
            .setPositiveButton("Retry") { _, _ -> recreate() }
            .setNegativeButton("Close") { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }

    // -------------------------------------------------------------------------
    // View helpers
    // -------------------------------------------------------------------------

    private fun indicatorCard(indicator: RootIndicator): View {
        val riskColor = when (indicator.risk) {
            RiskLevel.CRITICAL -> Color.parseColor("#EF5350")
            RiskLevel.HIGH     -> Color.parseColor("#FF7043")
            RiskLevel.MEDIUM   -> Color.parseColor("#FFCA28")
            RiskLevel.LOW      -> Color.parseColor("#66BB6A")
        }
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#1E2A30"))
            setPadding(20, 16, 20, 16)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.setMargins(0, 4, 0, 4) }
        }

        // Left color bar via compound drawable would require extra work; use text badge
        card.addView(TextView(this).apply {
            text = "[${indicator.risk}]  ${indicator.title}"
            textSize = 12f
            setTextColor(riskColor)
        })
        card.addView(TextView(this).apply {
            text = indicator.detail
            textSize = 11f
            setTextColor(Color.parseColor("#B0BEC5"))
            setPadding(0, 4, 0, 4)
        })
        if (indicator.evidence.isNotEmpty()) {
            card.addView(TextView(this).apply {
                text = indicator.evidence.take(4).joinToString("\n") { "  • $it" }
                textSize = 10f
                setTextColor(Color.parseColor("#78909C"))
            })
        }
        return card
    }

    private fun cardView(parent: LinearLayout, bgColor: Int, padV: Int = 20): LinearLayout {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(bgColor)
            setPadding(24, padV, 24, padV)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.setMargins(0, 0, 0, 16) }
        }
        parent.addView(card)
        return card
    }

    override fun onDestroy() {
        super.onDestroy()
        executor.shutdownNow()
    }
}
