package io.leemikepop.tamperprobe.lab.retrofit.common

import android.app.Activity
import android.graphics.Typeface
import android.widget.ScrollView
import android.widget.TextView
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import java.time.Instant

/** A plain-text view of a run, one line per check: upstream verdict → contract outcome. */
object RetrofitText {
    fun render(run: RetrofitRun): String = buildString {
        appendLine("${run.upstream.name} ${run.upstream.revision.take(7)}")
        appendLine("${run.upstream.aggregateMethod} = ${run.aggregateVerdict}")
        appendLine("package visibility: ${run.host.packageVisibility}")
        appendLine()
        run.evaluations.zip(run.results).forEach { (evaluation, result) ->
            val concealable = result.unitResults.any { unit ->
                unit.records.any { it.code.endsWith(".concealable-negative") }
            }
            val outcome = when {
                result.outcome == DetectionOutcome.OBSERVED -> "OBSERVED ${result.strength}"
                result.outcome == DetectionOutcome.NOT_OBSERVED && concealable -> "NOT_OBSERVED (concealable)"
                else -> result.outcome.name
            }
            appendLine("${evaluation.spec.detectorId}")
            appendLine("  upstream ${evaluation.upstreamVerdict} → $outcome")
            result.unitResults.flatMap { it.issues }.forEach { issue ->
                appendLine("  · ${issue.message}")
            }
        }
    }

    /**
     * Shows the run in a scrolling text view. The run happens on a background thread: upstream
     * checks spawn processes and must not block the main thread.
     */
    fun showRun(activity: Activity, run: () -> RetrofitRun) {
        val text = TextView(activity).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setPadding(32, 32, 32, 32)
            setTextIsSelectable(true)
            setText("Running…")
        }
        // Hosts targeting Android 15+ are drawn edge to edge: pad for the system bars.
        activity.setContentView(
            ScrollView(activity).apply {
                fitsSystemWindows = true
                addView(text)
            },
        )
        Thread {
            val rendered = runCatching { render(run()) }.getOrElse { "Run failed at ${Instant.now()}: $it" }
            activity.runOnUiThread { text.text = rendered }
        }.start()
    }
}
