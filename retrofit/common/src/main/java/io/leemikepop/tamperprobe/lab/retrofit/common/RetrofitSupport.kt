package io.leemikepop.tamperprobe.lab.retrofit.common

import android.app.UiAutomation
import android.os.ParcelFileDescriptor

/** Runs [block] and returns its value with the wall time it took, in microseconds. */
inline fun <T> timedMicros(block: () -> T): Pair<T, Long> {
    val start = System.nanoTime()
    val value = block()
    return value to (System.nanoTime() - start) / 1_000
}

/**
 * Runs one upstream check and its shadow probes. If the upstream call throws, the evaluation
 * records the failure: unmodified upstream code would have propagated it to its caller.
 */
inline fun evaluateCheck(
    spec: CheckSpec,
    crossinline upstream: () -> Boolean,
    crossinline evaluate: (upstreamPositive: Boolean) -> List<UnitEvaluation>,
): CheckEvaluation {
    val (evaluation, micros) = timedMicros {
        val upstreamResult = runCatching { upstream() }
        upstreamResult.fold(
            onSuccess = { positive ->
                CheckEvaluation(spec, positive.toString(), positive, evaluate(positive))
            },
            onFailure = { failure ->
                CheckEvaluation(spec, "threw", false, emptyList(), upstreamFailure = failure)
            },
        )
    }
    return evaluation.copy(durationMicros = micros)
}

/**
 * Writes a file owned by the shell user through the instrumentation's shell. `/data/local/tmp`
 * survives an uninstall of the host, and the adb shell user can pull it on every Android version.
 */
object InstrumentationShellWriter {
    fun write(automation: UiAutomation, path: String, bytes: ByteArray): Long {
        // `dd of=<path>`: the command is tokenised without a shell, so a redirect would never
        // reach one, and dd keeps stdout empty so its pipe cannot fill and deadlock our write.
        val descriptors = automation.executeShellCommandRw("dd of=$path")
        ParcelFileDescriptor.AutoCloseOutputStream(descriptors[1]).use { it.write(bytes) }
        ParcelFileDescriptor.AutoCloseInputStream(descriptors[0]).use { it.readBytes() }
        val size = ParcelFileDescriptor.AutoCloseInputStream(automation.executeShellCommand("stat -c %s $path"))
            .use { it.readBytes().decodeToString().trim() }
        return size.toLongOrNull() ?: -1
    }
}
