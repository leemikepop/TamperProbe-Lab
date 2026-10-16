package io.leemikepop.tamperprobe.lab.retrofit.common

import java.util.concurrent.TimeUnit

/**
 * Runs a command the way upstream checks do (`Runtime.exec`) and keeps what they discard: whether
 * it started, its exit status and its standard error.
 */
data class ShellOutput(
    val started: Boolean,
    val exitCode: Int?,
    val stdout: String,
    val stderr: String,
    val failure: String?,
) {
    val lines: List<String> get() = stdout.lines().filter { it.isNotBlank() }

    /** Why the command produced no usable output, or null when it did. */
    val noAnswerReason: String?
        get() = when {
            !started -> "exec_failed_${failure ?: "unknown"}"
            exitCode == null -> "timeout"
            else -> null
        }

    companion object {
        private const val TIMEOUT_SECONDS = 20L

        fun run(vararg command: String): ShellOutput {
            val process = try {
                Runtime.getRuntime().exec(command)
            } catch (error: Exception) {
                return ShellOutput(false, null, "", "", error.javaClass.simpleName)
            }
            return try {
                process.outputStream.close()
                val stdout = StringBuilder()
                val stderr = StringBuilder()
                val readers = listOf(
                    Thread { stdout.append(process.inputStream.bufferedReader().readText()) },
                    Thread { stderr.append(process.errorStream.bufferedReader().readText()) },
                )
                readers.forEach(Thread::start)
                val exited = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)
                if (!exited) process.destroy()
                readers.forEach { it.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS)) }
                ShellOutput(true, if (exited) process.exitValue() else null, stdout.toString(), stderr.toString(), null)
            } catch (error: Exception) {
                process.destroy()
                ShellOutput(true, null, "", "", error.javaClass.simpleName)
            }
        }
    }
}
