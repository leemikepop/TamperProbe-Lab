package io.leemikepop.tamperprobe.lab.internal

import android.util.Log

internal object TamperProbeLog {
    const val TAG: String = "TamperProbe"

    fun debug(component: String, event: String, details: String = "") {
        Log.d(TAG, message(component, event, details))
    }

    fun info(component: String, event: String, details: String = "") {
        Log.i(TAG, message(component, event, details))
    }

    fun warn(component: String, event: String, details: String = "", error: Throwable? = null) {
        val message = message(component, event, details)
        if (error == null) Log.w(TAG, message) else Log.w(TAG, message, error)
    }

    fun error(component: String, event: String, details: String = "", error: Throwable? = null) {
        val message = message(component, event, details)
        if (error == null) Log.e(TAG, message) else Log.e(TAG, message, error)
    }

    private fun message(component: String, event: String, details: String): String = buildString {
        append("component=")
        append(component)
        append(" event=")
        append(event)
        if (details.isNotBlank()) {
            append(' ')
            append(details)
        }
    }
}
