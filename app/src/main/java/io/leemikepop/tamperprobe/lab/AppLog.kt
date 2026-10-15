package io.leemikepop.tamperprobe.lab

import android.util.Log

internal object AppLog {
    private const val TAG = "TamperProbe"

    fun debug(component: String, event: String, details: String = "") {
        Log.d(TAG, message(component, event, details))
    }

    fun info(component: String, event: String, details: String = "") {
        Log.i(TAG, message(component, event, details))
    }

    fun error(component: String, event: String, details: String = "", error: Throwable? = null) {
        val message = message(component, event, details)
        if (error == null) Log.e(TAG, message) else Log.e(TAG, message, error)
    }

    private fun message(component: String, event: String, details: String): String =
        "component=$component event=$event${if (details.isBlank()) "" else " $details"}"
}
