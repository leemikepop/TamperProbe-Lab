package io.leemikepop.tamperprobe.lab

import android.content.Context
import io.leemikepop.tamperprobe.lab.api.TamperProbeClient
import io.leemikepop.tamperprobe.lab.internal.TamperProbeClientImpl

public object TamperProbe {
    @JvmStatic
    public fun create(context: Context): TamperProbeClient =
        TamperProbeClientImpl(context.applicationContext)
}
