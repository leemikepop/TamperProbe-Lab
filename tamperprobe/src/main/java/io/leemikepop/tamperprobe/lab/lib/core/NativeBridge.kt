package io.leemikepop.tamperprobe.lab.lib.core

import android.content.Context

/**
 * JNI Native Bridge for TamperProbe
 * Corresponding C++ implementation: src/main/cpp/core/native_bridge.cpp
 */
internal object NativeBridge {
    init {
        System.loadLibrary("tamperprobe_native")
    }

    external fun performScan(
        context: Context,
        filesDir: String,
        detectorIds: Array<String>,
        policyOracleSnapshot: ByteArray,
        fdForensicsSnapshot: ByteArray,
    ): ByteArray
}
