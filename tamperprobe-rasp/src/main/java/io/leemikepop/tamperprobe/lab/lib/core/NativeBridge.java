package io.leemikepop.tamperprobe.lab.lib.core;

import android.content.Context;

/**
 * Java-only binding of the native engine for the RASP adapter.
 *
 * <p>The parameter list must match {@code performScan} in {@code core/native_bridge.cpp}
 * exactly: JNI resolves the short symbol name without checking the signature, so a missing
 * parameter is not a link error but an undefined argument at run time.
 */
public final class NativeBridge {
    static {
        System.loadLibrary("tamperprobe_native");
    }

    public native byte[] performScan(
            Context context,
            String filesDir,
            String[] detectorIds,
            byte[] policyOracleSnapshot,
            byte[] fdForensicsSnapshot
    );
}
