package io.leemikepop.tamperprobe.lab.internal.policyoracle;

final class PolicyOracleNativeBridge {
    private static final boolean NATIVE_LOADED;

    static {
        boolean loaded;
        try {
            System.loadLibrary("tamperprobe_native");
            loaded = true;
        } catch (Throwable ignored) {
            loaded = false;
        }
        NATIVE_LOADED = loaded;
    }

    private PolicyOracleNativeBridge() {}

    static byte[] collectSnapshot(int applicationUid) {
        if (!NATIVE_LOADED) {
            return PolicyOraclePayloads.failure("Native policy-oracle collector is unavailable.");
        }
        try {
            byte[] snapshot = nativeCollectSnapshot(applicationUid);
            return snapshot == null || snapshot.length == 0
                    ? PolicyOraclePayloads.failure("Native policy-oracle collector returned no data.")
                    : snapshot;
        } catch (Throwable error) {
            return PolicyOraclePayloads.failure(
                    "Native policy-oracle collector failed: " + error.getClass().getSimpleName()
            );
        }
    }

    private static native byte[] nativeCollectSnapshot(int applicationUid);
}
