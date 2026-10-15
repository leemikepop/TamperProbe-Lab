package io.leemikepop.tamperprobe.lab.internal.fdforensics;

final class FdForensicsNativeBridge {
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

    private FdForensicsNativeBridge() {}

    static byte[] collectSnapshot(int trapFd) {
        if (!NATIVE_LOADED) {
            return FdForensicsPayloads.failure("Native descriptor-forensics collector is unavailable.");
        }
        try {
            byte[] snapshot = nativeCollectSnapshot(trapFd);
            return snapshot == null || snapshot.length == 0
                    ? FdForensicsPayloads.failure("Native descriptor-forensics collector returned no data.")
                    : snapshot;
        } catch (Throwable error) {
            return FdForensicsPayloads.failure(
                    "Native descriptor-forensics collector failed: " + error.getClass().getSimpleName()
            );
        }
    }

    private static native byte[] nativeCollectSnapshot(int trapFd);
}
