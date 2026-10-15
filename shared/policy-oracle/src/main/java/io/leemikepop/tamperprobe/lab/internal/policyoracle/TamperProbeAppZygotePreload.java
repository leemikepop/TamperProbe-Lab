package io.leemikepop.tamperprobe.lab.internal.policyoracle;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;

public final class TamperProbeAppZygotePreload implements ZygotePreload {
    @Override
    public void doPreload(ApplicationInfo appInfo) {
        byte[] snapshot;
        if (appInfo == null) {
            snapshot = PolicyOraclePayloads.failure("App-zygote preload received no application info.");
        } else {
            snapshot = PolicyOracleNativeBridge.collectSnapshot(appInfo.uid);
        }
        PolicyOraclePayloads.setPreloadedSnapshot(snapshot);
    }
}
