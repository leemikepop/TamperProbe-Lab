package io.leemikepop.tamperprobe.lab.rasp;

import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.SystemClock;
import android.provider.MediaStore;
import android.system.Os;
import android.util.Log;

import io.leemikepop.tamperprobe.lab.internal.policyoracle.SelinuxPolicyOracleCarrierManager;
import io.leemikepop.tamperprobe.lab.lib.core.NativeBridge;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Research-mode RASP adapter.
 *
 * <p>Started by the host app's {@code ContentProvider} initialisation, it runs one scan on a
 * background thread and records the raw wire-schema report. It never applies a policy, never
 * shows a dialog and never terminates the host: TamperProbe-Lab measures what the detectors
 * report, it does not enforce anything.
 *
 * <p>The report is written to {@code Download/tamperprobe-lab/} through MediaStore, which needs
 * no permission on API 29+ and can be pulled with {@code adb pull /sdcard/Download/tamperprobe-lab/}.
 * One summary line per detector is also logged under tag {@code TamperProbeLab}.
 */
public final class TamperProbeInitializer extends ContentProvider {
    private static final String TAG = "TamperProbeLab";
    private static final String STATUS_ASSET = "tamperprobe/attestation_status.json";
    private static final String STATUS_FILE = "attestation_status.json";
    private static final String REPORT_DIRECTORY = "Download/tamperprobe-lab/";
    private static final List<String> POLICY_ORACLE_DETECTOR_IDS = Arrays.asList(
            "LSPOSED_SEPOLICY",
            "NATIVE_ROOT_SEPOLICY"
    );

    @Override
    public boolean onCreate() {
        Context providerContext = getContext();
        if (providerContext == null) return false;
        Context context = providerContext.getApplicationContext();
        Thread worker = new Thread(() -> scan(context), "TamperProbeLab-scan");
        worker.setDaemon(true);
        worker.start();
        return true;
    }

    private void scan(Context context) {
        try {
            Bundle metadata = loadMetadata(context);
            installAttestationSnapshot(context);
            String[] detectorIds = RaspCatalog.load(context).resolve(metadata);
            long startedAt = SystemClock.elapsedRealtime();
            byte[] policyOracleSnapshot = usesPolicyOracle(detectorIds)
                    ? SelinuxPolicyOracleCarrierManager.collect(context)
                    : new byte[0];
            // The FD forensics carrier is not part of the RASP bundle, so ZYGISK_FD_FORENSICS
            // runs without its helper-process snapshot here (see README).
            byte[] response = new NativeBridge().performScan(
                    context,
                    context.getFilesDir().getAbsolutePath(),
                    detectorIds,
                    policyOracleSnapshot,
                    new byte[0]
            );
            long elapsedMs = SystemClock.elapsedRealtime() - startedAt;
            logSummary(response, detectorIds.length, elapsedMs);
            String location = writeReport(context, response);
            Log.i(TAG, "component=Rasp event=report_written location=" + location
                    + " bytes=" + response.length + " elapsedMs=" + elapsedMs);
        } catch (Throwable error) {
            Log.e(TAG, "component=Rasp event=scan_failed hostContinues=true", error);
        }
    }

    private static void logSummary(byte[] response, int selectedCount, long elapsedMs) {
        try {
            JSONObject envelope = new JSONObject(new String(response, StandardCharsets.UTF_8));
            JSONArray results = envelope.optJSONArray("results");
            Log.i(TAG, "component=Rasp event=scan_complete completion="
                    + envelope.optString("completion") + " selected=" + selectedCount
                    + " results=" + (results == null ? 0 : results.length())
                    + " elapsedMs=" + elapsedMs);
            if (results == null) return;
            for (int index = 0; index < results.length(); index++) {
                JSONObject result = results.getJSONObject(index);
                JSONObject error = result.optJSONObject("collectionError");
                Log.i(TAG, "component=Rasp event=detector_result detectorId="
                        + result.optString("detectorId")
                        + " outcome=" + result.optString("outcome")
                        + " strength=" + result.optString("evidenceStrength")
                        + " collectionError=" + (error == null ? "none" : error.optString("code")));
            }
        } catch (Exception error) {
            Log.w(TAG, "component=Rasp event=summary_unavailable", error);
        }
    }

    private static String writeReport(Context context, byte[] response) throws Exception {
        SimpleDateFormat format = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        String name = "rasp-" + context.getPackageName() + "-" + format.format(new Date()) + ".json";

        ContentResolver resolver = context.getContentResolver();
        ContentValues values = new ContentValues();
        values.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
        values.put(MediaStore.MediaColumns.MIME_TYPE, "application/json");
        values.put(MediaStore.MediaColumns.RELATIVE_PATH, REPORT_DIRECTORY);
        Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
        if (uri != null) {
            try (OutputStream output = resolver.openOutputStream(uri, "w")) {
                if (output != null) {
                    output.write(response);
                    return REPORT_DIRECTORY + name;
                }
            }
        }
        // Fallback: the app's private storage (readable with run-as on a debuggable build).
        File fallback = new File(context.getFilesDir(), name);
        try (FileOutputStream output = new FileOutputStream(fallback)) {
            output.write(response);
        }
        return fallback.getAbsolutePath();
    }

    private static boolean usesPolicyOracle(String[] detectorIds) {
        for (String detectorId : detectorIds) {
            if (POLICY_ORACLE_DETECTOR_IDS.contains(detectorId)) return true;
        }
        return false;
    }

    private static Bundle loadMetadata(Context context) throws PackageManager.NameNotFoundException {
        ApplicationInfo info = context.getPackageManager().getApplicationInfo(
                context.getPackageName(),
                PackageManager.GET_META_DATA
        );
        return info.metaData == null ? new Bundle() : info.metaData;
    }

    private static void installAttestationSnapshot(Context context) throws Exception {
        File target = new File(context.getFilesDir(), STATUS_FILE);
        File temporary = new File(context.getFilesDir(), STATUS_FILE + ".tmp");
        try (InputStream input = context.getAssets().open(STATUS_ASSET);
             FileOutputStream output = new FileOutputStream(temporary)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) >= 0) output.write(buffer, 0, read);
            output.getFD().sync();
        }
        try {
            Os.rename(temporary.getAbsolutePath(), target.getAbsolutePath());
        } catch (Exception error) {
            temporary.delete();
            throw error;
        }
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] selectionArgs, String sortOrder) { return null; }
    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String selection,
                                String[] selectionArgs) { return 0; }
}
