package io.leemikepop.tamperprobe.lab.fixture.storageowner;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Process;
import android.system.Os;
import android.system.OsConstants;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileDescriptor;
import java.util.ArrayList;
import java.util.List;

/**
 * Different-UID owner for PACKAGE_STORAGE_VISIBILITY stateful device experiments.
 *
 * This module is never linked into the SDK. It creates and removes only
 * tamperprobe-<nonce>-prefixed fixtures inside its own external data/OBB roots.
 */
public final class StorageOwnerProvider extends ContentProvider {
    private static final String PREFIX = "tamperprobe-";
    private static final List<FileDescriptor> HELD_DIRECTORIES = new ArrayList<>();

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Bundle call(String method, String nonce, Bundle extras) {
        Bundle result = new Bundle();
        result.putInt("ownerUid", Process.myUid());
        try {
            switch (method) {
                case "prepare":
                    requireNonce(nonce);
                    releaseHeldDirectories();
                    prepareFixtures(nonce);
                    break;
                case "hold":
                    requireNonce(nonce);
                    releaseHeldDirectories();
                    prepareFixtures(nonce);
                    holdDirectories(nonce);
                    break;
                case "release":
                    releaseHeldDirectories();
                    break;
                case "cleanup":
                    requireNonce(nonce);
                    releaseHeldDirectories();
                    cleanupFixtures(nonce);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown method: " + method);
            }
            result.putBoolean("ok", true);
        } catch (Exception error) {
            result.putBoolean("ok", false);
            result.putString("error", error.getClass().getSimpleName() + ": " + error.getMessage());
        }
        result.putInt("heldDirectoryCount", HELD_DIRECTORIES.size());
        result.putInt("residualCount", nonce == null ? -1 : countResiduals(nonce));
        return result;
    }

    private void prepareFixtures(String nonce) throws Exception {
        for (File root : storageRoots()) {
            if (!root.exists() && !root.mkdirs()) {
                throw new IllegalStateException("Unable to create " + root);
            }
            File held = new File(root, PREFIX + nonce + "-held");
            if (!held.exists() && !held.mkdir()) {
                throw new IllegalStateException("Unable to create " + held);
            }
            File rmdir = new File(root, PREFIX + nonce + "-rmdir");
            if (!rmdir.exists() && !rmdir.mkdir()) {
                throw new IllegalStateException("Unable to create " + rmdir);
            }
            createFile(new File(root, PREFIX + nonce + "-rename-source"));
            createFile(new File(root, PREFIX + nonce + "-unlink"));
        }
    }

    private void createFile(File file) throws Exception {
        if (file.exists()) return;
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(0x54);
        }
    }

    private void holdDirectories(String nonce) throws Exception {
        for (File root : storageRoots()) {
            HELD_DIRECTORIES.add(
                Os.open(
                    root.getAbsolutePath(),
                    OsConstants.O_RDONLY | OsConstants.O_CLOEXEC,
                    0
                )
            );
            HELD_DIRECTORIES.add(
                Os.open(
                    new File(root, PREFIX + nonce + "-held").getAbsolutePath(),
                    OsConstants.O_RDONLY | OsConstants.O_CLOEXEC,
                    0
                )
            );
        }
    }

    private void releaseHeldDirectories() {
        for (FileDescriptor descriptor : HELD_DIRECTORIES) {
            try {
                Os.close(descriptor);
            } catch (Exception ignored) {
                // A closed fixture descriptor needs no further recovery.
            }
        }
        HELD_DIRECTORIES.clear();
    }

    private void cleanupFixtures(String nonce) {
        String runPrefix = PREFIX + nonce + "-";
        for (File root : storageRoots()) {
            File[] children = root.listFiles();
            if (children == null) continue;
            for (File child : children) {
                if (child.getName().startsWith(runPrefix)) deleteRecursively(child);
            }
        }
    }

    private boolean deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) deleteRecursively(child);
            }
        }
        return file.delete() || !file.exists();
    }

    private int countResiduals(String nonce) {
        int count = 0;
        String runPrefix = PREFIX + nonce + "-";
        for (File root : storageRoots()) {
            File[] children = root.listFiles();
            if (children == null) continue;
            for (File child : children) {
                if (child.getName().startsWith(runPrefix)) count++;
            }
        }
        return count;
    }

    private List<File> storageRoots() {
        File externalFiles = getContext().getExternalFilesDir(null);
        File dataRoot = externalFiles == null ? null : externalFiles.getParentFile();
        File obbRoot = getContext().getObbDir();
        if (dataRoot == null || obbRoot == null) {
            throw new IllegalStateException("External data or OBB root is unavailable");
        }
        List<File> roots = new ArrayList<>();
        roots.add(dataRoot);
        roots.add(obbRoot);
        return roots;
    }

    private void requireNonce(String nonce) {
        if (nonce == null || !nonce.matches("[a-z0-9]{8,32}")) {
            throw new IllegalArgumentException("Invalid nonce");
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException();
    }
}
