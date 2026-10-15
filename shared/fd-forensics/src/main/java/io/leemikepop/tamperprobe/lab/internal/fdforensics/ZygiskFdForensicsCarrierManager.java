package io.leemikepop.tamperprobe.lab.internal.fdforensics;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class ZygiskFdForensicsCarrierManager {
    private static final String TAG = "TamperProbe";
    private static final long TIMEOUT_SECONDS = 5;
    private static final byte[] TRAP_SIGNATURE =
            "tamperprobe:zygisk:fdtrap:v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final Executor CALLBACK_EXECUTOR = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "TamperProbe-fd-forensics");
        thread.setDaemon(true);
        return thread;
    });

    private ZygiskFdForensicsCarrierManager() {}

    public static byte[] collect(Context context) {
        if (context == null) {
            return FdForensicsPayloads.failure("Carrier binding requires an Android context.");
        }

        ParcelFileDescriptor trap = null;
        try {
            java.io.File trapFile = java.io.File.createTempFile("tp_fdtrap", ".bin", context.getCacheDir());
            java.io.FileOutputStream out = new java.io.FileOutputStream(trapFile);
            try { out.write(TRAP_SIGNATURE); out.flush(); out.getFD().sync(); } finally { out.close(); }
            trap = ParcelFileDescriptor.open(trapFile, ParcelFileDescriptor.MODE_READ_ONLY);
            trapFile.delete();
        } catch (Throwable ignored) { trap = null; }

        final ParcelFileDescriptor boundTrap = trap;
        CountDownLatch completed = new CountDownLatch(1);
        AtomicReference<byte[]> result = new AtomicReference<>();
        ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                result.set(readSnapshot(service, boundTrap));
                completed.countDown();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                result.compareAndSet(
                        null,
                        FdForensicsPayloads.failure("Descriptor-forensics carrier disconnected.")
                );
                completed.countDown();
            }

            @Override
            public void onNullBinding(ComponentName name) {
                result.set(FdForensicsPayloads.failure("Descriptor-forensics carrier returned a null binding."));
                completed.countDown();
            }

            @Override
            public void onBindingDied(ComponentName name) {
                result.set(FdForensicsPayloads.failure("Descriptor-forensics carrier binding died."));
                completed.countDown();
            }
        };

        Context applicationContext = context.getApplicationContext();
        Context bindingContext = applicationContext == null ? context : applicationContext;
        Intent intent = new Intent(bindingContext, ZygiskFdForensicsCarrierService.class);
        boolean bound = false;
        try {
            bound = bindingContext.bindService(
                    intent,
                    Context.BIND_AUTO_CREATE,
                    CALLBACK_EXECUTOR,
                    connection
            );
            if (!bound) {
                return FdForensicsPayloads.failure("Descriptor-forensics carrier binding was rejected.");
            }
            if (!completed.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                Log.w(TAG, "component=FdForensics event=carrier_timeout timeoutSeconds=5");
                return FdForensicsPayloads.failure("Descriptor-forensics carrier timed out after 5 seconds.");
            }
            byte[] snapshot = result.get();
            if (snapshot == null || snapshot.length == 0) {
                return FdForensicsPayloads.failure("Descriptor-forensics carrier returned no data.");
            }
            if (snapshot.length > FdForensicsPayloads.MAX_PAYLOAD_BYTES) {
                return FdForensicsPayloads.failure("Descriptor-forensics carrier payload exceeded 64 KiB.");
            }
            return snapshot;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return FdForensicsPayloads.failure("Descriptor-forensics carrier wait was interrupted.");
        } catch (Throwable error) {
            return FdForensicsPayloads.failure(
                    "Descriptor-forensics carrier failed: " + error.getClass().getSimpleName()
            );
        } finally {
            if (bound) {
                try {
                    bindingContext.unbindService(connection);
                } catch (IllegalArgumentException ignored) {
                    // The platform may already have removed a dead binding.
                }
            }
            if (trap != null) {
                try {
                    trap.close();
                } catch (java.io.IOException ignored) {
                }
            }
        }
    }

    private static byte[] readSnapshot(IBinder binder, ParcelFileDescriptor trap) {
        if (binder == null) {
            return FdForensicsPayloads.failure("Descriptor-forensics carrier binder is unavailable.");
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(ZygiskFdForensicsCarrierService.DESCRIPTOR);
            if (trap == null) {
                data.writeInt(0);
            } else {
                data.writeInt(1);
                trap.writeToParcel(data, 0);
            }
            if (!binder.transact(
                    ZygiskFdForensicsCarrierService.TRANSACTION_GET_SNAPSHOT,
                    data,
                    reply,
                    0
            )) {
                return FdForensicsPayloads.failure("Descriptor-forensics carrier transaction was rejected.");
            }
            reply.readException();
            return reply.createByteArray();
        } catch (Throwable error) {
            return FdForensicsPayloads.failure(
                    "Descriptor-forensics carrier transaction failed: " + error.getClass().getSimpleName()
            );
        } finally {
            reply.recycle();
            data.recycle();
        }
    }
}
