package io.leemikepop.tamperprobe.lab.internal.policyoracle;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class SelinuxPolicyOracleCarrierManager {
    private static final String TAG = "TamperProbe";
    private static final long TIMEOUT_SECONDS = 5;
    private static final Executor CALLBACK_EXECUTOR = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "TamperProbe-policy-oracle");
        thread.setDaemon(true);
        return thread;
    });

    private SelinuxPolicyOracleCarrierManager() {}

    public static byte[] collect(Context context) {
        if (context == null) {
            return PolicyOraclePayloads.failure("Carrier binding requires an Android context.");
        }
        if (!isCarrierSupportedOnApi(Build.VERSION.SDK_INT)) {
            Log.w(
                    TAG,
                    "component=PolicyOracle event=carrier_unavailable apiLevel="
                            + Build.VERSION.SDK_INT
                            + " reason=android_10_app_zygote_fd_contract hostContinues=true"
            );
            return PolicyOraclePayloads.failure(
                    "Policy-oracle carrier is unavailable on Android 10 because its "
                            + "app-zygote descriptor contract cannot safely retain the snapshot."
            );
        }

        CountDownLatch completed = new CountDownLatch(1);
        AtomicReference<byte[]> result = new AtomicReference<>();
        ServiceConnection connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                result.set(readSnapshot(service));
                completed.countDown();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                result.compareAndSet(
                        null,
                        PolicyOraclePayloads.failure("Policy-oracle carrier disconnected.")
                );
                completed.countDown();
            }

            @Override
            public void onNullBinding(ComponentName name) {
                result.set(PolicyOraclePayloads.failure("Policy-oracle carrier returned a null binding."));
                completed.countDown();
            }

            @Override
            public void onBindingDied(ComponentName name) {
                result.set(PolicyOraclePayloads.failure("Policy-oracle carrier binding died."));
                completed.countDown();
            }
        };

        Context applicationContext = context.getApplicationContext();
        Context bindingContext = applicationContext == null ? context : applicationContext;
        Intent intent = new Intent(bindingContext, SelinuxPolicyOracleCarrierService.class);
        boolean bound = false;
        try {
            bound = bindingContext.bindService(
                    intent,
                    Context.BIND_AUTO_CREATE,
                    CALLBACK_EXECUTOR,
                    connection
            );
            if (!bound) {
                return PolicyOraclePayloads.failure("Policy-oracle carrier binding was rejected.");
            }
            if (!completed.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                Log.w(TAG, "component=PolicyOracle event=carrier_timeout timeoutSeconds=5");
                return PolicyOraclePayloads.failure("Policy-oracle carrier timed out after 5 seconds.");
            }
            byte[] snapshot = result.get();
            if (snapshot == null || snapshot.length == 0) {
                return PolicyOraclePayloads.failure("Policy-oracle carrier returned no data.");
            }
            if (snapshot.length > PolicyOraclePayloads.MAX_PAYLOAD_BYTES) {
                return PolicyOraclePayloads.failure("Policy-oracle carrier payload exceeded 64 KiB.");
            }
            return snapshot;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return PolicyOraclePayloads.failure("Policy-oracle carrier wait was interrupted.");
        } catch (Throwable error) {
            return PolicyOraclePayloads.failure(
                    "Policy-oracle carrier failed: " + error.getClass().getSimpleName()
            );
        } finally {
            if (bound) {
                try {
                    bindingContext.unbindService(connection);
                } catch (IllegalArgumentException ignored) {
                    // The platform may already have removed a dead binding.
                }
            }
        }
    }

    static boolean isCarrierSupportedOnApi(int apiLevel) {
        return apiLevel >= Build.VERSION_CODES.R;
    }

    private static byte[] readSnapshot(IBinder binder) {
        if (binder == null) {
            return PolicyOraclePayloads.failure("Policy-oracle carrier binder is unavailable.");
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(SelinuxPolicyOracleCarrierService.DESCRIPTOR);
            if (!binder.transact(
                    SelinuxPolicyOracleCarrierService.TRANSACTION_GET_SNAPSHOT,
                    data,
                    reply,
                    0
            )) {
                return PolicyOraclePayloads.failure("Policy-oracle carrier transaction was rejected.");
            }
            reply.readException();
            return reply.createByteArray();
        } catch (Throwable error) {
            return PolicyOraclePayloads.failure(
                    "Policy-oracle carrier transaction failed: " + error.getClass().getSimpleName()
            );
        } finally {
            reply.recycle();
            data.recycle();
        }
    }
}
