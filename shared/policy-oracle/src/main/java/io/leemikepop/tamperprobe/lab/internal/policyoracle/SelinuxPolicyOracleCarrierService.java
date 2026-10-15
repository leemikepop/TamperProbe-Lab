package io.leemikepop.tamperprobe.lab.internal.policyoracle;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

public final class SelinuxPolicyOracleCarrierService extends Service {
    static final String DESCRIPTOR =
            "io.leemikepop.tamperprobe.lab.internal.policyoracle.ISelinuxPolicyOracleCarrier";
    static final int TRANSACTION_GET_SNAPSHOT = IBinder.FIRST_CALL_TRANSACTION;

    private final IBinder binder = new SnapshotBinder();

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    private static final class SnapshotBinder extends Binder {
        SnapshotBinder() {
            attachInterface(null, DESCRIPTOR);
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws RemoteException {
            if (code == INTERFACE_TRANSACTION) {
                reply.writeString(DESCRIPTOR);
                return true;
            }
            if (code != TRANSACTION_GET_SNAPSHOT) {
                return super.onTransact(code, data, reply, flags);
            }
            data.enforceInterface(DESCRIPTOR);
            byte[] snapshot = PolicyOraclePayloads.getPreloadedSnapshot();
            if (snapshot == null || snapshot.length == 0) {
                snapshot = PolicyOraclePayloads.failure(
                        "TamperProbe app-zygote preload did not provide a snapshot."
                );
            } else if (snapshot.length > PolicyOraclePayloads.MAX_PAYLOAD_BYTES) {
                snapshot = PolicyOraclePayloads.failure(
                        "TamperProbe app-zygote snapshot exceeded 64 KiB."
                );
            }
            reply.writeNoException();
            reply.writeByteArray(snapshot);
            return true;
        }
    }
}
