package io.leemikepop.tamperprobe.lab.internal.fdforensics;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;

public final class ZygiskFdForensicsCarrierService extends Service {
    static final String DESCRIPTOR =
            "io.leemikepop.tamperprobe.lab.internal.fdforensics.IZygiskFdForensicsCarrier";
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
            ParcelFileDescriptor trap = null;
            if (data.readInt() != 0) {
                trap = ParcelFileDescriptor.CREATOR.createFromParcel(data);
            }
            int trapFd = trap == null ? -1 : trap.getFd();
            byte[] snapshot;
            try {
                snapshot = FdForensicsNativeBridge.collectSnapshot(trapFd);
            } finally {
                if (trap != null) {
                    try { trap.close(); } catch (java.io.IOException ignored) { }
                }
            }
            if (snapshot == null || snapshot.length == 0) {
                snapshot = FdForensicsPayloads.failure(
                        "Descriptor-forensics carrier produced no snapshot."
                );
            } else if (snapshot.length > FdForensicsPayloads.MAX_PAYLOAD_BYTES) {
                snapshot = FdForensicsPayloads.failure(
                        "Descriptor-forensics carrier snapshot exceeded 64 KiB."
                );
            }
            reply.writeNoException();
            reply.writeByteArray(snapshot);
            return true;
        }
    }
}
