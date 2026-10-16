package io.leemikepop.tamperprobe.lab.retrofit.ruru

import android.app.Application

/**
 * Loads Ruru's native library where Ruru's own `MyApplication` does: in the Application's
 * initialiser, before anything else runs.
 *
 * Loading it is not passive. Its `JNI_OnLoad` calls xposed-detector's `get_xposed_status`, which
 * clears Xposed hooks it finds in this process (`ANTIED_XPOSED`). That is why Ruru runs in its own
 * host app and never in the probe app or next to RootBeer (Rule 5).
 */
class RuruRetrofitApplication : Application() {
    init {
        System.loadLibrary("applist_detector")
        System.loadLibrary("ruru_shadow")
    }
}
