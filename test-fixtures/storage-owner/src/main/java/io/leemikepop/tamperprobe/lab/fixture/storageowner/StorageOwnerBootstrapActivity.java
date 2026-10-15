package io.leemikepop.tamperprobe.lab.fixture.storageowner;

import android.app.Activity;
import android.os.Bundle;

/** Clears the package stopped state between unheld and held fixture phases. */
public final class StorageOwnerBootstrapActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        finish();
    }
}
