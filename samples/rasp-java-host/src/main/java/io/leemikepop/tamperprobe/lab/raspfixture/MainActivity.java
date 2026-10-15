package io.leemikepop.tamperprobe.lab.raspfixture;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView content = new TextView(this);
        content.setText("Java-only RASP injection fixture");
        content.setTextSize(20);
        content.setPadding(32, 64, 32, 32);
        setContentView(content);
    }
}
