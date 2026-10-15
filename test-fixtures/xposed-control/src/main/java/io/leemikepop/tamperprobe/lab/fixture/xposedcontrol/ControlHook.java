package io.leemikepop.tamperprobe.lab.fixture.xposedcontrol;

import android.app.Activity;
import android.os.Process;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * A positive control, not a tampering tool.
 *
 * <p>An experiment needs a condition that differs from its baseline in exactly one way: an
 * inline-hook framework is active inside the Sample App's process. Third-party modules do more
 * than that -- they hide packages, spoof properties or rewrite resources -- and each of those
 * would move other detectors too, so a result could not be attributed. This module installs one
 * hook and changes no behaviour: after {@code Activity.onResume} it writes a log line.
 *
 * <p>Loading any module into a process makes the framework initialise its ART hooking there, and
 * installing a hook patches that method's entry. Those two effects are what the runtime-integrity
 * detectors are meant to see; everything here exists to produce them and to prove from logcat
 * that they happened.
 *
 * <p>Only the main process of {@code io.leemikepop.tamperprobe.lab} is hooked. Its helper processes
 * run isolated carriers, and keeping them unhooked means a change in a carrier-based result cannot
 * come from this module.
 */
public final class ControlHook implements IXposedHookLoadPackage {

    static final String TARGET_PACKAGE = "io.leemikepop.tamperprobe.lab";
    static final String TAG = "TPXposedControl";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam param) {
        if (!TARGET_PACKAGE.equals(param.packageName) || !TARGET_PACKAGE.equals(param.processName)) {
            return;
        }
        Log.i(TAG, "event=module_loaded process=" + param.processName + " pid=" + Process.myPid());

        XposedHelpers.findAndHookMethod(Activity.class, "onResume", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam hookParam) {
                Log.i(TAG, "event=hook_invoked method=Activity.onResume activity="
                        + hookParam.thisObject.getClass().getName());
            }
        });
        Log.i(TAG, "event=hook_installed method=Activity.onResume pid=" + Process.myPid());
    }
}
