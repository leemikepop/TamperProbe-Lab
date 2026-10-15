# Xposed control fixture

A research positive control for the runtime-integrity detectors. It is an Xposed module that
installs one hook in the Sample App's main process — after `Activity.onResume`, write a log
line — and changes nothing else.

It is not a dependency of `:tamperprobe`, is not published, and must never be installed on a
device that is not a test device.

## Why a purpose-built module

A positive control has to differ from its baseline in exactly one respect: an inline-hook
framework is active inside the process being scanned. Existing modules hide packages, spoof
properties or rewrite resources as well, and each of those moves other detectors, so a change in
the report could not be attributed to the hook. This module has one hook and no other effect.

## What it produces

- The framework initialises its ART hooking inside `io.leemikepop.tamperprobe.lab` (main process
  only; helper processes are left alone so carrier-based results cannot be affected).
- One method entry is patched: `android.app.Activity.onResume`.
- Logcat, tag `TPXposedControl`: `module_loaded` and `hook_installed` when the process starts,
  `hook_invoked` on every resume. An experiment is only valid if `module_loaded` and
  `hook_installed` appear for the scanned process.

## Installing

1. Build: `.\gradlew.bat :test-fixtures:xposed-control:assembleDebug`, then
   `adb install -r test-fixtures/xposed-control/build/outputs/apk/debug/xposed-control-debug.apk`.
2. In the LSPosed manager, enable the module and tick **only** `io.leemikepop.tamperprobe.lab` in its
   scope.
3. **Remove the Sample App from Magisk's DenyList.** LSPosed is loaded by Zygisk, and with Enforce
   DenyList on, no Zygisk module is loaded into a listed app, so the module would never run.
4. Force-stop the Sample App (no reboot is needed for a scope change), start it, and confirm the
   three log events.

## Recording a cell

Record the LSPosed build and where it came from, the Zygisk implementation, whether the Sample App
is on the DenyList, the module's enabled state and its exact scope. To attribute an effect to the
hook rather than to the DenyList change, capture the cell with the Sample App removed from the
DenyList **before** enabling this module, then again after.
