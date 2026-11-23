# Cell X0 — Xiaomi 12, stock, bootloader locked

Read from the device on 2026-11-23 between 17:42 and 17:48 (UTC+8), before any app under test was
installed, after the E4 registration commit `6ef1ada` (17:48:03). The phone had been up 13 minutes
at 17:48; it was not rebooted by this session.

| Condition | Value |
| --- | --- |
| Model | Xiaomi 2201123G (`cupid`) |
| Build fingerprint | `Xiaomi/cupid_global/cupid:15/AQ3A.250226.002/OS3.0.3.0.VLCTWXM:user/release-keys` |
| Security patch | system 2026-05-01, vendor 2026-02-01 (slot `_b`) |
| `uname -a` | `Linux localhost 5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284 #1 SMP PREEMPT Tue Oct 21 03:03:12 UTC 2025 aarch64` |
| `/proc/version` | `Linux version 5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284 (build-user@build-host) (Android (7284624, based on r416183b) clang version 12.0.5 …, LLD 12.0.5 …) #1 SMP PREEMPT Tue Oct 21 03:03:12 UTC 2025` |
| Build | `ro.build.type=user`, `ro.build.tags=release-keys`, `ro.debuggable=0`, `ro.secure=1` |
| Boot properties | `verifiedbootstate=green`, `flash.locked=1`, `vbmeta.device_state=locked`; `sys.oem_unlock_allowed=0` |
| SELinux | Enforcing |
| Root | `which su` empty; `/system/bin/su`, `/system/xbin/su`, `/sbin/su` absent; `/data/adb` not listable by the shell |
| Developer settings | `development_settings_enabled=1`, `adb_enabled=1`, `persist.sys.usb.config=adb` (§3) |
| Root-tool packages | none of the Lab's indicator list and none of RootBeer's 48 `Const.java` packages installed (matches only; no other package recorded) |
| Concealment | none installed; nothing to configure |

## Apps under test

Before the captures, as registered in §7 step 2: `io.leemikepop.tamperprobe` (1.0.157) and its
`.test` package, and the development builds of both retrofit hosts and their test packages
(versionName 1.0.4, installed 2026-10-16), were uninstalled. The tag builds and the archived
black-box APKs were then installed. HyperOS asks for confirmation of every adb install ("USB 安裝提醒",
auto-reject after 10 s); this session confirmed each one with `input tap`. Key Attestation was
already installed (2026-10-15) with the archived build and was kept.

Installed sha256 (first 16), every one equal to §2:

| Package | sha256 |
| --- | --- |
| `io.leemikepop.tamperprobe.lab` (+ `.test`) | `c8eb9b3955ba27a6` (`12df311fa6887171`) |
| `…retrofit.rootbeer` (+ `.test`) | `59303db8b5f7f2e9` (`9dc1ac578f985e01`) |
| `…retrofit.ruru` (+ `.test`) | `b7eaf05f07cfa3ec` (`b4a85dc6f92d0173`) |
| `com.eltavine.duckdetector` 1023, then 521 | `3a433cc90fc6f2ee`, then `8cca9380cc623f22` |
| `com.reveny.nativecheck` 7.7.0 | `1033d24102af2632` |
| `io.github.vvb2060.keyattestation` 2.0.2 | `f6acc0d3e25a1df8` |
| `com.byxiaorun.detector` 1.1.1 | `8a2856cd13353c18` |

Every export records `gitCommit 8c047f1693b5`, `gitDirty false`.

## Captures

The instrumented export tests were run with `adb shell am instrument -w` against the installed
APKs (the Lab with `-e class io.leemikepop.tamperprobe.lab.FullScanExportTest`), in rounds of Lab,
RootBeer host, Ruru host, three rounds. Gradle was not used because it reinstalls the APKs, which
on HyperOS needs the install confirmation each time; the test classes and APKs are those Gradle
would run.

**Recapture.** The first three rounds (17:53, UTC 09:53) were lost: the pull command wrote every
file to one wrong local path, each overwriting the last, and the session deleted the device copies
before checking. Only the last file survived under the wrong name; it was not kept. The three
rounds were captured again at 17:58–17:59 (UTC 09:58–09:59), pulled, checked and only then deleted
from the device. These are the exports in this directory. Nothing on the phone changed between the
two captures. Earlier development exports from 2026-10-16 left in `/data/local/tmp` were not
touched and are not used.

`compare_cells.py --provenance raw/X0` exits 0; repetition disagreements: none for `full`,
`rootbeer` and `ruru`. The exports contain no device serial, no Android ID and no package name
except the hosts' own.

## Black-box runs

| App | Run (local time) | Record | Displayed verdict |
| --- | --- | --- | --- |
| Key Attestation 2.0.2 | 18:02 | `keyattestation-1.png/.txt` | "Google 硬體認證的根憑證"; "開機載入器已上鎖"; chain of 4; revocation list of 2026-11-20 22:48 UTC fetched ("已取得新清單!"), no certificate marked revoked |
| Native Root Detector 7.7.0 | 18:03, 18:04 | `nrd-defaults.png`, `nrd-1.png/.txt` | "The Environment is normal" with both settings off (fresh-install defaults) and again with both on |
| Ruru 1.1.1 | 18:05 | `ruru-1…3.png/.txt` | every item "未發現" except 設置屬性 "可疑": 已開啓開發者選項 可疑, 已開啓usb調試 可疑, vpn not connected 未發現 |
| Duck 1023 | 18:08 | `duck1023-1.png/.txt`, `duck1023-report.txt` | Danger 0, Warning 2, Ready 18, Pending 0 |
| Duck 521 | 18:12 | `duck521-1.png/.txt`, `duck521-report.txt` | Danger 0, Warning 1, Ready 15, Pending 0 |

Notes:

- **NRD settings.** On this fresh install "Experimental Detections" and "Custom ROM Detections" were
  off; the E1 records show both on. The first screen (`nrd-defaults.png`) was kept, both were
  switched on in NRD's settings, the app was restarted and `nrd-1` was taken. uiautomator returns no
  node tree for NRD, so `nrd-1.txt` is transcribed from the screenshot.
- **Ruru.** The E1 records keep Ruru's first screen only, which ends at "LSPatch 應用程式". Here the
  list was scrolled (`ruru-2`) and the 設置屬性 item expanded (`ruru-3`); the items below the first
  screen (Magisk 應用程式, 無障礙服務, 設置屬性, 帳戶) were not recorded in E1, so whether 設置屬性 was
  also "可疑" there is unknown.
- **Duck 1023.** Warnings: ADB Runtime ("ADB enabled") and System Properties, whose single review
  item is `persist.sys.usb.config: adb`; Boot and Build both Clean. Every other card INFO or CLEAR.
  No Nightly update prompt appeared.
- **Duck 521.** Warning: System Properties, the same single item. Every other card INFO or CLEAR.
- **Duck start-up choices** (both builds): user agreement accepted (scroll, timer, arithmetic check),
  notifications "跳過", GitHub acceleration "暫不開啟" (1023), CRL online refresh left unanswered; both
  reports say "Built-in revocation snapshot is active; online refresh is awaiting startup consent",
  as in E1. The export picker opened in `Download/`; nothing in it was recorded.
- **Duck reports** were pulled to a scratch directory, deleted from the device and redacted before
  they were kept (E1–E3 amendment of 2026-10-20): 17 lines in the 1023 report (certificate serial
  numbers, `2.5.4.5` values, intermediate validity periods) and 4 lines in the 521 report (`2.5.4.5`
  values). Neither contains the serial, the Android ID or another app's package name.
- Duck 521 was left installed at the end; Duck 1023 was not restored, because no cell follows.
- Every screenshot was checked for notifications and other apps before it was kept.
