# Cell P0 — Pixel 7, KernelSU only

Read from the device on 2026-10-17 after the operator turned KernelSU "Hide SELinux" off and
rebooted (UTC times are in the export file names).

| Condition | Value |
| --- | --- |
| Build fingerprint | `google/panther/panther:17/CP3A.261005.002.A1/16269273:user/release-keys` |
| Security patch | 2026-10-05 (slot `_b`) |
| `uname -a` | `Linux localhost 6.1.162-android14-283-blu-spark #283 SMP PREEMPT Wed Oct 14 23:34:16 WEST 2026 aarch64` |
| `/proc/version` | `Linux version 6.1.162-android14-283-blu-spark (stk@sparky) (blu_spark clang version 17.0.6, blu_spark LLD 17.0.6) #283 SMP PREEMPT Wed Oct 14 23:34:16 WEST 2026` |
| ksud | `3.3.1-110` (uapi 5) |
| KernelSU features | `su_compat` on, `kernel_umount` on, `selinux_hide` **off**, `sulog` off, `adb_root` off, `shell_su_adb_only` off |
| Boot properties | `verifiedbootstate=orange`, `flash.locked=0`, `vbmeta.device_state=unlocked` |
| SELinux | Enforcing |
| Modules | `susfs4ksu` v1.5.2-R28 (105002028) installed, **disabled**; nothing else; `modules_update` empty |
| SUSFS kernel side | not loaded (no `susfs` entry in `/proc/modules`) |
| HMA / TrickyStore / LSPosed | not installed |

Apps under test, installed sha256 (first 16) checked against the tag build and `cells/apks.sha256`:

| Package | sha256 |
| --- | --- |
| `io.leemikepop.tamperprobe.lab` (+ `.test`) | `c8eb9b3955ba27a6` (`12df311fa6887171`) |
| `…retrofit.rootbeer` (+ `.test`) | `59303db8b5f7f2e9` (`9dc1ac578f985e01`) |
| `…retrofit.ruru` (+ `.test`) | `b7eaf05f07cfa3ec` (`b4a85dc6f92d0173`) |
| `com.eltavine.duckdetector` 1023 | `3a433cc90fc6f2ee` |
| `com.reveny.nativecheck` 7.7.0 | `1033d24102af2632` |
| `io.github.vvb2060.keyattestation` 2.0.2 | `f6acc0d3e25a1df8` |
| `com.byxiaorun.detector` 1.1.1 | `8a2856cd13353c18` |

Lab APKs built from tag `eval-2026-10-v1` in a clean worktree; every export records
`gitCommit 8c047f1693b5`, `gitDirty false`.

Other packages present: the Lab's own `…lab.raspfixture`, `…lab.fixture.storageowner` and
`…lab.lib.test` from development builds (2026-10-15/16); no Xposed module app is installed.

## Recapture

The first P0 capture (`../P0-superseded/`) was taken with the product repository's apps still
installed, among them `io.leemikepop.tamperprobe.fixture.xposedcontrol`, an Xposed module without
a launcher entry that Ruru 1.1.1 reported as "Xposed 模組: 發現". With the operator's agreement,
the six product-repository packages (`io.leemikepop.tamperprobe`, `.test`, `.lib.test`,
`.raspfixture`, `.fixture.xposedcontrol`, `.fixture.storageowner`) were uninstalled and the whole
cell was captured again; nothing else changed. The superseded capture is kept, not used.

## Black-box runs

| App | Run (local time) | Record | Displayed verdict |
| --- | --- | --- | --- |
| Key Attestation 2.0.2 | 20:22 | `keyattestation-1.png/.txt` | Google RKP chain; "開機載入器已解鎖" |
| Native Root Detector 7.7.0 | 20:22 | `nrd-1.png/.txt` | "The Environment is abnormal"; Bootloader Unlocked ×2 |
| Ruru 1.1.1 | 20:22 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | 20:23 | `duck1023-1…6.png/.txt` | Danger 3, Warning 6, Ready 18, Pending 0 |
| Duck 521 | 20:26 | `duck521-1.png/.txt`, `duck521-report.txt` | Danger 4, Warning 3, Ready 15, Pending 0 |
| Duck 1023 (after restore) | 20:33 | `duck1023-report.txt` | Danger 3, Warning 6, Ready 18, Pending 0 |

Duck order as registered: 1023, uninstall, install 521, capture, uninstall, install 1023. The
installed sha256 was checked after each install (521 `8cca9380cc623f22`, 1023 `3a433cc90fc6f2ee`).
Both fresh installs showed Duck's user agreement; the operator's session accepted it (scroll,
timer, arithmetic check). Duck 1023 first showed a Nightly update prompt, dismissed with "稍後";
nothing was downloaded. Duck's own exported reports were added at the operator's suggestion (see
the README amendment of 2026-10-17); the 1023 report comes from the post-restore launch, so 1023 has
two launches in this cell, with the same counts. The report files name the device model only.

Capture note: the capture script of the superseded capture first wrote the pulled files to a wrong
local path; those exports were pulled again from the device. The exports here were pulled once.
