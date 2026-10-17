# Cell P0 — Pixel 7, KernelSU only

> Superseded by `../P0/`: captured with the product repository's apps installed (see `../P0/cell.md`).

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

Capture note: the capture script first wrote the pulled files to a wrong local path; the nine
exports in this directory were pulled again from `/data/local/tmp` on the device, unchanged.
