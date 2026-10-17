# Cell P1 — Pixel 7, KernelSU + SUSFS LKM (no rules)

Differs from P0 only by the SUSFS LKM module. Read from the device on 2026-10-17 after the operator
installed `susfs_guard_lkm`, `early_load` was created and the phone was rebooted.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, `uname -a`, `/proc/version`, ksud | as P0 (unchanged) |
| KernelSU features | as P0: `su_compat` on, `kernel_umount` on, `selinux_hide` **off** |
| Boot properties | `verifiedbootstate=orange`, `flash.locked=0`, `vbmeta.device_state=unlocked` |
| SELinux | Enforcing |
| Modules | `susfs_guard_lkm` `main-899976e` (1792074277) **enabled**, `early_load` present; `susfs4ksu` v1.5.2-R28 installed, **disabled** |
| Early loader | `/data/adb/post-fs-data.d/00-susfs-guard-lkm.sh` byte-identical to the module's `early-dispatch.sh` |
| SUSFS kernel side | `/sys/module/susfs_guard_lkm` present; `ksu_susfs show version` = `v2.3.0`; `/proc/susfs_*` control nodes present (`expose_proc=1`); not listed in `/proc/modules` |
| `load.log` | one load this boot (20:40:14): `android14-6.1` image, 103/103 symbols resolved, `loaded.` |
| SUSFS rules | none (`susfs4ksu` disabled) |
| HMA / TrickyStore / LSPosed / Zygisk | not installed |

`load.log` cannot tell the early path from the module's own `post-fs-data.sh`; with `early_load`
present the latter exits without loading once the module is up, and the log shows a single load.

Apps under test: same installed builds and hashes as P0. No product-repository app installed.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "開機載入器已解鎖" |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is abnormal"; Bootloader Unlocked ×2 |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 521 | `duck521-report.txt` (20:49) | Danger 4, Warning 3, Ready 15, Pending 0 |
| Duck 1023 | `duck1023-report.txt` (20:52) | Danger 3, Warning 6, Ready 18, Pending 0 |

Every Duck card's level and verdict line is identical to P0 for both builds.

Deviations: Duck 521 ran before 1023 in this cell (registered order: 1023 first). The operator
drove Duck's UI and exported both reports; this session pulled them and deleted them from the
device. No Duck first-screen screenshot was kept: the only one taken caught a rescan in progress
(Pending 1), started by a leftover automation script, and was discarded. An earlier automated
attempt left no record.
