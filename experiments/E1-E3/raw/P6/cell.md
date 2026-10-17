# Cell P6 — Pixel 7, P5 + KernelSU "Hide SELinux modification"

Differs from P5 only by the KernelSU feature `selinux_hide` (on). Read from the device on
2026-10-17 after the operator switched it on and rebooted.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, ksud, uname, `/proc/version` | as P4 |
| KernelSU features | `su_compat` on, `kernel_umount` on, **`selinux_hide` on**, `sulog` off, `adb_root` off, `shell_su_adb_only` off |
| Boot properties | as P2: green / locked (spoofed by `susfs4ksu`) |
| Modules | `hma_oss_zygisk` oss-173, `zygisksu` 864, `susfs4ksu`, `susfs_guard_lkm` (early load), all enabled |
| Zygisk Next | `inject_state:1`, `enforce_denylist:0`, `modules64:1,hma_oss_zygisk` |
| `susfs4ksu` | as P5 (`spoof_uname=2`; rule files unchanged) |
| HMA-OSS scope | as P5 for all seven apps under test (re-read for Duck after each reinstall: unchanged) |

Apps under test: same installed builds and hashes as P0.

## Observations (from `compare_cells.py raw/P5 raw/P6`; 3 repetitions agree)

| Detector | P5 | P6 |
| --- | --- | --- |
| `NATIVE_ROOT_SEPOLICY` | OBSERVED WEAK (`ksu_file_read_allowed`) | **INCONCLUSIVE** |

`NATIVE_ROOT_SEPOLICY` in P6: target context `ksu_file` is now `absent` (P5: `valid`); the other
targets as in P5 (`magisk_binder_call` and `adbd_adbroot_binder_call` absent, `shell_su_transition`
valid). All 6 gates passed, `oracleState inconclusive`, `findingCount 0`,
`concealableNegativeCount 0`. `LSPOSED_SEPOLICY` stays NOT_OBSERVED with concealable negatives
(`lsposed_file`, `xposed_data` targets absent). RootBeer and Ruru retrofits unchanged.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "開機載入器已解鎖" |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is normal" |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | `duck1023-report.txt` (23:16) | Danger 1, Warning 4, Ready 18, Pending 0; SELinux **Clear** ("Enforcing") |
| Duck 521 | `duck521-report.txt` (23:19) | Danger 2, Warning 3, Ready 15, Pending 0; SELinux **Warning** ("Enforcing with audit exposure") |

Duck card changes from P5:

- 1023: SELinux Danger ("Enforcing with KSU context materialized") → Clear ("Enforcing"); LSPosed
  Warning ("Dirty SELinux policy signal(s)") → Info ("LSPosed scan has reduced coverage"); Zygote
  heap residue "Inconclusive" → "No target trace observed".
- 521: SELinux Danger → Warning ("Enforcing with audit exposure": policy "Strong", one readable
  su-related AVC denial, a `getattr` on `/data/adb` by an `untrusted_app` thread in the scan's own
  category set); LSPosed Warning ("Dirty SELinux policy signal(s)") → Info ("reduced coverage").

Both builds obtained key attestation. Order as registered (1023, then 521, then 1023 restored,
sha256 checked after each install). The operator drove Duck's UI and exported the reports; this
session pulled and deleted them.
