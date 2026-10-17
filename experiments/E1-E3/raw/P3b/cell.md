# Cell P3b — Pixel 7, P2 + uname spoof after Zygote (timing branch)

Differs from P2 only by the uname spoof in `susfs4ksu` mode 1 (`spoof_uname=1`, applied in
boot-completed, after Zygote has started), with the same strings as P3a. Compared with P3a for the
timing question only. Read from the device on 2026-10-17 after the reboot.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, ksud | as P0 |
| `uname -a` (shell, after boot) | `Linux localhost 6.1.162-android14-11-g9dd05ae3a1de-ab16261587 #1 SMP PREEMPT Thu Sep  3 03:59:00 UTC 2026 aarch64` |
| `/proc/version` (root shell) | unchanged blu_spark banner, as P3a |
| `susfs4ksu` `config.sh` | as P3a except `spoof_uname=1`; same `kernel_version` / `kernel_build`; rule files unchanged |
| KernelSU features | as P0: `selinux_hide` **off** |
| Boot properties | as P2: green / locked (spoofed by `susfs4ksu`) |
| Modules | `susfs4ksu` and `susfs_guard_lkm` (early load) enabled, as P2 |

Apps under test: same installed builds and hashes as P0.

## Observations (from `compare_cells.py raw/P3a raw/P3b`; 3 repetitions agree)

| Detector | P3a | P3b |
| --- | --- | --- |
| `KERNEL_CHECK` | NOT_OBSERVED (concealable negatives) | OBSERVED MODERATE |

Identity coherence `disagree`: `zygote_os_version` = `6.1.162-android14-283-blu-spark`,
`uname_release` = `6.1.162-android14-11-g9dd05ae3a1de-ab16261587`. RootBeer and Ruru retrofits
unchanged.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "開機載入器已解鎖" |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is normal" |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | `duck1023-report.txt` (21:35) | Danger 3, Warning 6, Ready 18, Pending 0; **Kernel Check Danger** ("1 suspicious kernel signal(s)") |
| Duck 521 | `duck521-report.txt` (21:42) | Danger 4, Warning 3, Ready 15, Pending 0; **Kernel Check Danger** ("1 suspicious kernel signal(s)") |

Both Duck builds state that the uname identity disagrees with the value captured when the app's
runtime started. Other Duck card changes from P3a: 1023 Bootloader 1 → 5 critical signals (its key
attestation succeeded again, chain length 5; see `../P3a/cell.md`); 1023 Zygote heap residue
"No target trace observed" → "Inconclusive". Both builds obtained a 5-certificate chain here.

Order as registered (1023, then 521, then 1023 restored, sha256 checked after each install). The
operator drove Duck's UI and exported the reports; this session pulled and deleted them.
