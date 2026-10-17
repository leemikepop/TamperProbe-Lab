# Cell P3a — Pixel 7, P2 + uname spoof before Zygote

Differs from P2 only by the uname spoof in `susfs4ksu` mode 2 (`spoof_uname=2`, applied in
post-fs-data). Read from the device on 2026-10-17 after the reboot.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, ksud | as P0 |
| `uname -a` (shell) | `Linux localhost 6.1.162-android14-11-g9dd05ae3a1de-ab16261587 #1 SMP PREEMPT Thu Sep  3 03:59:00 UTC 2026 aarch64` |
| `/proc/version` (root shell) | unchanged: `Linux version 6.1.162-android14-283-blu-spark (stk@sparky) (blu_spark clang version 17.0.6, blu_spark LLD 17.0.6) #283 SMP PREEMPT Wed Oct 14 23:34:16 WEST 2026` |
| Spoof values | release and version strings of the stock kernel in the `CP3A.261005.002.A1` factory image (`boot.img`, LZ4 kernel, `Linux version` banner) |
| `susfs4ksu` `config.sh` | as P2 except `spoof_uname=2`, `kernel_version='6.1.162-android14-11-g9dd05ae3a1de-ab16261587'`, `kernel_build='#1 SMP PREEMPT Thu Sep  3 03:59:00 UTC 2026'`; rule files unchanged (all 0 except `legit_mounts.txt` 46) |
| KernelSU features | as P0: `selinux_hide` **off** |
| Boot properties | as P2: green / locked (spoofed by `susfs4ksu`) |
| Modules | `susfs4ksu` and `susfs_guard_lkm` (early load) enabled, as P2 |

Apps under test: same installed builds and hashes as P0.

## Observations (from `compare_cells.py raw/P2 raw/P3a`; 3 repetitions agree)

| Detector | P2 | P3a |
| --- | --- | --- |
| `KERNEL_CHECK` | OBSERVED MODERATE | NOT_OBSERVED with concealable-negative records |

`KERNEL_CHECK` publishes `custom_kernel_signature` and `kernel_symbol_token` as banner concealable
negatives (uname source; `/proc/version` unreadable to the app). Identity coherence reports
`agree` over two readable sources (`zygote_os_version`, `uname_release`); `/proc/sys/kernel/osrelease`
and the `/proc/version` release are unreadable to the app. RootBeer and Ruru retrofits unchanged.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "開機載入器已解鎖" |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is normal" |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | `duck1023-report.txt` (21:18) | Danger 2, Warning 6, Ready 18, Pending 0; Kernel Check Info, Identity Clean |
| Duck 521 | `duck521-report.txt` (21:22) | Danger 3, Warning 3, Ready 15, Pending 0; Kernel Check Info, Identity Clean |

Duck card changes from P2, neither from the uname factor:

- 1023 Bootloader 5 → 1 critical signal. In this run Duck reports "Key attestation: Unavailable
  (Failed to generate key pair)", chain length 0, and falls back to the spoofed boot properties.
- 521 TEE verdict back to "Attestation aligned; local probes need review" (chain length 5, Google
  root); in P2 its local chain had failed (see the note in `../P2/cell.md`).

Black-box apps run once per build, so a Duck-side attestation failure cannot be separated from a
cell effect by repetition; these cards are reported as displayed and not attributed. The Lab's
`TEE_ATTESTATION` obtained a hardware chain in all three repetitions of both cells.

Order as registered (1023, then 521, then 1023 restored, sha256 checked after each install). The
operator drove Duck's UI and exported the reports; this session pulled and deleted them.
