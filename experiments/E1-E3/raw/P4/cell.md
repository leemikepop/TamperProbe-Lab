# Cell P4 — Pixel 7, P3a + Zygisk Next

Differs from P3a only by Zygisk Next 1.5.2, installed with its defaults. Read from the device on
2026-10-17 after the reboot.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, ksud | as P0 |
| `uname -a` (shell) | stock-kernel strings, as P3a (`spoof_uname=2`) |
| `/proc/version` (root shell) | unchanged blu_spark banner |
| `susfs4ksu` `config.sh` | as P3a (`spoof_uname=2`, same strings); rule files unchanged |
| KernelSU features | as P0: `selinux_hide` **off** |
| Boot properties | as P2: green / locked (spoofed by `susfs4ksu`) |
| Modules | `zygisksu` `1.5.2 (864-a4a72ce-release)` (864) **enabled**; `susfs4ksu`, `susfs_guard_lkm` (early load) enabled |
| Zygisk Next (`znctl status`) | `zygote_state_0` injected (`inject_state:1`), root `KernelSU (32695)`, `enforce_denylist:0`, `denylist_policy:0`, `memory_type:0`, `linker:1`, `modules64:0`, `modules32:0`; processes `zn-daemon`, `zn-nsdaemon-zygote` |

Apps under test: same installed builds and hashes as P0.

## Observations (from `compare_cells.py raw/P3a raw/P4`; 3 repetitions agree)

No detector changed outcome or strength. RootBeer and Ruru retrofits unchanged. With no Zygisk
module loaded and the DenyList off, nothing in the Lab's catalog distinguished P4 from P3a.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "開機載入器已解鎖" |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is normal" |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | `duck1023-report.txt` (21:53) | Danger 2, Warning 6, Ready 18, Pending 0; Zygisk Clear ("No Zygisk runtime signal") |
| Duck 521 | `duck521-report.txt` (22:17) | Danger 3, Warning 3, Ready 15, Pending 0; card list identical to P3a |

The only Duck card change from P3a is 1023 Bootloader 1 → 5 critical signals: its key attestation
succeeded here (it failed in the P3a run; see `../P3a/cell.md`). Against P3b's successful 1023 run,
Bootloader is unchanged at 5.

Order as registered (1023, then 521, then 1023 restored, sha256 checked after each install). The
operator drove Duck's UI and exported the reports; this session pulled and deleted them.
