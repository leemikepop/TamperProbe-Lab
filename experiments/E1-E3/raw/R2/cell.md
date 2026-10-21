# Cell R2 — Redmi 13C, R1 + HMA-OSS (held out)

Differs from R1 by HMA-OSS oss-173 (Zygisk module and app) with the P5 presets on every app under
test. Read from the device on 2026-10-21 after the operator flashed the module, set the presets,
put Duck 1023 back on the DenyList and rebooted.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, `uname`, boot properties, SELinux, Magisk settings | as R1 |
| Modules | **`hma_oss_zygisk` `oss-173` (7304656) enabled**; `zygisksu` 864 enabled; `zn_magisk_compat` disabled |
| HMA-OSS module files | the 12 files of the registered zip (`be364502…`) match the installed module; the module adds `module.prop.bak` |
| HMA-OSS app | `org.frknkrc44.hma_oss` oss-173, sha256 `e2f28be0689080ba` (the `manager.apk` inside the registered zip) |
| Zygisk Next | `inject_state:1`, `enforce_denylist:1`, `modules64:1,hma_oss_zygisk`, `modules32:1,hma_oss_zygisk`, `modules_with_issue:0` |
| HMA-OSS scope | each of the seven apps under test: `applyPresets` `root_apps`, `shizuku_dhizuku`, `sus_apps`, `xposed`; blacklist mode, `excludeSystemApps` true, no templates, no extra apps (re-read for Duck after each reinstall: unchanged) |
| DenyList | as R1; Duck put back after each reinstall and counted (1023: 5 processes; 521: 4 + 5 isolated services) |

Apps under test: same installed builds and hashes as R0.

## Observations (from `compare_cells.py raw/R1 raw/R2`; 3 repetitions agree)

No Lab detector changed outcome or strength. `DANGEROUS_PACKAGES` stays OBSERVED WEAK: the
detected packages go from four (`com.termux`, `com.topjohnwu.magisk`, `io.github.a13e300.ksuwebui`,
`top.canyie.magiskkiller`) to one, `top.canyie.magiskkiller` (MagiskKiller 1.3, a detector app on
the Redmi since 2025-10-27), which none of the four presets hides. Visible packages 297 → 292.
The concealable-negative records are the same three as in R0 and R1.

Prediction check: "package checks in Lab and both retrofits become NOT_OBSERVED with C-neg" holds for
RootBeer and Ruru, and fails for the Lab because of MagiskKiller (README amendment of 2026-10-21).
On the Pixel no such app was installed and P5 reached the concealable negative.

Retrofits:

- RootBeer: positives 1 → 0; all 9 clean checks concealable.
- Ruru: PM conventional, sundry and intent queries FOUND → NOT_FOUND, concealable; libc and syscall
  file checks stay FOUND; 8 clean checks = 1 `no_answer`, 6 concealable, 1 mixed.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "無法認證", as R0 |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is abnormal"; Bootloader Unlocked ×2; Risky App gone |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" except PM 命令 "被拒絕" (libc and syscall file checks included) |
| Duck 1023 | `duck1023-report.txt` (15:01) | Danger 4, Warning 5, Ready 18, Pending 0 |
| Duck 521 | `duck521-report.txt` (15:14) | Danger 5, Warning 3, Ready 15, Pending 0 |

NRD again did not come to the foreground on the first launch and was captured on a second launch.

Duck 1023 changes from R1: Dangerous Apps 4 → 1 (MT Manager via `/sdcard/MT2`); Root Managers
Warning → "Partially evaluated". Duck 521 changes from R1: Dangerous Apps 4 → 1. Neither Duck build
lists MagiskKiller. Mount stays Danger in both.

Certificate identifiers in both reports were redacted before the files were kept. Order as
registered (1023, then 521, then 1023 restored, sha256 checked after each install, Duck put back on
the DenyList before each run). The operator drove Duck's UI and exported the reports; this session
pulled and deleted them.
