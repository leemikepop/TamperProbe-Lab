# Cell P2 — Pixel 7, KernelSU + SUSFS LKM + susfs4ksu R28

Differs from P1 only by enabling `susfs4ksu`. Read from the device on 2026-10-17 after the
operator enabled the module and rebooted.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, `uname -a`, `/proc/version`, ksud | as P0 (unchanged; no uname spoof) |
| KernelSU features | as P0: `su_compat` on, `kernel_umount` on, `selinux_hide` **off** |
| Boot properties | **`verifiedbootstate=green`, `flash.locked=1`, `vbmeta.device_state=locked`** (set by `susfs4ksu`, see below) |
| SELinux | Enforcing |
| Modules | `susfs4ksu` (`module.prop` version now reads `v2.3.0-R28`, versionCode 105002028) **enabled**; `susfs_guard_lkm` `main-899976e` enabled, `early_load` present |
| SUSFS kernel side | loaded as P1 (`load.log`: one load, `loaded.`) |
| HMA / TrickyStore / LSPosed / Zygisk | not installed |

`susfs4ksu` configuration in `/data/adb/susfs4ksu/` (kinds and counts only; no paths recorded):

| File | Entries |
| --- | --- |
| `sus_path.txt`, `sus_path_loop.txt`, `sus_mount.txt`, `sus_maps.txt`, `sus_open_redirect.txt`, `try_umount.txt` | 0 each |
| `legit_mounts.txt` | 46 |
| `sus_kstat_statically.json` | `[]` |

`config.sh`: `spoof_uname=0`, `kernel_version`/`kernel_build` `default`, `spoof_cmdline=0`,
`hide_sus_mnts_for_all_or_non_su_procs=1`, `auto_try_umount=0`, `avc_log_spoofing=0`, every
`hide_*` option 0, `vbmeta_size=18816`.

The module's `service.sh` sets `ro.boot.vbmeta.device_state=locked`,
`ro.boot.verifiedbootstate=green`, `ro.boot.flash.locked=1` (and the `vendor.boot.*` copies)
unconditionally; no `config.sh` key controls it. P2 therefore changes two things at once: SUSFS
rules (none are configured) and boot-property spoofing. Every change below is a property change.

Apps under test: same installed builds and hashes as P0.

## Observations (from `compare_cells.py raw/P1 raw/P2`; 3 repetitions agree)

| Detector | P1 | P2 |
| --- | --- | --- |
| `DANGEROUS_PROPS` | OBSERVED MODERATE | NOT_OBSERVED, **no concealable-negative record** |
| `TEE_ATTESTATION` | OBSERVED WEAK | OBSERVED MODERATE (`attested_boot_state_contradicts_properties` added) |
| `DRM_CREDENTIAL_COHERENCE` | NOT_OBSERVED | OBSERVED MODERATE (`locked_claim_without_drm_credential`) |

RootBeer and Ruru retrofits unchanged from P1. No path-based check was positive in P1, so the P2
prediction about path-based checks has nothing to test.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "開機載入器已解鎖" |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | **"The Environment is normal"**; no finding |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | `duck1023-report.txt` (21:02) | Danger 2, Warning 6, Ready 18, Pending 0 |
| Duck 521 | `duck521-report.txt` (21:07) | Danger 3, Warning 3, Ready 15, Pending 0 |

Duck card changes from P1: 1023 — Bootloader 8 → 5 critical signals; System Properties Danger →
Warning ("1 property signal(s) need review"); Custom ROM Warning → Info (reduced coverage); ADB
Runtime (Warning, unchanged) now also appears under Top Findings; Zygote heap residue Inconclusive → "No target trace
observed". 521 — Bootloader 6 → 5; System Properties Danger → Warning; TEE verdict now "Policy-backed
attestation anomalies were detected"; Custom ROM Warning → Info.

Order as registered (1023, then 521, then 1023 restored, sha256 checked after each install). The
operator drove Duck's UI and exported the reports; this session pulled and deleted them.

## Note added 2026-10-17 (after P3a)

Duck 521's TEE verdict in this cell ("Policy-backed attestation anomalies were detected",
"Tampered") comes with its local certificate chain failing (chain length 0, trust root unknown);
in P3a the same build obtained a 5-certificate Google chain again. The change is a Duck-side
attestation failure in this single run and is not attributed to the P2 factor.
