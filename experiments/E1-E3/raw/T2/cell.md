# Cell T2 — Pixel 7, T1 + Play Integrity Fix

Differs from T1 only by Play Integrity Fix v4.9-inject-s (same build as R4). Read from the device on
2026-10-20 after the operator installed it and rebooted.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, ksud, uname, `/proc/version` | as P4 |
| KernelSU features | as P6: **`selinux_hide` on** |
| Boot properties | as P2: green / locked (spoofed by `susfs4ksu`) |
| Modules | **`playintegrityfix` `v4.9-inject-s` (490) enabled**; `tricky_store` 199, `hma_oss_zygisk` oss-173, `zygisksu` 864, `susfs4ksu`, `susfs_guard_lkm` (early load) enabled |
| Zygisk Next | `inject_state:1`, `enforce_denylist:0`, `modules64:2,hma_oss_zygisk,playintegrityfix` |
| `susfs4ksu`, HMA-OSS scope | as T1 (HMA re-read for Duck after each reinstall: unchanged) |
| TrickyStore | as T1: seven apps under test in `target.txt`, leaked hardware keybox (class only), `security_patch.txt` unchanged since 2026-10-16 |

PIF configuration in effect (`/data/adb/pif.prop`, set by the operator in the PIF WebUI after the
first boot, 22:36):

| Key | Value (module default in brackets where different) |
| --- | --- |
| `FINGERPRINT` | `google/panther_beta/panther:CANARY/ZP11.260918.007/16484274:user/release-keys` (default: `bluejay_beta` CANARY) |
| `MANUFACTURER` / `MODEL` | `Google` / `Pixel 7` (default model: Pixel 6a) |
| `SECURITY_PATCH` | `2026-10-05` |
| `DEVICE_INITIAL_SDK_INT` | `33` (default 32) |
| `spoofBuild` / `spoofVendingBuild` | true / true |
| `spoofProps` | **false** (default true) |
| `spoofProvider`, `spoofSignature`, `spoofVendingSdk`, `DEBUG` | false |

PIF injects into Google Play services and the Play Store, not into the apps under test. Apps under
test: same installed builds and hashes as P0.

## Observations (from `compare_cells.py raw/T1 raw/T2`; 3 repetitions agree)

No detector changed outcome or strength: `DRM_CREDENTIAL_COHERENCE` stays OBSERVED MODERATE,
`TEE_ATTESTATION` stays NOT_OBSERVED with its concealable-negative record, `NATIVE_ROOT_SEPOLICY`
stays INCONCLUSIVE. RootBeer and Ruru retrofits unchanged.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "Google 硬體認證的根憑證", "開機載入器已上鎖", CRL current |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is normal" |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | `duck1023-report.txt` (23:03) | Warning overall: Danger 0, Warning 4, Ready 18, Pending 0 |
| Duck 521 | `duck521-report.txt` (23:16) | Danger 1, Warning 3, Ready 15, Pending 0; every card as T1 |

Duck 1023's only card change from T1 is Zygote heap residue "Inconclusive" → "No target trace
observed". Certificate identifiers in both reports were redacted before the files were kept
(README amendment of 2026-10-20).

Order as registered (1023, then 521, then 1023 restored, sha256 checked after each install). The
operator drove Duck's UI and exported the reports; this session pulled and deleted them.
