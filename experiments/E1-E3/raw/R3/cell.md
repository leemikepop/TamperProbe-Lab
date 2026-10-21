# Cell R3 — Redmi 13C, R2 + TrickyStore-OSS with a leaked hardware keybox (held out)

Differs from R2 by TrickyStore-OSS v3.1.0 targeting every app under test with a leaked hardware
keybox (the keybox of T1). Read from the device on 2026-10-21 after the operator installed the module
and the keybox, rebooted, and this session completed `target.txt` and `security_patch.txt`.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, `uname`, boot properties, SELinux, Magisk settings | as R0 (`orange` / `0` / `unlocked`, Enforcing) |
| Modules | **`tricky_store` `v3.1.0 (199-dda5277-release)` (199) enabled**; `hma_oss_zygisk` oss-173, `zygisksu` 864 enabled; `zn_magisk_compat` disabled |
| Zygisk Next | as R2: `inject_state:1`, `enforce_denylist:1`, `modules64:1,hma_oss_zygisk`, `modules_with_issue:0` |
| HMA-OSS scope, DenyList | as R2 (HMA re-read for Duck after each reinstall: unchanged; Duck 1023: 5 processes; 521: 4 + 5 isolated services) |
| TrickyStore `target.txt` | 45 entries in all; each of the seven apps under test listed once, plain. Other entries not read |
| Keybox | leaked hardware keybox (class only), `keybox.xml` present; contents not read and not recorded |
| `security_patch.txt` | `system=prop`, `boot=2024-09-01`, `vendor=2024-09-01` (equal to the real SPL) |
| `tee_status` | `status=FAILED`, `category=service_error`, `serviceErrorCode=-1000`, `teeBroken=true` (the phone's own TEE cannot generate attested keys, R0) |

Configuration completed by this session before the captures (15:53), without a reboot afterwards:

- `target.txt` lacked three apps under test (both retrofit hosts and Ruru 1.1.1); they were appended
  plain.
- `security_patch.txt` held `boot` and `vendor` values from another device (2026-10-05); they were set
  to the Redmi's patch level.
- The operator had copied the keybox to `/sdcard/Download`; that copy was identical to the installed
  `keybox.xml` and was deleted.

TrickyStore reads both files at run time; Key Attestation obtained a Google-rooted chain right after
the change. `/data/adb/tricky_store/` also holds empty Tricky Addon flag files dated 2026-07-26
(`target_from_denylist`, `security_patch_auto_config`, `pif_auto_security_patch`) and a
`keybox.xml.bak`; no Tricky Addon module is installed (README amendment of 2026-10-21).

Apps under test: same installed builds and hashes as R0.

## Observations (from `compare_cells.py raw/R2 raw/R3`; 3 repetitions agree)

| Detector | R2 | R3 |
| --- | --- | --- |
| `TEE_ATTESTATION` | INCONCLUSIVE | **OBSERVED MODERATE** |
| `TEE_OVERSIZED_CHALLENGE` | INCONCLUSIVE | **NOT_OBSERVED** |
| `KEYSTORE_GRANT_SPLIT` | INCONCLUSIVE | unchanged (needs API 36; the Redmi runs Android 13) |
| `DANGEROUS_PROPS`, `DANGEROUS_PACKAGES`, `NATIVE_ROOT_SEPOLICY` | | unchanged |

`TEE_ATTESTATION` reports `attested_boot_state_contradicts_properties`: a chain of length 4 to a
trusted Google root, revocation checked and not revoked, security level TrustedEnvironment,
RootOfTrust Verified with `deviceLocked=true`, while the three boot properties read `orange`, `0`
and `unlocked`. Reference score 7 in both cells. The concealable-negative records are the same three
as in R0–R2.

Prediction check: "a locked, verified attestation; with the boot properties not spoofed,
`attested_boot_state_contradicts_properties` fires (MODERATE)" — as predicted.

Retrofits: RootBeer and Ruru unchanged from R2.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "Google 硬體認證的根憑證", "開機載入器已上鎖" |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is abnormal"; Bootloader Unlocked ×2 |
| Ruru 1.1.1 | `ruru-1.png/.txt` | as R2 |
| Duck 1023 | `duck1023-report.txt` (17:05) | Danger 4, Warning 5, Ready 18, Pending 0 |
| Duck 521 | `duck521-report.txt` (17:16) | Danger 5, Warning 3, Ready 15, Pending 0 |

NRD again did not come to the foreground on the first launch and was captured on a second launch.

Both Duck builds: the only card change from R2 is Bootloader 6 → 3 critical signals; the
attestation side now reports Verified, Locked, Google root, while the property signals remain. TEE
stays Danger with a new basis: R2 had chain length 0; R3 has chain length 4 to a Google root,
locally verified, boot hash matched, verdict "Tampered" with one policy-hard indicator that the
report does not name. Duck 1023 rejected the 256, 512 and 4096 B challenges.

Certificate identifiers in both reports were redacted before the files were kept. Order as
registered (1023, then 521, then 1023 restored, sha256 checked after each install, Duck put back on
the DenyList before each run). The operator drove Duck's UI and exported the reports; this session
pulled and deleted them.
