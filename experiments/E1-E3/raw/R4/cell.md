# Cell R4 — Redmi 13C, R3 + Play Integrity Fix (held out)

Differs from R3 by Play Integrity Fix v4.9-inject-s (the build of T2). Read from the device on
2026-10-21 after the operator installed the module and rebooted (17:26); every capture below ran in
that boot.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, `uname`, SELinux, Magisk settings | as R0 |
| Modules | **`playintegrityfix` `v4.9-inject-s` (490) enabled**; `tricky_store` 199, `hma_oss_zygisk` oss-173, `zygisksu` 864 enabled; `zn_magisk_compat` disabled |
| Zygisk Next | `inject_state:1`, `enforce_denylist:1`, `modules64:2,hma_oss_zygisk,playintegrityfix`, `modules_with_issue:0` |
| Boot properties | **`verifiedbootstate=green`, `flash.locked=1`, `vbmeta.device_state=locked`**; also `ro.secureboot.lockstate=locked`, `ro.boot.veritymode=enforcing`, `sys.oem_unlock_allowed=0` |
| TrickyStore, HMA-OSS scope, DenyList | as R3 (HMA re-read for Duck after each reinstall: unchanged; Duck 1023: 5 processes; 521: 4 + 5 isolated services) |

The boot properties are set by PIF's `service.sh` (`resetprop_if_diff`). Magisk's own Zygisk is off,
so Magisk skips the module (`playintegrityfix: ignore` in `magisk.log`); Zygisk Next's
`magisk_compat` runs its `post-fs-data.sh` and `service.sh` and loads its Zygisk library (logcat,
`zn-daemon64`). On the Pixel the same properties were already spoofed by `susfs4ksu` (P2), so PIF's
conditional rewrites changed nothing there.

PIF configuration in effect: `/data/adb/pif.prop`, left from 2026-10-16 and not rewritten by the
install (sha256 `d10b1cc9e936fcda`); every key equal to T2.

Apps under test: same installed builds and hashes as R0.

## Observations (from `compare_cells.py raw/R3 raw/R4`; 3 repetitions agree)

| Detector | R3 | R4 |
| --- | --- | --- |
| `TEE_ATTESTATION` | OBSERVED MODERATE | **NOT_OBSERVED**, concealable-negative record |
| `DANGEROUS_PROPS` | OBSERVED MODERATE | **NOT_OBSERVED**, no concealable-negative record |
| `KEYSTORE_GRANT_SPLIT` | INCONCLUSIVE | unchanged |
| `DANGEROUS_PACKAGES`, `NATIVE_ROOT_SEPOLICY` | OBSERVED WEAK | unchanged |

Reference score 3 (R3: 7). The concealable-negative records are R3's three plus
`TEE_ATTESTATION.chain-and-root-of-trust.concealable-negative`.

Prediction check: "with properties spoofed to match, the boot-state comparison agrees (C-neg)" — as
predicted. `DANGEROUS_PROPS` turning negative without the record is the same kind of finding as in P2
and R1.

Retrofits: RootBeer and Ruru unchanged from R3 (`summarize_retrofit.py` output identical).

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "Google 硬體認證的根憑證", "開機載入器已上鎖", as R3 |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | **"The Environment is normal"**; Bootloader Unlocked gone |
| Ruru 1.1.1 | `ruru-1.png/.txt` | as R3 |
| Duck 1023 | `duck1023-report.txt` (17:50) | Danger 2, Warning 6, Ready 18, Pending 0 |
| Duck 521 | `duck521-report.txt` (21:22) | Danger 3, Warning 4, Ready 15, Pending 0 |

NRD again did not come to the foreground on the first launch and was captured on a second launch.

Both Duck builds change the same way from R3: Bootloader Danger (3 critical signals) → Warning
("1 boot state signal(s) need review", not named; attested boot hash matches `ro.boot.vbmeta.digest`);
System Properties Danger (3) → Warning (1; in Duck 1023 `persist.sys.usb.config=adb`); Custom ROM
Warning → Info ("reduced coverage"). TEE and Mount stay Danger.

Certificate identifiers in both reports were redacted before the files were kept. Order as
registered (1023, then 521, then 1023 restored, sha256 checked after each install, Duck put back on
the DenyList before each run). The operator drove Duck's UI and exported the reports; this session
pulled and deleted them.
