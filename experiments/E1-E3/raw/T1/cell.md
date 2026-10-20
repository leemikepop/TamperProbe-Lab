# Cell T1 — Pixel 7, P6 + TrickyStore-OSS with a leaked hardware keybox

Differs from P6 only by TrickyStore-OSS v3.1.0 targeting every app under test with a leaked
hardware keybox. Before the reboot into this cell the operator removed LSPosed and this session
uninstalled the P7 fixture. Read from the device on 2026-10-20.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, ksud, uname, `/proc/version` | as P4 |
| KernelSU features | as P6: **`selinux_hide` on** |
| Boot properties | as P2: green / locked (spoofed by `susfs4ksu`) |
| Modules | **`tricky_store` `v3.1.0 (199-dda5277-release)` (199) enabled**; `hma_oss_zygisk` oss-173, `zygisksu` 864, `susfs4ksu`, `susfs_guard_lkm` (early load) enabled; no LSPosed (`/data/adb/lspd` absent), no fixture |
| Zygisk Next | `inject_state:1`, `enforce_denylist:0`, `modules64:1,hma_oss_zygisk` |
| `susfs4ksu`, HMA-OSS scope | as P6 (HMA re-read for Duck after each reinstall: unchanged) |
| TrickyStore `target.txt` | 32 entries in all; each of the seven apps under test listed once, plain (no `!` or `?` suffix). Other entries not read |
| Keybox | leaked hardware keybox (class only), `keybox.xml` present; contents not read and not recorded |
| `security_patch.txt` | `system=202610`, `boot=2026-10-05`, `vendor=2026-10-05` (equal to the real SPL) |
| `tee_status` | `status=AVAILABLE`, `teeBroken=false` |

Tricky Addon (`TA_utl`), installed by the operator to edit the TrickyStore configuration and fetch
the keybox, was present at the first read. Its boot script rewrites further properties
(`ro.boot.veritymode`, `ro.debuggable`, `ro.secure`, `ro.adb.secure`, `ro.build.type`,
`ro.build.tags`, warranty bits, `sys.oem_unlock_allowed`), which is outside the cell definition. Its
module directory was deleted without running its `uninstall.sh` (that script replaces
`keybox.xml` with an AOSP keybox), its `webroot` symlink in the TrickyStore module was removed, the
keybox was checked unchanged, and the phone was rebooted before any capture. After that reboot:
`sys.oem_unlock_allowed` empty, `ro.boot.veritymode=enforcing`, `ro.debuggable=0`, `ro.secure=1`,
`ro.adb.secure=1`, `ro.build.type=user`, `ro.build.tags=release-keys`, `ro.boot.warranty_bit=0`.

Apps under test: same installed builds and hashes as P0.

## Observations (from `compare_cells.py raw/P6 raw/T1`; 3 repetitions agree)

| Detector | P6 | T1 |
| --- | --- | --- |
| `TEE_ATTESTATION` | OBSERVED MODERATE | NOT_OBSERVED with a concealable-negative record (`attested_boot_state_coherence`) |

`TEE_ATTESTATION` in T1: chain of 4, every certificate valid, trusted root, TrustedEnvironment
security level, no RKP provisioning extension; RootOfTrust `deviceLocked true`,
`verifiedBootState Verified`; `bootConsistency.matches true` (attested boot hash equals the runtime
vbmeta digest); revocation checked, not revoked, not suspended. `DRM_CREDENTIAL_COHERENCE` stays
OBSERVED MODERATE; `NATIVE_ROOT_SEPOLICY` stays INCONCLUSIVE. RootBeer and Ruru retrofits
unchanged. The export records chain length and validity states only, no certificate identifiers.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "Google 硬體認證的根憑證", **"開機載入器已上鎖"**, CRL current; KeyMint 4.0, TEE |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is normal" |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | `duck1023-report.txt` (21:52) | **Warning** overall: Danger 0, Warning 4, Ready 18, Pending 0 |
| Duck 521 | `duck521-report.txt` (22:20) | Danger 1, Warning 3, Ready 15, Pending 0 |

Duck card changes from P6:

- 1023: Bootloader Danger (5 critical signals) → Clear ("Locked and attested verified"); System
  Properties now also listed under Top Findings ("1 property signal(s) need review"); TEE stays
  Warning ("Attestation aligned; local probes need review"); Zygote heap residue → "Inconclusive".
- 521: Bootloader Danger (5) → Warning ("1 DRM consistency signal(s) need review"); SELinux back to
  Clear; TEE Danger ("Attestation aligned; local probes need review").

The Duck reports list the attestation chain; certificate serial numbers, every `2.5.4.5`
(serialNumber) name attribute and intermediate validity periods were replaced with `<redacted>`
before the files were kept (see the README amendment of 2026-10-20).

Order as registered (1023, then 521, then 1023 restored, sha256 checked after each install). The
operator drove Duck's UI and exported the reports; this session pulled and deleted them.
