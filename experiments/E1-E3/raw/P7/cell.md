# Cell P7 — Pixel 7, P6 + LSPosed with the xposed-control positive control (E7)

Differs from P6 only by LSPosed v2.2.1 and the Lab's `xposed-control` fixture, enabled and scoped to
the probe app alone. Read from the device on 2026-10-17 after the operator installed LSPosed and
rebooted, this session installed the fixture, and the operator set its scope.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, ksud, uname, `/proc/version` | as P4 |
| KernelSU features | as P6: **`selinux_hide` on** |
| Boot properties | as P2: green / locked (spoofed by `susfs4ksu`) |
| Modules | **`zygisk_lsposed` `v2.2.1 (7912)` (7912) enabled**; `hma_oss_zygisk` oss-173, `zygisksu` 864, `susfs4ksu`, `susfs_guard_lkm` (early load) enabled |
| Zygisk Next | `inject_state:1`, `enforce_denylist:0`, `modules64:2,hma_oss_zygisk,zygisk_lsposed` |
| LSPosed (`lspctl status`) | 2.2.1 (7912), API 102, developer mode off, safe mode off, system server connected, 1 module installed |
| Fixture | `io.leemikepop.tamperprobe.lab.fixture.xposedcontrol`, built from tag `eval-2026-10-v1`, installed sha256 `19819f82927e614f` |
| LSPosed scope (`modules_config.db`, one module present) | `xposedcontrol` → `io.leemikepop.tamperprobe.lab` (user 0) only |
| `susfs4ksu`, HMA-OSS scope | as P6 (HMA re-read for Duck after each reinstall: unchanged) |

Validity check: before each probe-app capture logcat was cleared, and after it the `TPXposedControl`
tag showed `module_loaded` and `hook_installed` once each, in all three repetitions. A launch of the
app before the captures also showed `hook_invoked` for `MainActivity.onResume`. Only the probe app is
in scope, so the retrofit hosts and black-box apps run without the module, as registered.

Apps under test: same installed builds and hashes as P0.

## Observations (from `compare_cells.py raw/P6 raw/P7`; 3 repetitions agree)

| Detector | P6 | P7 |
| --- | --- | --- |
| `LSPOSED_MAPS` | NOT_OBSERVED | OBSERVED STRONG |
| `ELF_TEXT_INTEGRITY` | NOT_OBSERVED | OBSERVED MODERATE |
| `MEMORY_LINKER_VISIBILITY` | NOT_OBSERVED | OBSERVED MODERATE |
| `RUNTIME_INSTRUMENTATION` | NOT_OBSERVED | OBSERVED MODERATE |
| `ZYGISK_SMAPS` | NOT_OBSERVED | OBSERVED MODERATE |
| `MEMORY_MAPS_ANOMALY` | NOT_OBSERVED | OBSERVED WEAK |

`NATIVE_ROOT_SEPOLICY` stays INCONCLUSIVE. RootBeer and Ruru retrofits unchanged.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "開機載入器已解鎖" |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is normal" |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | `duck1023-report.txt` (23:54) | Danger 1, Warning 4, Ready 18, Pending 0; every card as P6 |
| Duck 521 | `duck521-report.txt` (23:56) | Danger 2, Warning 2, Ready 15, Pending 0 |

Duck 521's only card change from P6 is SELinux Warning ("Enforcing with audit exposure") → Clear
("Enforcing"); no other build or app changed. Both builds obtained key attestation.

Order as registered (1023, then 521, then 1023 restored, sha256 checked after each install). The
operator drove Duck's UI and exported the reports; this session pulled and deleted them.
