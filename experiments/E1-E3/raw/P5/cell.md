# Cell P5 — Pixel 7, P4 + HMA-OSS

Differs from P4 only by HMA-OSS oss-173 (Zygisk module and manager app
`org.frknkrc44.hma_oss`), with the same four presets on every app under test. Read from the device
on 2026-10-17 after the reboot.

| Condition | Value |
| --- | --- |
| Build fingerprint, SPL, ksud, uname, `/proc/version` | as P4 |
| KernelSU features | as P0: `selinux_hide` **off** |
| Boot properties | as P2: green / locked (spoofed by `susfs4ksu`) |
| Modules | `hma_oss_zygisk` `oss-173` (7304656) **enabled**; `zygisksu` 864, `susfs4ksu`, `susfs_guard_lkm` (early load) enabled |
| Zygisk Next | `inject_state:1`, `enforce_denylist:0`, `modules64:1,hma_oss_zygisk` |
| `susfs4ksu` | as P3a/P4 (`spoof_uname=2`; rule files unchanged) |

HMA-OSS scope, read from its `config.json` by package name for the apps under test only:

| Package | `applyPresets` | `applyTemplates` | `extraAppList` | `useWhitelist` |
| --- | --- | --- | --- | --- |
| `io.leemikepop.tamperprobe.lab` | `root_apps`, `shizuku_dhizuku`, `sus_apps`, `xposed` | none | 0 | false |
| `…lab.retrofit.rootbeer` | same | none | 0 | false |
| `…lab.retrofit.ruru` | same | none | 0 | false |
| `com.eltavine.duckdetector` | same (re-read after each reinstall: unchanged) | none | 0 | false |
| `com.reveny.nativecheck` | same | none | 0 | false |
| `io.github.vvb2060.keyattestation` | same | none | 0 | false |
| `com.byxiaorun.detector` | same | none | 0 | false |

Every entry also has `excludeSystemApps true` and every other boolean false. Apps under test: same
installed builds and hashes as P0.

## Observations (from `compare_cells.py raw/P4 raw/P5`; 3 repetitions agree)

| Detector | P4 | P5 |
| --- | --- | --- |
| `DANGEROUS_PACKAGES` | OBSERVED WEAK | NOT_OBSERVED with a concealable-negative record (`visiblePackageCount` 200) |

RootBeer and Ruru retrofits unchanged: their package checks had no positive to hide in any
earlier cell (concealable negatives since P0).

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "開機載入器已解鎖" |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is normal" |
| Ruru 1.1.1 | `ruru-1.png/.txt` | every item "未發現" |
| Duck 1023 | `duck1023-report.txt` (22:32) | Danger 2, Warning 5, Ready 18, Pending 0 |
| Duck 521 | `duck521-report.txt` (22:43) | Danger 3, Warning 3, Ready 15, Pending 0 |

Duck card changes from P4: both builds' Dangerous Apps 2 → 1 risky package; the one left is MT
Manager (`bin.mt.termex`), found through `/sdcard/MT2` on shared storage, not through the package
manager. 1023 Root Managers Warning → Clear ("No root manager apps"). 1023 Zygote heap residue
"No target trace observed" → "Inconclusive" (this card has alternated between the two since P0).
Both builds obtained key attestation.

Order as registered (1023, then 521, then 1023 restored, sha256 checked after each install). The
operator drove Duck's UI and exported the reports; this session pulled and deleted them.
