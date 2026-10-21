# Cell R0 — Redmi 13C, Magisk only (held out)

Read from the device on 2026-10-21 after the operator removed every module, this session deleted the
leftover `.TA_utl` directory and the operator rebooted (README amendment of 2026-10-21).

| Condition | Value |
| --- | --- |
| Build fingerprint | `Redmi/gale_global/gale:13/TP1A.220624.014/V14.0.11.0.TGPMIXM:user/release-keys` |
| Security patch | 2024-09-01 (slot `_b`) |
| `uname -a` | `Linux localhost 4.19.191-gf41c3bed52e9 #1 SMP PREEMPT Tue Sep 3 06:21:48 UTC 2024 aarch64` |
| Magisk | 30.6 (30600); settings `zygisk=0`, `denylist=0` ("Denylist is not enforced"); Magisk app not hidden (`com.topjohnwu.magisk`) |
| Boot properties | `verifiedbootstate=orange`, `flash.locked=0`, `vbmeta.device_state=unlocked` (kernel command line agrees) |
| SELinux | Enforcing |
| Modules | none; `modules_update` absent; no `post-fs-data.d`, `service.d` or `boot-completed.d` scripts; `magisk.log` runs no module script |
| Left on disk, not loaded | `/data/adb/tricky_store/`, `/data/adb/pif.prop`, the HMA-OSS data directory under `/data/misc/` |

Apps under test, installed sha256 (first 16) as P0: Lab `c8eb9b3955ba27a6` (`.test`
`12df311fa6887171`), RootBeer host `59303db8b5f7f2e9` (`9dc1ac578f985e01`), Ruru host
`b7eaf05f07cfa3ec` (`b4a85dc6f92d0173`), Duck 1023 `3a433cc90fc6f2ee`, NRD 7.7.0 `1033d24102af2632`,
Key Attestation 2.0.2 `f6acc0d3e25a1df8`, Ruru 1.1.1 `8a2856cd13353c18`. Every export records
`gitCommit 8c047f1693b5`, `gitDirty false`. Before installing them, the product repository's apps,
the Lab's development `…lab.lib.test`, the HMA-OSS app and two detector apps outside the
experiment were uninstalled (README amendment of 2026-10-21).

## Observations (from `compare_cells.py raw/P0 raw/R0`; 3 repetitions agree)

| Detector | R0 | Note |
| --- | --- | --- |
| `SU_BINARY` | OBSERVED STRONG | |
| `MOUNT_INTEGRITY` | OBSERVED STRONG | |
| `DANGEROUS_PROPS` | OBSERVED MODERATE | |
| `DANGEROUS_PACKAGES` | OBSERVED WEAK | |
| `NATIVE_ROOT_SEPOLICY` | OBSERVED WEAK | |
| `KERNEL_CHECK` | NOT_OBSERVED | stock kernel |
| `TEE_ATTESTATION` | INCONCLUSIVE | no certificate chain (length 0) |
| `TEE_OVERSIZED_CHALLENGE` | INCONCLUSIVE | `provider_error`, code 10 at `generate` |
| `KEYSTORE_GRANT_SPLIT` | INCONCLUSIVE | `available=false` |

Reference score 15 (P0: 7). The three keystore results share one cause: the phone cannot generate an
attested key. Key Attestation 2.0.2 shows the same failure (`Failed to generate key pair`,
`Error::Km(ErrorCode(-1000))`, public code 10), and Duck's TEE card reports chain length 0.

Prediction check: Magisk path and mount evidence observed, `DANGEROUS_PROPS` observed,
`KERNEL_CHECK` not observed, RootBeer and Ruru each with positives — as predicted.
`TEE_ATTESTATION` was predicted OBSERVED WEAK and is INCONCLUSIVE.

Retrofits (`summarize_retrofit.py`, same in all three runs):

- RootBeer: 5 checks positive (root management apps, su binary, which su, native su, Magisk
  binary); 4 clean checks, all concealable.
- Ruru: 5 checks positive (PM conventional, sundry and intent queries, libc and syscall file
  checks); 5 clean checks = 1 `no_answer` (PM command), 3 concealable, 1 mixed.

## Black-box runs

| App | Record | Displayed verdict |
| --- | --- | --- |
| Key Attestation 2.0.2 | `keyattestation-1.png/.txt` | "無法認證": `Failed to generate key pair`, Keymaster error -1000 |
| Native Root Detector 7.7.0 | `nrd-1.png/.txt` | "The Environment is abnormal"; Suspicious Mount, Bootloader Unlocked ×2 |
| Ruru 1.1.1 | `ruru-1.png/.txt` | 發現: PM 常規, 混合, 主介面查詢, Libc, Syscall 檔案檢查; 被拒絕: PM 命令; 未發現: 環境檢測, Xposed 模組 |
| Duck 1023 | `duck1023-report.txt` (11:15) | Danger 5, Warning 7, Ready 18, Pending 0 |
| Duck 521 | `duck521-report.txt` (11:23) | Danger 6, Warning 3, Ready 15, Pending 0 |

Duck 1023 Danger: Bootloader (6 signals), Mount (1), SU binary, System Properties (3), TEE (chain
length 0, local chain failed). Warning: ADB, Custom ROM, Dangerous Apps (Magisk app, KSU WebUI,
Termux, MT Manager via `/sdcard/MT2`), LSPosed (dirty SELinux policy), Root Managers (Magisk),
SELinux, Zygisk (one heuristic probe).

Duck 521 Danger: Bootloader, Mount, SELinux (`app_zygote` attr-write anomaly), SU, System
Properties, TEE. Warning: Custom ROM, Dangerous Apps (4), LSPosed.

Certificate identifiers in both reports were redacted before the files were kept. Order as
registered (1023, then 521, then 1023 restored, sha256 checked after each install). The operator
drove Duck's UI and exported the reports; this session pulled and deleted them.

Note (2026-10-21, during R1): the NRD row above omits one line of `nrd-1.txt`; NRD also showed
"Detected Risky App (3)".
