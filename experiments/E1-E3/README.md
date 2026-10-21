# E1–E3: Silence attribution on concealment ladders, with retrofits and black-box baselines

> Status: **Registered** by the commit that adds this file. No cell is captured before that commit;
> after it, this file changes only by appended `## Amendment <date>` sections.

## 1. Question

On fixed root and concealment configurations, built up one component at a time, what does each
tool report, and when a tool reports a clean result, what does that result rest on: a check that
found nothing, a check that could not look, or an absence a hiding tool can manufacture?

- **E1** answers it for TamperProbe-Lab (every detector).
- **E2** answers it for RootBeer through its contract retrofit; **E3′** for Ruru through its
  retrofit.
- **E3** records what black-box tools display on the same cells.

It cannot answer how often any tool is right on the device population. Two phones in fixed
configurations give no detection or false-positive rate, and nothing here is reported as one.

## 2. Builds under test

| Tool | Build | Identity |
| --- | --- | --- |
| TamperProbe-Lab probe app | tag `eval-2026-10-v1` (`8c047f1`), debug, clean tree | `io.leemikepop.tamperprobe.lab` |
| RootBeer retrofit host (E2) | same tag | `io.leemikepop.tamperprobe.lab.retrofit.rootbeer`, RootBeer `de7bc7b` |
| Ruru retrofit host (E3′) | same tag | `io.leemikepop.tamperprobe.lab.retrofit.ruru`, Ruru `30694c2` |
| Duck-Detector (E3) | versionCode 521, `2026.08.28-c1c8e0c17577`, sha256 `8cca9380cc623f22…` | `com.eltavine.duckdetector` |
| Duck-Detector (E3) | versionCode 1023, `2026.10.14-9fcc940074ed`, sha256 `3a433cc90fc6f2ee…` | same package |
| Native Root Detector (E3) | 7.7.0, sha256 `1033d24102af2632…` | `com.reveny.nativecheck` |
| Key Attestation (E3) | 2.0.2 (247), sha256 `f6acc0d3e25a1df8…` | `io.github.vvb2060.keyattestation` |
| Ruru, unmodified (E3) | 1.1.1, sha256 `8a2856cd13353c18…` | `com.byxiaorun.detector` |

Full hashes are in `cells/apks.sha256` (written at registration from the archived APKs). Every
detector runs; there is no selection. The two Duck builds share a package and a signer; a switch
from 1023 to 521 is a downgrade, so each switch is an uninstall followed by an install.

Black-box apps are never updated during the experiment; automatic updates stay off on both phones.

Root and concealment components, installed only from the archived files (full hashes in
`cells/modules.sha256`):

| Component | `module.prop` id, version (versionCode) | Archive sha256 | Source |
| --- | --- | --- | --- |
| Magisk (Redmi) | app 30.6 (30600) | `f1ffc3c9a5614c25…` | Magisk v30.6 release APK |
| SUSFS LKM | `susfs_guard_lkm`, `main-899976e` (1792074277) | `3b1b77f7224a60d1…` | inforcqb release v2.3.0-r18.3, commit `899976e`; loads `susfs_guard_lkm-android14-6.1.ko` |
| SUSFS userspace | `susfs4ksu`, `v1.5.2-R28` (105002028) | `abcd6bf456ea8189…` | sidex15 release v1.5.2+_R28, commit `d30974d` |
| Zygisk Next | `zygisksu`, `1.5.2 (864-a4a72ce-release)` (864) | `ce50b13fecb9e445…` | release 1.5.2; matches the publisher's stated sha256 |
| HMA-OSS | `hma_oss_zygisk`, `oss-173` (7304656) | `be364502b3d34510…` | release oss-173 (module and app) |
| TrickyStore-OSS | `tricky_store`, `v3.1.0 (199-dda5277-release)` (199) | `ef356f81c57b0106…` | beakthoven/TrickyStoreOSS CI build, Actions run 38476533465 (not a tagged release) |
| Play Integrity Fix | `playintegrityfix`, `v4.9-inject-s` (490) | `bc7a9d92638a6bd9…` | KOW channel release v4.9-inject-s |
| LSPosed | `zygisk_lsposed`, `v2.2.1 (7912)` (7912) | `ed37de2d2097aa6b…` | lsposed.zip release v2.2.1 |

Both phones run the same module builds; a cell whose installed `version`/`versionCode` differs from
this table stops at §7 step 3.

## 3. Devices and configurations

| Device (model only) | OS / patch | Base | Role |
| --- | --- | --- | --- |
| Pixel 7 | Android 17, `CP3A.261005.002.A1`, SPL 2026-10-05 | blu_spark r283 `gs`, KernelSU 3.3.1 (ksud `3.3.1-110`), engstk manager | development device |
| Redmi 13C | Android 13, `V14.0.11.0.TGPMIXM`, SPL 2026-09-05 | Magisk 30.6 (Magisk Zygisk and DenyList off) | **held out** (see below) |

No clean device is in this experiment; clean devices are deferred and named as a limitation.

**Held out.** No detector change in the Lab was made from a Redmi result. During development the
Redmi ran the Lab once, on 2026-10-16, to check that commit `7847dd2` builds and passes its
instrumented tests (20/20); that run was not inspected for detector behaviour and its module
configuration was not recorded. The Redmi cells are therefore held out from tuning, not untouched.

**Unrelated module.** The Redmi carried a Pokémon GO module (PGS 1.0.6); it and its leftover
`pgs.zip` were removed before registration and are not reinstalled during the experiment. The Pixel
does not carry it.

Concealment is configured identically for every app under test on a cell: the probe app, both
retrofit hosts and every black-box app. Test packages (`*.test`) need no concealment.

## 4. Cells

Pixel ladder (each cell adds one component to the cell it differs from):

| Cell | Differs from | The one factor changed |
| --- | --- | --- |
| P0 | — | KernelSU only; no module enabled (`susfs4ksu` installed but disabled) |
| P1 | P0 | SUSFS LKM v2.3.0-r18.3 loaded (early load); `susfs4ksu` stays disabled, so no SUSFS rules |
| P2 | P1 | `susfs4ksu` R28 enabled with the operator's existing path and mount hiding rules in `/data/adb/susfs4ksu/`; no uname spoof. The cell record lists the rule kinds and their counts, not the hidden paths |
| P3a | P2 | uname spoof applied at post-fs-data (before Zygote) |
| P3b | P2 | uname spoof applied after Zygote (a timing branch of P3a; not on the main ladder) |
| P4 | P3a | Zygisk Next 1.5.2 |
| P5 | P4 | HMA-OSS with the presets `root_apps`, `shizuku_dhizuku`, `sus_apps`, `xposed` on every app under test |
| P6 | P5 | KernelSU "Hide SELinux modification" on |
| P7 | P6 | LSPosed v2.2.1 with `xposed-control` scoped to the probe app (E7 positive control) |
| T1 | P6 | TrickyStore-OSS v3.1.0 targeting every app under test, with a leaked hardware keybox (class only; its contents and certificate serials are never recorded; its revocation status is taken from `TEE_ATTESTATION` and Key Attestation in each cell) |
| T2 | T1 | Play Integrity Fix v4.9-inject-s (same build as R4) |

Redmi ladder, held out. It keeps the thesis ladder's rungs with the modules the phone runs now;
R1 uses Zygisk Next instead of Magisk's own Zygisk, as the Pixel does, so it is not the thesis R1:

| Cell | Differs from | The one factor changed |
| --- | --- | --- |
| R0 | — | Magisk 30.6 only; every module disabled, Magisk Zygisk and DenyList off |
| R1 | R0 | Zygisk Next with its DenyList enforcement on for every app under test |
| R2 | R1 | HMA-OSS with the same presets as P5 |
| R3 | R2 | TrickyStore-OSS targeting every app under test, leaked hardware keybox |
| R4 | R3 | Play Integrity Fix |

Module builds on both ladders are those in §2.

Captures per cell: the probe app 3 times, each retrofit host 3 times, each black-box app once per
build (Duck twice: 521 and 1023).

## 5. Predictions

Written before any capture. "C-neg" means NOT_OBSERVED published with a concealable-negative
record; a prediction about a C-neg is a test of that unit's concealment declaration.

| Cell | Prediction |
| --- | --- |
| P0 | Lab: `KERNEL_CHECK` OBSERVED (custom kernel name), `DANGEROUS_PROPS` OBSERVED (orange boot state), `TEE_ATTESTATION` OBSERVED WEAK (unlocked), `DANGEROUS_PACKAGES` OBSERVED if a listed app is visible. RootBeer `isRooted()` false; its clean checks rest on concealable or no-answer units, none on trusted ones. |
| P1 | No change from P0 in any tool: loading SUSFS without rules hides nothing. |
| P2 | Path-based checks that were positive in P1 turn to C-neg in Lab, RootBeer and Ruru; no unit declared non-concealable turns negative. |
| P3a | `KERNEL_CHECK` identity coherence reports agreement (C-neg); the banner-based finding disappears. Duck Kernel Check clear. |
| P3b | `KERNEL_CHECK` identity coherence OBSERVED MODERATE (`os.version` differs from `uname()`); Duck Kernel Check flags the same mismatch. |
| P4 | No prediction of direction; every change from P3a is recorded and attributed to Zygisk Next. |
| P5 | `DANGEROUS_PACKAGES` and both retrofits' package checks become NOT_OBSERVED with C-neg; Ruru unmodified shows "not found" for its package checks. |
| P6 | `NATIVE_ROOT_SEPOLICY` and `LSPOSED_SEPOLICY` negatives rest on absent target types (C-neg); Duck 521 reports SELinux clear. |
| P7 | The `xposed-control` hook is visible to at least one runtime-integrity detector, or the miss is reported as an E7 finding. |
| T1 | `TEE_ATTESTATION` reports a locked, verified attestation; if the boot properties are not spoofed, `attested_boot_state_contradicts_properties` fires (MODERATE). |
| T2 | With properties spoofed to match, the boot-state comparison agrees (C-neg); `DRM_CREDENTIAL_COHERENCE` stays OBSERVED. |

Redmi predictions are carried over from the Pixel cell with the same mechanism; the Redmi was not
scanned to write them.

| Cell | Prediction |
| --- | --- |
| R0 | Lab: Magisk path and mount evidence OBSERVED (nothing hides it); `TEE_ATTESTATION` OBSERVED WEAK (unlocked); `DANGEROUS_PROPS` OBSERVED if no module is left spoofing the boot properties; `KERNEL_CHECK` NOT_OBSERVED (stock kernel name). At least one RootBeer and one Ruru check positive. |
| R1 | Path and mount checks that were positive in R0 turn to C-neg for the apps under test; no unit declared non-concealable turns negative. |
| R2 | As P5: package checks in Lab and both retrofits become NOT_OBSERVED with C-neg; Ruru unmodified shows "not found" for its package checks. |
| R3 | As T1: `TEE_ATTESTATION` reports a locked, verified attestation; if the boot properties are not spoofed, `attested_boot_state_contradicts_properties` fires (MODERATE). |
| R4 | As T2: with properties spoofed to match, the boot-state comparison agrees (C-neg). |

## 6. Decision rules

- An outcome or strength change between a cell and the cell it differs from is attributed to the
  one factor changed. P3b is compared with P3a only for the timing question, and T-cells with P6.
- A change is counted only if all three repetitions of the cell agree; otherwise the detector is
  reported as unstable in that cell, with no attribution.
- **Concealment declarations.** A unit declared concealable is confirmed in a cell when the
  mechanism it names is switched on and the unit's earlier positive becomes a C-neg. A unit declared
  non-concealable is falsified if switching a mechanism on turns its positive into a negative.
  Both outcomes are reported per unit.
- **Retrofit measurement.** For each cell, `summarize_retrofit.py` classifies every upstream-clean
  check as `no_answer`, `concealable`, `trusted` or `mixed`; the table reports the counts per cell.
- Black-box tools are reported as displayed, with the build. No black-box result is reinterpreted.
- Play Integrity, if checked, is a dated server verdict, not ground truth.
- Held-out cells (Redmi) are reported in their own table and are not pooled with Pixel cells.

## 7. Procedure

For each cell:

1. The operator changes the one factor and reboots. Nothing else on the phone changes.
2. Read the conditions from the device into `raw/<cell>/cell.md` (`ADB_SERIAL` held in an
   environment variable only): build fingerprint and SPL, `uname -a`, `/proc/version`, ksud version,
   every module's id, version and enabled state, SUSFS presence and the rule set in effect, the
   KernelSU Hide SELinux setting, and for each app under test only: its TrickyStore target entry and
   its HMA preset/template (grep by package name; never read or record other apps' settings).
3. **Stop** if a condition differs from the cell definition, if any app under test has different
   concealment from the others, or if an installed build's version or hash differs from §2.
4. Capture the probe app and both retrofit hosts three times each with the instrumented export
   tests (`leaveApksInstalledAfterRun=true`), pull the JSON into `raw/<cell>/`, and run
   `compare_cells.py --provenance raw/<cell>`; **stop** on a non-zero exit.
5. Run each black-box app and record its verdict screens as screenshots in `raw/<cell>/blackbox/`;
   for Duck, capture 1023, then uninstall and install 521 and capture again, then restore 1023,
   and re-read both apps' concealment settings after each reinstall.
6. Run `summarize_retrofit.py` and `compare_cells.py` over the cell and paste their output into
   the results section.

Screenshots must not show notifications or other apps; a screenshot that does is deleted and
retaken.

## 8. Threats to validity

- Two phones, one per root family; no clean device; no rates.
- The Pixel configurations were used during detector development (the ladder components were
  installed and scanned before the tag). Only the Redmi ladder is held out.
- Module and app versions change outside our control; each cell records them, and cells captured
  on different module versions are not pooled.
- Black-box tools may behave differently after reinstall (Duck downgrade); the reinstall is part
  of the procedure and logged.
- Concealment declarations are threat-model claims; a cell confirms or falsifies only the
  mechanisms switched on in it.

---

<!-- Below this line: append only. -->

## Amendment 2026-10-17

Made during P0, before any other cell.

- **Duck records.** For each Duck build, the record is Duck's own full report, exported with its
  "Export Report" action into `Download/`, pulled into `raw/<cell>/blackbox/duck<versionCode>-report.txt`
  and then deleted from the device, plus a screenshot of the first result screen. Scrolling
  screenshots of every card are no longer taken. Duck's update prompt is dismissed and never
  accepted; the user agreement shown after each reinstall is accepted.
- **Other apps on the Pixel.** The product repository's apps (`io.leemikepop.tamperprobe` and its
  test and fixture packages) are not installed on the Pixel for the rest of the experiment. One of
  them is an Xposed module that Ruru 1.1.1 reported in the first P0 capture, which is kept in
  `raw/P0-superseded/` and not used.

## Amendment 2026-10-20

Made during T1.

- **Certificate identifiers in Duck reports.** Duck 1023's report (and Duck 521's in T1) lists the
  key-attestation chain with certificate serial numbers and subject/issuer serialNumber
  (`2.5.4.5`) attributes. On the P cells these identify the Pixel's own RKP certificates; in T1
  they identify the leaked keybox, which this experiment records by class only. In every Duck
  report kept, certificate serial numbers, every `2.5.4.5` attribute value and the validity periods
  of intermediate certificates are replaced with `<redacted>`; nothing else in the file changes.
  The P0–P7 reports were redacted after capture; from T1 on, reports are redacted before they are
  kept. The Lab's own exports record chain length and validity states only and need no redaction.
- **Tricky Addon.** Tricky Addon (`TA_utl`) is a common companion of TrickyStore that also
  rewrites boot and build properties. It is not part of any cell: T1 and R3 measure TrickyStore
  alone, which is narrower than the usual TrickyStore installation. This is reported as a threat to
  validity.

## Amendment 2026-10-21

Made before R0.

- **Leftover Tricky Addon on the Redmi.** The Redmi's module list was empty, but a hidden
  `/data/adb/modules/.TA_utl` directory left by Tricky Addon was still run by Magisk at boot and set
  `ro.boot.verifiedbootstate=green`, `flash.locked=1` and `vbmeta.device_state=locked` (the kernel
  command line says `orange` and `unlocked`). With the operator's agreement the directory was deleted
  without running its `uninstall.sh`, which would replace the keybox; the keybox was checked
  unchanged and the phone was rebooted before R0.
- **Other apps on the Redmi.** As on the Pixel, the product repository's apps
  (`io.leemikepop.tamperprobe`, `.test`, `.lib.test`, `.fixture.xposedcontrol`,
  `.fixture.storageowner`) and the Lab's development `…lab.lib.test` are uninstalled for the whole
  experiment. Two detector apps outside this experiment (RootBeer sample 0.9 and
  `com.chunqiunativecheck` 2.8.2) are uninstalled too. The HMA-OSS app is uninstalled before R0 and
  installed again at R2, so that R0 and R1 carry no concealment app.
- **Redmi security patch.** The device table above gives the Redmi's SPL as 2026-09-05; the phone
  reports `ro.build.version.security_patch=2024-09-01` (build `V14.0.11.0.TGPMIXM`). The table entry
  is wrong; the build is the one listed.
- **DenyList after a Duck reinstall (Redmi; added during R1).** Magisk removes a package's DenyList entries when the
  package is uninstalled, so swapping Duck builds also removes Duck from the DenyList. From R1 on,
  after every Duck install on the Redmi the operator puts all of Duck's processes on the DenyList
  again and the entry count is checked before Duck runs. R1's first Duck 521 run, made before this
  rule, is kept as `duck521-superseded-report.txt` and not used.
- **MagiskKiller on the Redmi (added during R2).** MagiskKiller 1.3 (`top.canyie.magiskkiller`), a
  detector app installed on the Redmi since 2025-10-27, was missed by the pre-R0 cleanup. It is in
  the Lab's dangerous-package list and none of the HMA presets hides it, so `DANGEROUS_PACKAGES`
  stays OBSERVED from R2 on. The operator chose to keep it rather than uninstall it and capture R0–R2
  again: it is present in every Redmi cell, so the Redmi cells stay comparable with each other. It is
  reported as a difference from the Pixel, which does not carry it.
