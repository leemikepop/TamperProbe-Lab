# E4: Clean-device baseline

> Status: **Registered** by the commit that adds this file, on 2026-11-23. No cell is captured
> before that commit; after it, this file changes only by appended `## Amendment <date>` sections.

## 1. Question

On a stock, bootloader-locked, never-rooted phone with no concealment installed, what does each
tool from E1–E3 report, and does any of them report an indicator that the phone cannot carry?
Second, what in the Lab's report from this phone differs from its reports from the concealed cells
of E1, and what does not?

It cannot answer how often any tool raises a false alarm. One phone in one configuration gives no
false-positive rate, and nothing here is reported as one. An OBSERVED result here is a false alarm
on this configuration, and is reported as that.

## 2. Builds under test

Identical to E1–E3 §2: every build, archive and hash listed there, with no change.

| Tool | Build | Identity |
| --- | --- | --- |
| TamperProbe-Lab probe app | tag `eval-2026-10-v1` (`8c047f1`), debug, clean tree (worktree `TPL-eval`) | `io.leemikepop.tamperprobe.lab`, sha256 `c8eb9b3955ba27a6` (`.test` `12df311fa6887171`) |
| RootBeer retrofit host (E2) | same tag | `…lab.retrofit.rootbeer`, `59303db8b5f7f2e9` (`.test` `9dc1ac578f985e01`) |
| Ruru retrofit host (E3′) | same tag | `…lab.retrofit.ruru`, `b7eaf05f07cfa3ec` (`.test` `b4a85dc6f92d0173`) |
| Duck-Detector 1023 and 521, Native Root Detector 7.7.0, Key Attestation 2.0.2 (the `VisionR1` fork, E1–E3 amendment of 2026-10-22), Ruru 1.1.1 | archived APKs | full hashes in `../E1-E3/cells/apks.sha256` |

Every detector runs; there is no selection. No root or concealment component is installed.

## 3. Device and configuration

| Device (model only) | OS / patch | Base | Role |
| --- | --- | --- | --- |
| Xiaomi 12 (`cupid`, 2201123G) | Android 15 (API 35), HyperOS `OS3.0.3.0.VLCTWXM`, SPL 2026-05-01 | stock; `ro.build.type=user`, release-keys; `verifiedbootstate=green`, `flash.locked=1`, `vbmeta.device_state=locked`; `sys.oem_unlock_allowed=0`; SELinux Enforcing; no `su` | clean device |

**Not held out.** This phone was the clean control of the thesis evaluation and was used during
Lab development. Its own detector docs cite it: the `MOUNT_INTEGRITY` mount-ID gap rule was
reduced to telemetry on 2026-09-18 after it fired on this phone, and the `NATIVE_ROOT_SEPOLICY`
and `LSPOSED_SEPOLICY` docs describe its user-build result. Before registration it carried
development builds of both retrofit hosts (installed 2026-10-16), the product repository's app and
test package, and Key Attestation 2.0.2 (sha256 matches the archive). A clean result here is
therefore partly a result the detectors were tuned towards; it is reported as such.

**Developer settings.** USB debugging is on, because every capture runs over adb, and with it
developer options. This is the one setting in which the phone differs from an ordinary user's
phone; a tool that reports it is reporting a real setting, not a root indicator.

## 4. Cells

| Cell | Differs from | The one factor changed |
| --- | --- | --- |
| X0 | — (no ladder) | Stock Xiaomi 12, nothing installed beyond the apps under test |

Captures: the probe app 3 times, each retrofit host 3 times, each black-box app once per build
(Duck twice: 1023, then 521).

Comparisons with E1 cells (P0, P6, T2, R0, R4) change the device, the OS, the vendor and the root
state at once: **not a single factor; no attribution**. They are printed only to show which
results a clean phone shares with a concealed one.

## 5. Predictions

Written before any capture. "C-neg" means NOT_OBSERVED published with concealable-negative records.

**Lab (E1 tools on X0).**

1. No detector is OBSERVED.
2. `TEE_ATTESTATION` NOT_OBSERVED: locked, verified boot, a hardware chain; the attested boot state
   agrees with the boot properties, which is published as a C-neg.
3. `DANGEROUS_PACKAGES`, `KERNEL_CHECK` and `LSPOSED_SEPOLICY` NOT_OBSERVED with their
   concealable-negative records; `LSPOSED_SEPOLICY` with two concealable and no trusted negatives.
   The point is that the clean phone's negatives on the units that declare concealment are
   published exactly as the concealed cells' are.
4. `NATIVE_ROOT_SEPOLICY` INCONCLUSIVE (on a user build the `shell_su_transition` target exists and
   the Java-level `denied` is not an answer; recorded for this phone in its docs).
5. `KEYSTORE_GRANT_SPLIT` INCONCLUSIVE (API 35; `KeyStoreManager` exists from API 36).
6. `DRM_CREDENTIAL_COHERENCE` NOT_OBSERVED. Its docs record that it has never been measured on a
   locked, unmodified phone; it is the finding left on the Pixel in P6, T1 and T2, so an OBSERVED
   here would show that finding is not specific to concealment.
7. `DANGEROUS_PROPS`, `SU_BINARY`, `MOUNT_INTEGRITY` NOT_OBSERVED with no concealable-negative
   record (as in E1; these are the three falsified declarations, and on a clean phone they publish
   trusted negatives, which here are correct).

**Retrofits.**

8. RootBeer `isRooted()` false; no RootBeer check positive; every upstream-clean check rests on a
   `no_answer` or `concealable` unit (every RootBeer unit declares concealment, so the
   `concealable` share is by declaration).
9. Ruru `max(Result)` NOT_FOUND; no Ruru check positive.
10. Both libraries' clean results on X0 rest on the same classes as in P6 and T2: the result
    returned to the host does not separate this phone from the concealed Pixel.

**Black-box tools.** No root or concealment finding in any of them:

11. Key Attestation: bootloader locked, verified boot, chain verified to a Google root, no revoked
    certificate.
12. Native Root Detector: no root, concealment or bootloader finding.
13. Ruru 1.1.1: every item "未發現", except that "PM 命令查詢" may be "被拒絕" (as on the Redmi).
14. Duck 1023 and 521: Danger 0. A Warning that names USB debugging or developer options is
    expected and is not counted against this prediction; any other Warning is reported.

## 6. Decision rules

- A detector result counts only if the three repetitions agree; otherwise it is reported unstable.
- A Lab OBSERVED result is a false alarm on this configuration. It is reported with its records
  and the detector's docs; no detector is changed in response within this tag. A fix would be a new
  tag, and E1 would be captured again with it (`../README.md`, Development and evaluation, 3).
- No concealment mechanism is switched on, so no concealment declaration is confirmed or falsified
  here. A C-neg on this phone is the intended behaviour: a declaration says what could produce the
  negative, not what did.
- INCONCLUSIVE results are reported per detector with the reason the Lab gives; they are not
  read as clean.
- Black-box tools are reported as displayed, with the build. No black-box result is reinterpreted.
- X0 is reported in its own table, not pooled with the Pixel or the Redmi.

## 7. Procedure

1. Read the conditions from the device into `raw/X0/cell.md` (`ANDROID_SERIAL` held in an
   environment variable only): fingerprint, SPL, `uname -a`, `/proc/version`, boot properties,
   SELinux, absence of `su`, and whether any package on the Lab's or RootBeer's indicator list is
   installed (matches only; no other package is recorded).
2. Uninstall the product repository's packages (`io.leemikepop.tamperprobe`, `.test`) as in E1–E3
   (amendments of 2026-10-17 and 2026-10-21), and the development builds of the retrofit hosts and
   their test packages. Install the tag builds and the archived black-box APKs, and check every
   installed sha256 against §2. **Stop** on a mismatch.
3. Capture the probe app and both retrofit hosts three times each with the instrumented export
   tests (installed APKs kept between runs), pull the JSON into `raw/X0/`, delete it from the
   device, and run `compare_cells.py --provenance raw/X0`; **stop** on a non-zero exit.
4. Run Key Attestation, Native Root Detector and Ruru 1.1.1 once each; keep a screenshot and a
   text dump of the first screen in `raw/X0/blackbox/`. Run Duck 1023, export its report, uninstall
   it, install 521 (sha256 checked), run and export again. Duck reports are redacted as in the
   E1–E3 amendment of 2026-10-20 before they are kept.
5. Check every kept file for the device serial, IMEI, accounts and personal app lists; **stop** if
   one appears.
6. Run `summarize_retrofit.py` and `compare_cells.py` (X0 alone and with the E1 cells of §4) and
   paste their output into `results.md`.

Screenshots must not show notifications or other apps; one that does is deleted and retaken.

## 8. Threats to validity

- One clean phone, from one vendor; no rate.
- Not held out (§3): the detectors were tuned with this phone among others.
- USB debugging and developer options are on.
- A clean result shows only that this phone, at this time, triggered nothing; it says nothing about
  other stock builds, which may differ in exactly the properties the detectors read.

---

<!-- Below this line: append only. -->

## Amendment 2026-11-23

Made after X0 was captured. No prediction or decision rule changes.

- **Correction to §5, prediction 6.** `DRM_CREDENTIAL_COHERENCE` is the only finding left on the
  Pixel in T1 and T2, not in P6, where `TEE_ATTESTATION` is OBSERVED too (E1–E3 results). The
  prediction itself is unchanged.
- **Capture command (§7 step 3).** The export tests were run with `adb shell am instrument -w`
  against the installed tag APKs instead of Gradle, which reinstalls them and on HyperOS needs a
  confirmation on the phone for every install. Same APKs, same test classes.
- **Recapture.** The first capture of X0 was lost before it was checked (`raw/X0/cell.md`); all
  three rounds were captured again, and only the second capture is kept.
- **Black-box settings.** Native Root Detector was installed fresh with its two optional detection
  sets off; they were switched on to match the E1 records, and both screens are kept. Ruru 1.1.1
  is recorded below its first screen as well, which the E1 records are not. Duck's start-up
  choices (notifications skipped, GitHub acceleration off, CRL online refresh not granted) leave
  both builds on the built-in revocation snapshot, as in E1.
- **Results** are in `results.md`, as for E1–E3.
