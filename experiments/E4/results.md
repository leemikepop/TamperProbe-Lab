# E4 results

The results section named in `README.md` §7 step 6. Every matrix and count below is the unedited
output of `tools/compare_cells.py`, `retrofit/tools/summarize_retrofit.py` and
`E4/declared_units.py` over the committed `raw/X0` cell, captured 2026-11-23. Conditions,
black-box screens and Duck reports are in `raw/X0/cell.md`. One phone in one configuration:
nothing here is a detection or false-positive rate.

## Validity

```
$ compare_cells.py --provenance E4/raw/X0
device:    Xiaomi/cupid_global/cupid:15/AQ3A.250226.002/OS3.0.3.0.VLCTWXM:user/release-keys
full build: {"buildType": "debug", "gitCommit": "8c047f1693b5", "gitDirty": false, "versionCode": 5, "versionName": "1.0.5"}
full: 3 runs, repetition disagreements: none
rootbeer build: {"applicationId": "io.leemikepop.tamperprobe.lab.retrofit.rootbeer", "buildType": "debug", "gitCommit": "8c047f1693b5", "gitDirty": false, "versionCode": 5, "versionName": "1.0.5"}
rootbeer: 3 runs, repetition disagreements: none
ruru build: {"applicationId": "io.leemikepop.tamperprobe.lab.retrofit.ruru", "buildType": "debug", "gitCommit": "8c047f1693b5", "gitDirty": false, "versionCode": 5, "versionName": "1.0.5"}
ruru: 3 runs, repetition disagreements: none
```

The three repetitions agree in every selection, so every result below meets the three-repetition
rule. `summarize_retrofit.py` gives the same classification for all three runs of each host.

## E1 tools — TamperProbe-Lab on X0

```
$ compare_cells.py E4/raw/X0
selection=full
detector                                X0
KEYSTORE_GRANT_SPLIT                     ?
NATIVE_ROOT_SEPOLICY                     ?
(36 detectors NOT_OBSERVED in every listed cell are omitted)
observed                                 0
reference score                          2
```

The two INCONCLUSIVE results: `KEYSTORE_GRANT_SPLIT` records `apiLevel = 35`, `available = false`
(the `KeyStoreManager` API exists from API 36); `NATIVE_ROOT_SEPOLICY` records
`overview.oracleState = inconclusive`, with `shell_su_transition` the only rule whose target
(`u:r:su:s0`) is `valid` and its Java-level decision `denied`, which the detector does not take as
an answer.

Units that declare a concealable negative, and the detectors whose negatives carry none:

```
$ python E4/declared_units.py E4/raw/X0 E1-E3/raw/T2
X0 tamperprobe-scan-20261123T095843Z-catalog-1.0-full.json
  declared units: dangerous-packages.package-identity-visibility=COMPLETE/1 dangerous-packages.app-data-path-visibility=UNAVAILABLE/0 kernel-check.integrity-posture=PARTIAL/2 kernel-check.identity-coherence=PARTIAL/1 lsposed-sepolicy.policy-oracle=PARTIAL/2 native-root-sepolicy.policy-oracle=PARTIAL/0 tee-attestation.chain-and-root-of-trust=COMPLETE/1
  NOT_OBSERVED without any concealable-negative record: 32
X0 tamperprobe-scan-20261123T095853Z-catalog-1.0-full.json
  (same two lines)
X0 tamperprobe-scan-20261123T095903Z-catalog-1.0-full.json
  (same two lines)
T2 tamperprobe-scan-20261020T143728Z-catalog-1.0-full.json
  declared units: dangerous-packages.package-identity-visibility=COMPLETE/1 dangerous-packages.app-data-path-visibility=UNAVAILABLE/0 kernel-check.integrity-posture=PARTIAL/2 kernel-check.identity-coherence=PARTIAL/1 lsposed-sepolicy.policy-oracle=PARTIAL/2 native-root-sepolicy.policy-oracle=PARTIAL/0 tee-attestation.chain-and-root-of-trust=COMPLETE/1
  NOT_OBSERVED without any concealable-negative record: 32
T2 tamperprobe-scan-20261020T143739Z-catalog-1.0-full.json
  (same two lines)
T2 tamperprobe-scan-20261020T143750Z-catalog-1.0-full.json
  (same two lines)
```

(The repeated lines are abbreviated here; the script prints them in full and they are identical.)

`TEE_ATTESTATION` on X0: chain of 4, `trustedRootState = trusted`, `revocation.revoked = false`,
`rootOfTrust.deviceLocked = true`, `rootOfTrust.verifiedBootState = Verified`,
`attestationSecurityLevel = TrustedEnvironment`, and the attested boot state agrees with
`verifiedbootstate=green`, `flash.locked=1`, `vbmeta.device_state=locked`.
`DRM_CREDENTIAL_COHERENCE` on X0: `securityLevel = L1`, `systemIdState = provisioned`, boot claim
locked, NOT_OBSERVED. `LSPOSED_SEPOLICY`: `overview.concealableNegativeCount = 2`,
`overview.trustedNegativeCount = 0`.

## Next to the concealed cells (not a single factor; no attribution)

```
$ compare_cells.py E4/raw/X0 E1-E3/raw/P0 E1-E3/raw/P6 E1-E3/raw/T2 E1-E3/raw/R0 E1-E3/raw/R4
selection=full
detector                                X0          P0          P6          T2          R0          R4
DANGEROUS_PACKAGES                       .         O:W           .           .         O:W         O:W
DANGEROUS_PROPS                          .         O:M           .           .         O:M           .
DRM_CREDENTIAL_COHERENCE                 .           .         O:M         O:M           .           .
KERNEL_CHECK                             .         O:M           .           .           .           .
KEYSTORE_GRANT_SPLIT                     ?           .           .           .           ?           ?
MOUNT_INTEGRITY                          .           .           .           .         O:S           .
NATIVE_ROOT_SEPOLICY                     ?         O:W           ?           ?         O:W         O:W
SU_BINARY                                .           .           .           .         O:S           .
TEE_ATTESTATION                          .         O:W         O:M           .           ?           .
TEE_OVERSIZED_CHALLENGE                  .           .           .           .           ?           .
(28 detectors NOT_OBSERVED in every listed cell are omitted)
observed                                 0           5           2           1           5           2
reference score                          2           7           5           3          15           3
```

On the units that declare concealment, the clean X0 and the fully concealed T2 publish the same
statuses and the same concealable-negative records, and the same number of detectors (32) publish
negatives without one; on T2 one of those 32 is `DANGEROUS_PROPS`, whose negative the property
spoof produced (E1–E3 results, Concealment declarations). What separates the two reports is
`DRM_CREDENTIAL_COHERENCE`, OBSERVED MODERATE on T2 and NOT_OBSERVED on X0; `KEYSTORE_GRANT_SPLIT`
differs only by API level.

## E2 and E3′ — retrofits on X0

```
$ compare_cells.py --selection rootbeer E4/raw/X0 E1-E3/raw/P6 E1-E3/raw/T2 E1-E3/raw/R4
selection=rootbeer
detector                                 X0          P6          T2          R4
ROOTBEER_DANGEROUS_PROPS                  .           ?           ?           .
(8 detectors NOT_OBSERVED in every listed cell are omitted)
observed                                  0           0           0           0
reference score                           0           1           1           0

$ compare_cells.py --selection ruru E4/raw/X0 E1-E3/raw/P6 E1-E3/raw/T2 E1-E3/raw/R4
selection=ruru
detector                             X0          P6          T2          R4
RURU_FILE_LIBC                        .           .           .         O:W
RURU_FILE_SYSCALL                     .           .           .         O:W
RURU_PM_COMMAND                       .           .           .           ?
(7 detectors NOT_OBSERVED in every listed cell are omitted)
observed                              0           0           0           2
reference score                       0           0           0           3
```

`summarize_retrofit.py` (each of the three runs of each host):

```
upstream: RootBeer de7bc7b4b09c; isRooted() = false
upstream clean checks: 9; resting on: no_answer 0, concealable 9, mixed 0, trusted 0
upstream: Ruru 30694c211c63; max(Result) over the checks = NOT_FOUND
upstream clean checks: 10; resting on: no_answer 0, concealable 9, mixed 1, trusted 0
```

Per unit, RootBeer's three file checks answered 19 of 21 paths (`EACCES`) and its property check 2
of 2; Ruru's two file checks answered 33 of 66 (`control_ENOENT`), every other unit answered fully.
On the Pixel cells RootBeer's property check had no answer (0 of 2), so its classification there
is 1 / 8 / 0 / 0; Ruru's is 0 / 9 / 1 / 0 there as here (E1–E3 results).

## Black-box tools

As displayed (`raw/X0/cell.md`): Key Attestation, Google hardware root, bootloader locked, no
certificate marked revoked; Native Root Detector "The Environment is normal" with and without its
two optional detection sets; Ruru 1.1.1 every item "未發現" except 設置屬性 "可疑" (developer options
on, USB debugging on); Duck 1023 Danger 0 / Warning 2 (ADB Runtime; System Properties, single
item `persist.sys.usb.config: adb`); Duck 521 Danger 0 / Warning 1 (System Properties, the same
item).

## Predictions (§5)

| # | Result | Basis |
| --- | --- | --- |
| 1 | holds | observed 0 |
| 2 | holds | `TEE_ATTESTATION` NOT_OBSERVED; locked, verified, trusted root, not revoked; one concealable-negative record |
| 3 | holds | the package-identity unit, both `KERNEL_CHECK` units and `LSPOSED_SEPOLICY` (2 concealable, 0 trusted) carry their records; the app-data path unit reports UNAVAILABLE |
| 4 | holds | `NATIVE_ROOT_SEPOLICY` INCONCLUSIVE (`oracleState inconclusive`) |
| 5 | holds | `KEYSTORE_GRANT_SPLIT` INCONCLUSIVE (`apiLevel 35`, `available false`) |
| 6 | holds | `DRM_CREDENTIAL_COHERENCE` NOT_OBSERVED (L1, provisioned, locked) |
| 7 | holds | `DANGEROUS_PROPS`, `SU_BINARY`, `MOUNT_INTEGRITY` NOT_OBSERVED with no concealable-negative record |
| 8 | holds | `isRooted()` false; 9 clean checks, 0 / 9 / 0 / 0 |
| 9 | holds | `max(Result)` NOT_FOUND; no Ruru check positive |
| 10 | holds in part | Ruru 0 / 9 / 1 / 0 as on P6 and T2; RootBeer 0 / 9 / 0 / 0 here and 1 / 8 / 0 / 0 there, because its property check answered here. No clean check of either library rests on a trusted unit in X0, P6 or T2, so neither host verdict separates them |
| 11 | holds | Key Attestation as above |
| 12 | holds | NRD "normal" |
| 13 | **fails** as worded | 設置屬性 "可疑": developer options and USB debugging, the settings §3 names; every other item "未發現", PM 命令 included |
| 14 | holds | Danger 0 in both builds; every Warning names USB debugging |

Fourteen predictions: twelve hold, one holds in part, one fails as worded. No detector was changed.

## What X0 shows

- No Lab detector reports an indicator on this stock, locked phone. That is one phone; it is not a
  rate, and the phone was among those the detectors were developed on (README §3).
- `DRM_CREDENTIAL_COHERENCE`, OBSERVED on the Pixel from P2 on and the only finding left in T1 and T2, does not
  fire here. This is its first measurement on a locked, unmodified phone.
- On every unit that declares concealment, the clean phone's report is the concealed Pixel's
  report. The contract reports that those negatives cannot be told apart, which is what it
  promises; it does not claim the clean phone is clean. RootBeer and Ruru return the same verdicts
  as on the concealed Pixel, resting on the same kinds of evidence.
