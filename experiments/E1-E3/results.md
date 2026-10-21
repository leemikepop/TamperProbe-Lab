# E1–E3 results

The results section named in `README.md` §7 step 6. Every matrix and count below is the unedited
output of `tools/compare_cells.py` and `retrofit/tools/summarize_retrofit.py` over the committed
`raw/` cells, captured 2026-10-17 to 2026-10-21. Conditions, black-box screens and Duck reports are
in each `raw/<cell>/cell.md`. Two phones in fixed configurations: nothing here is a detection or
false-positive rate. Pixel and Redmi cells are reported separately (§6).

## Validity

- `compare_cells.py --provenance` exits 0 for all 16 cells (P0, P1, P2, P3a, P3b, P4, P5, P6, P7,
  T1, T2, R0–R4): one device and one app build per selection, `gitCommit 8c047f1693b5`,
  `gitDirty false`.
- Every cell reports `repetition disagreements: none` for `full`, `rootbeer` and `ruru` (3 runs
  each), so every change below meets the three-repetition rule; no detector is unstable.
- `summarize_retrofit.py` gives the same classification counts for all three runs of each cell.

## E1 — TamperProbe-Lab

Key: `O:S`/`O:M`/`O:W` OBSERVED with strength, `?` INCONCLUSIVE, `.` NOT_OBSERVED.

### Pixel 7

```
$ compare_cells.py raw/P0 raw/P1 raw/P2 raw/P3a raw/P4 raw/P5 raw/P6 raw/P7
selection=full
detector                                P0          P1          P2         P3a          P4          P5          P6          P7
DANGEROUS_PACKAGES                     O:W         O:W         O:W         O:W         O:W           .           .           .
DANGEROUS_PROPS                        O:M         O:M           .           .           .           .           .           .
DRM_CREDENTIAL_COHERENCE                 .           .         O:M         O:M         O:M         O:M         O:M         O:M
ELF_TEXT_INTEGRITY                       .           .           .           .           .           .           .         O:M
KERNEL_CHECK                           O:M         O:M         O:M           .           .           .           .           .
LSPOSED_MAPS                             .           .           .           .           .           .           .         O:S
MEMORY_LINKER_VISIBILITY                 .           .           .           .           .           .           .         O:M
MEMORY_MAPS_ANOMALY                      .           .           .           .           .           .           .         O:W
NATIVE_ROOT_SEPOLICY                   O:W         O:W         O:W         O:W         O:W         O:W           ?           ?
RUNTIME_INSTRUMENTATION                  .           .           .           .           .           .           .         O:M
TEE_ATTESTATION                        O:W         O:W         O:M         O:M         O:M         O:M         O:M         O:M
ZYGISK_SMAPS                             .           .           .           .           .           .           .         O:M
(26 detectors NOT_OBSERVED in every listed cell are omitted)
observed                                 5           5           5           4           4           3           2           8
reference score                          7           7           8           6           6           5           5          18

$ compare_cells.py raw/P2 raw/P3a raw/P3b
selection=full
detector                                P2         P3a         P3b
DANGEROUS_PACKAGES                     O:W         O:W         O:W
DRM_CREDENTIAL_COHERENCE               O:M         O:M         O:M
KERNEL_CHECK                           O:M           .         O:M
NATIVE_ROOT_SEPOLICY                   O:W         O:W         O:W
TEE_ATTESTATION                        O:M         O:M         O:M
(33 detectors NOT_OBSERVED in every listed cell are omitted)
observed                                 5           4           5
reference score                          8           6           8

$ compare_cells.py raw/P6 raw/T1 raw/T2
selection=full
detector                                P6          T1          T2
DRM_CREDENTIAL_COHERENCE               O:M         O:M         O:M
NATIVE_ROOT_SEPOLICY                     ?           ?           ?
TEE_ATTESTATION                        O:M           .           .
(35 detectors NOT_OBSERVED in every listed cell are omitted)
observed                                 2           1           1
reference score                          5           3           3
```

### Redmi 13C (held out)

```
$ compare_cells.py raw/R0 raw/R1 raw/R2 raw/R3 raw/R4
selection=full
detector                                R0          R1          R2          R3          R4
DANGEROUS_PACKAGES                     O:W         O:W         O:W         O:W         O:W
DANGEROUS_PROPS                        O:M         O:M         O:M         O:M           .
KEYSTORE_GRANT_SPLIT                     ?           ?           ?           ?           ?
MOUNT_INTEGRITY                        O:S           .           .           .           .
NATIVE_ROOT_SEPOLICY                   O:W         O:W         O:W         O:W         O:W
SU_BINARY                              O:S           .           .           .           .
TEE_ATTESTATION                          ?           ?           ?         O:M           .
TEE_OVERSIZED_CHALLENGE                  ?           ?           ?           .           .
(30 detectors NOT_OBSERVED in every listed cell are omitted)
observed                                 5           3           3           4           2
reference score                         15           7           7           7           3

$ compare_cells.py --selection rootbeer raw/R0 raw/R1 raw/R2 raw/R3 raw/R4
selection=rootbeer
detector                                 R0          R1          R2          R3          R4
ROOTBEER_MAGISK_BINARY                  O:W           .           .           .           .
ROOTBEER_NATIVE_SU                      O:W           .           .           .           .
ROOTBEER_ROOT_MANAGEMENT_APPS           O:W         O:W           .           .           .
ROOTBEER_SU_BINARY                      O:W           .           .           .           .
ROOTBEER_WHICH_SU                       O:W           .           .           .           .
(4 detectors NOT_OBSERVED in every listed cell are omitted)
observed                                  5           1           0           0           0
reference score                           5           1           0           0           0

$ compare_cells.py --selection ruru raw/R0 raw/R1 raw/R2 raw/R3 raw/R4
selection=ruru
detector                             R0          R1          R2          R3          R4
RURU_FILE_LIBC                      O:W         O:W         O:W         O:W         O:W
RURU_FILE_SYSCALL                   O:W         O:W         O:W         O:W         O:W
RURU_PM_COMMAND                       ?           ?           ?           ?           ?
RURU_PM_CONVENTIONAL_APIS           O:W         O:W           .           .           .
RURU_PM_INTENT_QUERIES              O:W         O:W           .           .           .
RURU_PM_SUNDRY_APIS                 O:W         O:W           .           .           .
(4 detectors NOT_OBSERVED in every listed cell are omitted)
observed                              5           5           2           2           2
reference score                       6           6           3           3           3

```

## E2 and E3′ — retrofits

Pixel (no retrofit check positive in any Pixel cell; `ROOTBEER_DANGEROUS_PROPS` is the RootBeer
host's INCONCLUSIVE check):

```
$ compare_cells.py --selection rootbeer raw/P0 raw/P1 raw/P2 raw/P3a raw/P3b raw/P4 raw/P5 raw/P6 raw/P7 raw/T1 raw/T2
selection=rootbeer
detector                                 P0          P1          P2         P3a         P3b          P4          P5          P6          P7          T1          T2
ROOTBEER_DANGEROUS_PROPS                  ?           ?           ?           ?           ?           ?           ?           ?           ?           ?           ?
(8 detectors NOT_OBSERVED in every listed cell are omitted)
observed                                  0           0           0           0           0           0           0           0           0           0           0
reference score                           1           1           1           1           1           1           1           1           1           1           1

$ compare_cells.py --selection ruru raw/P0 raw/P1 raw/P2 raw/P3a raw/P3b raw/P4 raw/P5 raw/P6 raw/P7 raw/T1 raw/T2
selection=ruru
detector                             P0          P1          P2         P3a         P3b          P4          P5          P6          P7          T1          T2
(10 detectors NOT_OBSERVED in every listed cell are omitted)
observed                              0           0           0           0           0           0           0           0           0           0           0
reference score                       0           0           0           0           0           0           0           0           0           0           0

```

Classification of the upstream-clean checks (`summarize_retrofit.py`, "resting on"):

| Cells | RootBeer clean checks: no_answer / concealable / mixed / trusted | Ruru clean checks: no_answer / concealable / mixed / trusted |
| --- | --- | --- |
| P0–P7, P3b, T1, T2 (each) | 9: 1 / 8 / 0 / 0 | 10: 0 / 9 / 1 / 0 |
| R0 | 4: 0 / 4 / 0 / 0 | 5: 1 / 3 / 1 / 0 |
| R1 | 8: 0 / 8 / 0 / 0 | 5: 1 / 3 / 1 / 0 |
| R2, R3, R4 (each) | 9: 0 / 9 / 0 / 0 | 8: 1 / 6 / 1 / 0 |

No upstream-clean check of either library rests on a `trusted` unit in any cell. RootBeer
`isRooted()` is false in every Pixel cell, true in R0 and R1, and false from R2 on. Ruru's
`max(Result)` is NOT_FOUND in every Pixel cell and FOUND in every Redmi cell (its libc and syscall
file checks).

## Predictions (§5)

| Cell | Result | Basis |
| --- | --- | --- |
| P0 | holds | `KERNEL_CHECK`, `DANGEROUS_PROPS`, `DANGEROUS_PACKAGES` OBSERVED, `TEE_ATTESTATION` OBSERVED WEAK; RootBeer `isRooted()` false, clean checks on no-answer or concealable units only |
| P1 | holds | no change in the Lab, either retrofit or any Duck card |
| P2 | not testable for paths | no path-based check was positive in P1; `DANGEROUS_PROPS` turned NOT_OBSERVED **without** a concealable-negative record |
| P3a | holds | `KERNEL_CHECK` NOT_OBSERVED with concealable negatives, identity coherence `agree`; Duck Kernel Check Info, identity clean |
| P3b | holds | `KERNEL_CHECK` OBSERVED MODERATE (identity `disagree`); both Duck builds Kernel Check Danger |
| P4 | — (no direction predicted) | no change |
| P5 | holds for the Lab; not testable for the retrofits | `DANGEROUS_PACKAGES` C-neg; the retrofits' package checks had no positive in P4; Ruru 1.1.1 "未發現" throughout |
| P6 | **fails** | `NATIVE_ROOT_SEPOLICY` became INCONCLUSIVE, not C-neg; `LSPOSED_SEPOLICY` C-neg as before; Duck 521 SELinux Warning, not Clear |
| P7 | holds | the hook is visible to six detectors (`LSPOSED_MAPS` O:S and five others) |
| T1 | holds | locked, verified attestation; the boot properties were already spoofed (P2), so the comparison agrees (C-neg) |
| T2 | holds | boot-state comparison C-neg as in T1; `DRM_CREDENTIAL_COHERENCE` stays OBSERVED |
| R0 | holds except TEE | path, mount and property evidence OBSERVED, `KERNEL_CHECK` NOT_OBSERVED, both retrofits positive; `TEE_ATTESTATION` INCONCLUSIVE (the phone cannot generate an attested key), not OBSERVED WEAK |
| R1 | **fails** | `SU_BINARY` and `MOUNT_INTEGRITY` turned NOT_OBSERVED **without** concealable-negative records |
| R2 | holds for the retrofits, fails for the Lab | RootBeer and Ruru package checks concealable; `DANGEROUS_PACKAGES` stays OBSERVED on MagiskKiller (amendment 2026-10-21); Ruru 1.1.1 package checks "未發現", PM command "被拒絕" |
| R3 | holds | `attested_boot_state_contradicts_properties`, OBSERVED MODERATE |
| R4 | holds | boot-state comparison agrees (C-neg); PIF's `service.sh` spoofed the boot properties |

## Concealment declarations (§6)

A positive that turned negative when a concealment mechanism was switched on:

| Detector unit | Cell (mechanism) | Negative published as |
| --- | --- | --- |
| `KERNEL_CHECK.integrity-posture`, `.identity-coherence` | P3a (uname spoof) | concealable negative — confirmed |
| `DANGEROUS_PACKAGES.package-identity-visibility` | P5 (HMA-OSS) | concealable negative — confirmed |
| `TEE_ATTESTATION.chain-and-root-of-trust` | T1 (TrickyStore), R4 (PIF property spoof) | concealable negative — confirmed |
| `DANGEROUS_PROPS` | P2 (`susfs4ksu`), R4 (PIF) | plain NOT_OBSERVED — **no** concealable-negative record |
| `SU_BINARY.su-binary.visible-artifact` | R1 (Zygisk Next DenyList) | plain NOT_OBSERVED — **no** record |
| `MOUNT_INTEGRITY` | R1 (Zygisk Next DenyList) | plain NOT_OBSERVED — **no** record |
| `NATIVE_ROOT_SEPOLICY` | P6 (Hide SELinux) | INCONCLUSIVE (`oracleState inconclusive`) |

The three detectors without the record are negatives a concealment tool produced, published as if
nothing had been hidden.
