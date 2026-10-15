# Kernel and Privilege Interfaces Evidence Domain

This directory is the primary source owner for `KERNEL_CHECK`, `LSPOSED_SEPOLICY`,
`NATIVE_ROOT_DEVPTS`, `NATIVE_ROOT_PRCTL`, `NATIVE_ROOT_SEPOLICY`, and `NATIVE_ROOT_SUSFS`.

`NATIVE_ROOT_PATHS` owns fixed root-framework paths. It probes each candidate with
`stat`, `lstat`, and `O_PATH` open and requires at least two successful operations.
Provider-specific KernelSU, APatch, and Magisk paths retain their existing strong
classification. The shared `/data/adb` and `/data/adb/modules` roots are `other`
artifacts and therefore remain weak because they do not identify one provider. These
paths were removed from `DANGEROUS_PACKAGES`, whose path probes are now package-derived.
Legacy `scene_*` and shared-storage tool directories were not migrated because their
visibility alone is not specific enough to support a native-root finding.

`NATIVE_ROOT_SEPOLICY` consumes the same immutable app-zygote snapshot as
`LSPOSED_SEPOLICY`; selecting either or both IDs starts one carrier. It owns four fixed rules:

The shared carrier is deliberately unavailable on Android 10 (API 29), where retaining the
inherited policy snapshot can violate the app-zygote descriptor contract. On that platform the
manager returns a failure snapshot, this detector reports `INCONCLUSIVE` with an unavailable unit
issue, and sibling detectors continue. API 30 and later retain the carrier path.
Those platforms close libselinux's status/netlink resource after snapshot collection and before
the app zygote forks a service child. A missing teardown symbol makes the snapshot unavailable
rather than risking a process-level zygote failure.

| Rule | Assessment |
| --- | --- |
| `untrusted_app -> magisk:binder call` | Native-trusted or Java-controlled `Allowed` is WEAK |
| `untrusted_app -> ksu_file:file read` | Native-trusted or Java-controlled `Allowed` is WEAK |
| `adbd -> adbroot:binder call` | Native-trusted or Java-controlled `Allowed` is WEAK |
| `shell -> su:process transition` | WEAK only when `ro.build.type=user`; otherwise Research data |

Multiple allowed rules remain WEAK. Java-only `Denied` on a target type that exists is
`INCONCLUSIVE`, because the hidden API cannot tell a denial from a failure. `NOT_OBSERVED` needs
every assessment rule to be either a native-trusted `Denied` (a trusted negative) or a target
type the loaded policy does not define (a concealable negative: hiding tools can remove the
type). On a `user` build without the native tier this means a clean phone stays `INCONCLUSIVE`,
since `u:r:su:s0` exists and only the Java tier answers `shell -> su`. Contradictions,
Permissive/Disabled state, failed controls, instability, wrong carrier state, timeout, and
malformed snapshots remain `INCONCLUSIVE`.

The detector uses payload schema 1 and returns the shared `overview`, `carrier`, `device`,
`trust`, `enforcementSources[]`, `querySources[]`, `controls[]`, `concealableNegatives[]`, and
`collectionErrors[]` fields, plus only its four owned `rules[]` and any `findings[]`. On
`NOT_OBSERVED`, `overview.trustedNegativeCount` and `overview.concealableNegativeCount` split
the negatives it rests on, and the adapter publishes one
`<DETECTOR>.policy-oracle.concealable-negative` OBSERVATION record per concealable negative. LSPosed/Xposed rules cannot affect this
detector's verdict. Correlation with paths, prctl, devpts, SUSFS, SU, Magisk, or KernelSU evidence
is left to consumer policy.

DroidSpaces, MSD, `fsck_untrusted sys_admin`, and `zygote -> adb_data_file` remain research
inventory and are not published as findings.

## LSPosed policy consumer

`LSPOSED_SEPOLICY` consumes the same immutable app-zygote snapshot but receives only its three
owned LSPosed/Xposed rules. Native-trusted `Allowed` observations can support WEAK or MODERATE
evidence; Java-controlled `Allowed` is capped at WEAK. Java `Denied` on an existing type,
contradictions, failed controls, Permissive state, wrong carrier identity, timeout, and malformed
input remain `INCONCLUSIVE`. With LSPosed absent, both owned types are undefined and the result is
a `NOT_OBSERVED` resting only on concealable negatives (`trustedNegativeCount` 0). An allowed rule is not proof that LSPosed is installed or in scope.

## Shared policy-oracle helper

`policy_oracle.{h,cpp}` owns the fixed rule registry and trust-tier classification. It is not a
published detector. Adding a rule does not publish it: a consumer still needs a detector ID,
payload decoder, evidence adapter, catalog unit, fixture, and traceability review.

## Kernel and direct privilege probes

`KERNEL_CHECK` records bounded kernel/build and verified-boot observations. The prctl, devpts, and
SUSFS detectors probe narrow kernel/VFS side channels and keep unavailable or ambiguous channels
explicit. These mechanisms can be patched or filtered and do not establish universal provider
coverage or successful root access.
