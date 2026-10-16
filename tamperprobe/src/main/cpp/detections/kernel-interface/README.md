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

`KERNEL_CHECK` has two units. `kernel-check.integrity-posture` is the marker, cmdline, kptr and
symbol scan. When `/proc/version` is unreadable (the usual case for an app), its banner scan saw
only the uname syscall, which a kernel-side uname spoof (SUSFS `spoof_uname` hooks `newuname`)
rewrites to a stock string; that not-found is listed in `bannerConcealableNegatives` and published
as a `KERNEL_CHECK.integrity-posture.concealable-negative` OBSERVATION record, the same Rule 3
treatment as `NATIVE_ROOT_PATHS`' `concealableNotFoundPaths` and the policy oracle's
`concealableNegatives`. The outcome stays `NOT_OBSERVED`, as it does for the policy oracle.

`kernel-check.identity-coherence` compares the kernel release from up to four sources: the
`os.version` property (read through JNI with the scan's `JNIEnv`), which libcore fills from
`uname().release` while Zygote initialises and every app inherits; the live `uname()` release;
`/proc/sys/kernel/osrelease`; and the release parsed from `/proc/version`. The comparison is the
pure function `kernel_identity::compareReleases` in `kernel_identity_coherence.{h,cpp}`. Any two
readable sources that differ give a `kernel_identity_mismatch` finding and a MODERATE signal, which
makes the detector `OBSERVED` (posture hits keep their own grading; the stronger result wins).
MODERATE matches `BUILD_PATCH_COHERENCE` and `DRM_CREDENTIAL_COHERENCE`: the contradiction is sound,
but the snapshot is a Java value an in-process hook can rewrite and no clean control has been
measured on this build. Agreement is published as a concealable negative
(`identityConcealableNegatives`), and fewer than two readable sources leave the unit `UNAVAILABLE`
with a `kernel_identity` issue, never a negative.

The snapshot only helps when the spoof lands after Zygote cached the release. A spoof applied after
Zygote started (observed on a Pixel 7 with a blu_spark kernel and susfs4ksu: `os.version`
`6.1.162+blu-spark`, live `uname()` the stock `6.1.162-android14-11-g2ec90535fa34-ab15810641`) is
caught. A spoof applied before Zygote initialises, as the SUSFS reference module does from
`post-fs-data.sh`, makes the snapshot carry the spoofed value too; the unit then agrees and only the
procfs sources, which an app usually cannot read, could still differ. The idea is adapted from
Duck-Detector's `KernelIdentityConsistencyUtils.kt` (eltavine/Duck-Detector-Refactoring,
Apache-2.0); no code was copied.
