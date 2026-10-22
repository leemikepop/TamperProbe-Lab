# Contract retrofits (experiments E2 and E3′)

Two third-party detectors, wrapped so that they report through the Evidence Contract without any
change to how they detect:

| Experiment | Detector | Host module | Application ID |
| --- | --- | --- | --- |
| E2 | [RootBeer](https://github.com/scottyab/rootbeer) `de7bc7b` (release 0.1.2, the revision the thesis examined) | `:retrofit:rootbeer` | `io.leemikepop.tamperprobe.lab.retrofit.rootbeer` |
| E3′ | [Ruru](https://github.com/byxiaorun/Ruru) `30694c2`, the maintained fork of ApplistDetector | `:retrofit:ruru` | `io.leemikepop.tamperprobe.lab.retrofit.ruru` |

Both were run on the E1 ladder cells ([`../experiments/E1-E3/`](../experiments/E1-E3/), results in
`results.md`). E2 retrofits a Boolean detector; E3′ extends it to a
detector that already has a coverage state. They show that the contract is an abstraction that
can be applied to code we did not write, and they measure how many of a detector's "clean" results
rest on a channel that did not answer or on an absence concealment can manufacture. Neither is a
detection or false-positive rate.

## What a retrofit changes, and what it does not

RootBeer returns `false` both when a check found nothing and when it could not look. Ruru has
`METHOD_UNAVAILABLE`, but its libc file check maps every errno, `EACCES` included, to `NOT_FOUND`,
and neither tool can say that a "not found" is one a hiding tool produces on demand. The
retrofit keeps the detection and changes only the report:

1. **The upstream code decides every positive.** Each check is the unmodified upstream method,
   called as an integrator (RootBeer) or Ruru's own main page calls it. Its verdict is recorded
   verbatim, and an upstream positive is never dropped.
2. **A shadow probe decides whether the channel answered.** After the upstream call, the retrofit
   repeats the same call on the same channel (the same `stat`, `open`, `faccessat`, PackageManager
   lookup or command) and keeps what upstream discards: the errno, the exception, whether the
   listing was empty. A target the shadow sees but upstream missed is reported as an issue, not
   as a positive.
3. **Rule 1:** a target whose call failed with anything other than "not there" (`ENOENT`,
   `ENOTDIR`, `NameNotFoundException`) is not answered. A unit with no answered target is
   `UNAVAILABLE`; a check with no answering unit is `INCONCLUSIVE`, never `NOT_OBSERVED`.
4. **Rule 2:** every channel has an anchor, something present on every device that must come back
   through the same call: `/system/bin/sh` for path checks, the host and the `android` package for
   PackageManager, `ro.build.version.sdk` for `getprop`, the root mount for `mount`, `which sh`
   for `which su`, `com.android.settings`' directory for each app-data path family. If the anchor
   fails, that channel's "not there" counts as no answer. Platform package-visibility filtering
   is handled the same way: a package outside the host's visibility scope is not answered.
5. **Rule 3:** every unit declares in advance whether concealment can manufacture its negative,
   and names the mechanism (`RootBeerSpecs.kt`, `RuruSpecs.kt`). Answered negatives from such a
   unit are published with a `concealable-negative` record. Each declaration is a claim a ladder
   cell can falsify by switching the mechanism on.
6. **Rule 6:** every unit lists how many targets it tried and how many answered (a `coverage`
   record), and findings are graded as TamperProbe grades the same evidence: a package name or a
   development property is `WEAK`, an executable `su` at a fixed path is `STRONG`.

Assembly is in [`common/.../ContractAssembler.kt`](common/src/main/java/io/leemikepop/tamperprobe/lab/retrofit/common/ContractAssembler.kt);
the result types are the SDK's own (`shared/evidence-contract`), so a retrofitted check is held to
the same invariants as a TamperProbe detector.

## The checks

**RootBeer** (`isRooted()` ORs nine checks; each becomes a detector with one unit):

| Detector | Upstream | Shadow and anchor | Concealment declared |
| --- | --- | --- | --- |
| `ROOTBEER_ROOT_MANAGEMENT_APPS` | `detectRootManagementApps()` | `getPackageInfo` per package; host + `android`; visibility scope | package-visibility hiding |
| `ROOTBEER_DANGEROUS_APPS` | `detectPotentiallyDangerousApps()` | as above | package-visibility hiding |
| `ROOTBEER_SU_BINARY` | `checkForBinary("su")` | `stat` per path; `/system/bin/sh` | namespace unmount, SUSFS |
| `ROOTBEER_DANGEROUS_PROPS` | `checkForDangerousProps()` | `getprop` listing; a property not listed is not answered | `resetprop` |
| `ROOTBEER_RW_PATHS` | `checkForRWPaths()` | `mount` table parsed as RootBeer parses it; root mount | separate mount namespace |
| `ROOTBEER_TEST_KEYS` | `detectTestKeys()` | `Build.TAGS` not null | `resetprop` |
| `ROOTBEER_WHICH_SU` | `checkSuExists()` | `which su`; `which sh` | namespace unmount, SUSFS |
| `ROOTBEER_NATIVE_SU` | `checkForRootNative()` | `open(O_RDONLY)` per path; `/system/bin/sh`; no answer if `libtoolChecker.so` did not load | namespace unmount, SUSFS |
| `ROOTBEER_MAGISK_BINARY` | `checkForMagiskBinary()` | `stat` per path; `/system/bin/sh` | namespace unmount, SUSFS |

The retrofit runs every check to completion, then calls `isRooted()` once more as an integrator
would; that verdict is the export's `retrofit.aggregate`.

**Ruru** (ten of the thirteen checks on its main page, with its `basicAppList`):

| Detector | Upstream | Units |
| --- | --- | --- |
| `RURU_ABNORMAL_ENVIRONMENT` | `AbnormalEnvironment` | `xposed-hooks`, `user-profile` (no concealment declared), `marker-files`, `root-binaries` |
| `RURU_PM_COMMAND` | `PMCommand` | `pm list packages`; listing must hold the host and `android` |
| `RURU_PM_CONVENTIONAL_APIS` | `PMConventionalAPIs` | installed packages and applications; same anchor |
| `RURU_PM_SUNDRY_APIS` | `PMSundryAPIs` | three lookups per package; `getPackageUid` of host and `android` |
| `RURU_PM_INTENT_QUERIES` | `PMQueryIntentActivities` | MAIN-intent query; must list the host |
| `RURU_FILE_LIBC` | `FileDetection(false)` | `access`/`stat`/`open(O_PATH)` errnos per path; Settings' directory per family |
| `RURU_FILE_SYSCALL` | `FileDetection(true)` | raw `faccessat` errno per path; same control |
| `RURU_XPOSED_MODULES` | `XposedModules(false)` | per launcher app: metadata and APK readable |
| `RURU_LSPATCH` | `XposedModules(true)` | per launcher app: metadata readable |
| `RURU_MAGISK_APP` | `MagiskApp` | stub reference parses; per launcher app: the comparison did not throw |

Ruru's `SUSPICIOUS` counts as a positive (graded `WEAK`); `METHOD_UNAVAILABLE` counts as no answer.
`Accessibility`, `SettingProp` and `Account` are left out: Ruru's app code, not the library,
collects their inputs, they describe privacy settings rather than root or hiding, and `Account`
would record account names. Launcher-app targets are never written into issues, only counted,
because they would list the device's apps.

## Hosts

Each retrofit runs in its own app, so its conditions are its own and it cannot disturb another
detector (Rule 5). Loading Ruru's native library runs xposed-detector, which clears Xposed hooks it
finds in the process; it must never share a process with RootBeer or TamperProbe.

| | RootBeer host | Ruru host |
| --- | --- | --- |
| `targetSdk` | 36, as an app integrating RootBeer today | 29, as Ruru ships |
| Package visibility | `<queries>` naming exactly RootBeer's 39 packages (RootBeer declares none; `RootBeerManifestTest` keeps them equal) | `QUERY_ALL_PACKAGES` and MAIN intents, as Ruru's manifest |
| Native code | RootBeer's own `CMakeLists.txt` | Ruru's sources built with CMake; see `ruru/upstream/UPSTREAM.md` |

Configure concealment (HMA, DenyList, LSPosed scope, TrickyStore targets) for each host package
exactly as for the probe app, and read the settings back from the device into the cell notes.

## Run

```bash
./gradlew :retrofit:common:testDebugUnitTest :retrofit:rootbeer:testDebugUnitTest :retrofit:ruru:testDebugUnitTest
python3 -m unittest discover -s retrofit/tools/tests
python3 retrofit/tools/verify_upstream.py          # vendored code is unmodified

# Capture one run per host into /data/local/tmp (keep the hosts installed between runs)
./gradlew :retrofit:rootbeer:connectedDebugAndroidTest -Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true
./gradlew :retrofit:ruru:connectedDebugAndroidTest -Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true
adb -s <serial> pull /data/local/tmp/retrofit-<time>-rootbeer.json <cell dir>
adb -s <serial> pull /data/local/tmp/retrofit-<time>-ruru.json <cell dir>

python3 retrofit/tools/summarize_retrofit.py <cell dir> ...
python3 experiments/tools/compare_cells.py <cell dir> ... --selection rootbeer
```

Launching a host app shows the same run as text. Exports use the probe app's document format
(`scan.report.results`, `provenance.sampleApp`, `provenance.device`), plus `provenance.host`
(target SDK, package-visibility basis) and a `retrofit` block with every upstream verdict.

## The measurement

`summarize_retrofit.py` classifies, for every check whose upstream verdict was clean, what that
verdict rests on: `no_answer` (no unit answered), `concealable` (every answered unit declares a
concealment), `trusted`, or `mixed`, with the per-unit answered/attempted counts and the reasons
targets did not answer. The E1–E3 preregistration (`../experiments/E1-E3/README.md`) fixes the
cells (the Pixel and Redmi ladders of E1; no clean device), the build tag `eval-2026-10-v1`, and
which declaration each ladder cell tests. Development captures are not results (see
`../experiments/README.md`).

## Limits

- The shadow probe makes its call shortly after upstream's. A state change in between would show
  as a disagreement (`shadow_present_upstream_absent`), not as a wrong positive.
- Each channel is judged on its own. `RURU_PM_INTENT_QUERIES` sees only packages with a MAIN
  activity, so an installed package without one is reported as an answered (concealable) negative
  even when another Ruru channel sees it; the unit's inference limit states this, and the
  retrofit does not use one channel to overrule another.
- Concealment declarations come from the threat model. A ladder cell tests only the mechanisms
  switched on in it; a declaration no cell has tested remains a declaration, not an observation.
- The Ruru host's target SDK and `QUERY_ALL_PACKAGES` reproduce Ruru's release, not a Play-store
  app; the RootBeer host's `<queries>` reproduce a careful integrator. An integrator without them
  gets package checks that never answer, which the retrofit reports as `INCONCLUSIVE`.
- Third-party code and its licences: [`NOTICE.md`](NOTICE.md).
