# TamperProbe-Lab

TamperProbe-Lab is the research edition of TamperProbe, an evidence-oriented framework for
app-local Android root and runtime-tampering detection. It is the artifact for a journal paper in
preparation (IEEE journal first), and contains only what that paper needs: the native detectors,
the Evidence Contract they report through, a minimal SDK, a probe app that exports raw reports, and
a research-mode RASP adapter with a command-line injector.

> **Status:** E1–E3 evaluated. The repository was created from the TamperProbe product code on
> 2026-10-14 with a fresh history. Experiments E1–E3 were captured on tag `eval-2026-10-v1`
> (2026-10-17 to 10-21); results are in [`experiments/E1-E3/results.md`](experiments/E1-E3/results.md).
> Three detectors whose concealment declarations the ladders falsified are reported as found and
> are not changed on this tag; any fix gets a new tag and its own experiment.

## Relation to the thesis and the product

- **Thesis.** TamperProbe was developed for an NTHU master's thesis. The thesis evaluated the
  product build; the paper re-runs its experiments on this repository.
- **Product.** The TamperProbe product repository stays private. It adds licensing, a reference
  policy that can block the host app, Maven publishing, a developer portal and a web injection
  service. None of these are needed to reproduce the paper, so none are here (see
  [What was removed](#what-was-removed-and-why)).
- **Separate install.** The Lab uses its own package namespace and application IDs
  (`io.leemikepop.tamperprobe.lab...`), so it can be installed next to the product app on one phone.

## What the paper uses it for

| Experiment | What it needs from this repository |
| --- | --- |
| E1: concealment ladders (done) | the probe app (every detector, JSON export) and `experiments/tools/compare_cells.py` |
| E2: RootBeer contract retrofit (done) | `retrofit/rootbeer`: RootBeer's nine checks reported through the Evidence Contract |
| E3′: Ruru contract retrofit (done) | `retrofit/ruru`: ten of Ruru's checks reported through the Evidence Contract |
| E3: black-box detectors on the same cells (done) | nothing; screens and exported reports are recorded in each `cell.md` |
| E5: RASP deployability on open-source F-Droid apps (deferred) | `tamperprobe-rasp` (research mode) and `injector/` |

No result in this repository is a detection rate or a false-positive rate. A handful of phones in
fixed configurations shows how detectors behave in those configurations; it does not estimate how
often they are right on the device population.

## The Evidence Contract in one page

A **detector** answers one security question and returns exactly one assessment:

| Outcome | Strength | Meaning |
| --- | --- | --- |
| `OBSERVED` | `WEAK`, `MODERATE` or `STRONG` | at least one `SIGNAL` record supports it |
| `NOT_OBSERVED` | `NONE` | the checks ran and found nothing; this is **not** proof of a clean device |
| `INCONCLUSIVE` | `NONE` | a check could not run or could not decide (blocked channel, missing data) |
| `FAILED` | `NONE` | the detector itself failed; only a detector-level `collectionError` is reported |

Each detector is split into **evidence units**, one per observation channel. A unit has no outcome
of its own. Its descriptor (observed object, proposition, channel, availability, trust boundary,
inference limit) is declared once in the catalog; each scan reports the unit's collection status
(`COMPLETE`, `PARTIAL`, `UNAVAILABLE`), its records (`SIGNAL`, `OBSERVATION`, `RESEARCH`) and its
issues. Only `SIGNAL` records may support an assessment. `Succeeded=true` in a payload means the
probe completed, not that tampering was observed.

The catalog is generated from one `*.evidence.json` sidecar per detector (next to its `.cpp`) and
`tamperprobe/evidence_domains.json`. Counts quoted anywhere should be read from the generated
`tamperprobe/scripts/generated/detections_manifest.json`; on tag `eval-2026-10-v1` it holds 8
evidence domains, 38 detectors and 54 evidence units.

## Layout

| Path | Contents |
| --- | --- |
| `tamperprobe/` | Native engine (`src/main/cpp`, one folder per evidence domain, JNI `performScan`, wire schema 1) and the minimal Kotlin SDK (`scan()` → raw report). `scripts/generate_detections_manifest.py` validates the sidecars and generates the catalog. |
| `shared/` | Sources compiled into more than one module (not Gradle modules): the Evidence Contract model (SDK and retrofits); DRM credential, FD forensics carrier, SELinux Policy Oracle carrier, TEE keystore, attestation roots (SDK and RASP adapter). |
| `app/` | Probe app: scans every detector, shows each detector's units, records and issues, and exports the report as JSON. |
| `tamperprobe-rasp/` | Java-only RASP adapter in research mode, and the Gradle tasks that build the RASP bundle. |
| `injector/` | Command-line injector: `inject.sh`, `merge_manifest.py`, `verify_bundle.py`, tests. |
| `test-fixtures/` | `xposed-control` (a positive-control inline hook for LSPosed) and `storage-owner` (a fixture app for the package-storage visibility test). |
| `samples/rasp-java-host/` | A minimal pure-Java APK to inject into when testing the injector. |
| `experiments/` | Preregistration rules and template, and analysis tools. Raw data from new experiments goes here. |
| `retrofit/` | Contract retrofits of RootBeer (E2) and Ruru (E3′): the vendored, unmodified upstream code, a host app for each, and the summary tool. See [`retrofit/README.md`](retrofit/README.md). |
| `scripts/` | `analyze_scan_durations.py` for per-detector timing. |

Per-detector developer notes (`*.docs.md` beside each `.cpp`) are inherited from the product and
are written in Traditional Chinese.

## Build

Requirements: JDK 17, the Android SDK with NDK `27.0.12077973` and CMake `3.22.1`, and Python 3
(standard library only) for the catalog generator.

```bash
export ANDROID_HOME=/path/to/Android/Sdk          # or create local.properties with sdk.dir=...
export TAMPERPROBE_LAB_PYTHON=python3             # interpreter used by the catalog generator
./gradlew assembleDebug
./gradlew :tamperprobe:testDebugUnitTest :app:testDebugUnitTest :tamperprobe-rasp:testDebugUnitTest
python3 -m unittest discover -s tamperprobe/scripts/tests
python3 -m unittest discover -s injector/tests
python3 -m unittest discover -s scripts/tests
python3 -m unittest discover -s retrofit/tools/tests
```

`assembleDebug` also builds the two retrofit hosts; their JVM tests are
`:retrofit:common:testDebugUnitTest`, `:retrofit:rootbeer:testDebugUnitTest` and
`:retrofit:ruru:testDebugUnitTest`.

On Windows use `gradlew.bat` and set the variables with `$env:NAME = "..."`. `local.properties` is
ignored by git; never commit it.

The build regenerates the catalog (`:tamperprobe:generateDetectionsManifest`) before compiling. The
generated files under `tamperprobe/scripts/generated/` and `tamperprobe/src/main/AndroidManifest.xml`
are committed; CI fails if they are stale.

## Run a scan and export JSON

Install the probe app (`app/build/outputs/apk/debug/app-debug.apk`, application ID
`io.leemikepop.tamperprobe.lab`). It scans every detector on launch. **Export JSON** saves the report,
with device and build provenance, through the Android file picker.

To capture a scan without touching the UI, run the instrumented export test. It writes the report to
`/data/local/tmp`, which survives an uninstall:

```bash
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=io.leemikepop.tamperprobe.lab.FullScanExportTest \
  -Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true
adb -s <serial> shell ls /data/local/tmp/
adb -s <serial> pull /data/local/tmp/<file>.json
```

Keep the app installed between runs (`leaveApksInstalledAfterRun=true`): concealment modules are
configured per installed package, and reinstalling silently changes the conditions. To scan a subset
of detectors, use `DetectorSetProbeTest` with `-e detectors A,B,C` (or `ALL`). Never record a device
serial in experiment notes.

## Inject the research RASP into an APK

Use this only with apps you are allowed to modify; the paper uses open-source F-Droid apps.

1. Build the bundle: `./gradlew :tamperprobe-rasp:prepareRaspBundle`, which writes
   `tamperprobe-rasp/build/outputs/rasp-bundle/tamperprobe-rasp-bundle.zip`.
2. Download [apktool](https://apktool.org/) and baksmali ([smali releases](https://github.com/baksmali/smali))
   into `injector/tools/` as `apktool.jar` and `baksmali.jar`, or set `APKTOOL_JAR` and `BAKSMALI_JAR`.
   They are not redistributed here.
3. Run (bash, on Linux, macOS, WSL or Git Bash):

   ```bash
   export ANDROID_SDK_ROOT=/path/to/Android/Sdk
   injector/inject.sh input.apk output.apk
   ```

   The script verifies the bundle (file hashes, four ABIs, declared catalog counts), converts the
   adapter to smali, adds it with the native libraries and catalog assets, merges the manifest,
   rebuilds, aligns and signs with the SDK debug keystore (override with `KEYSTORE_PATH`,
   `KEYSTORE_PASS`, `KEY_ALIAS`). `RASP_ENABLED_DETECTIONS` / `RASP_DISABLED_DETECTIONS` narrow the
   selection; by default every detector runs. A per-injection report is written next to the output
   APK (`*.injection.json`).
4. Install and launch the injected app. On start-up the adapter scans on a background thread and
   writes the raw wire-schema report to `Download/tamperprobe-lab/` (pull it with
   `adb -s <serial> pull /sdcard/Download/tamperprobe-lab/`). One line per detector is logged under
   tag `TamperProbeLab`. The adapter never blocks or terminates the host.

Known limits of the research RASP: the FD forensics helper process is not part of the bundle, so
`ZYGISK_FD_FORENSICS` runs without its snapshot; when either SEPOLICY detector is selected the
injector configures an app-zygote preload, and it refuses targets that already declare their own
`zygotePreloadName`. The injected app's minimum SDK is raised to 29 if it was lower.

## What was removed, and why

| Removed | Why |
| --- | --- |
| License gate, TP1 tokens, issuer and verification keys, `license_key.py`, `verify_license.py` | Product access control; irrelevant to measuring detectors, and keys must never be published. |
| `STABLE`/`EXPERIMENTAL` tiers and the default selection (`maturity`, `enabledByDefault`) | Research needs every detector, including the aggressive ones. Every scan runs the whole catalog unless a selection is given. |
| RASP auto-block dialog, process kill, fixed-weight RASP scorer, threshold metadata | The paper separates detection from policy; the research RASP only records what it observed. |
| Reference scorer in the core path | The probe app shows the raw report only. `ReferenceTamperScorer` remains in the SDK as an optional, documented example (with its tests) and nothing calls it. |
| Maven publishing, the SDK consumer sample | No artifact is published from this repository. |
| `web/portal` and the Flask/Celery/Redis injection service | Product delivery; the command-line injector is enough for experiment E5. |
| Product documentation, ADRs and agent instructions, IDE settings | They describe the product, its history and its licensing. |
| Raw evaluation data, device notes, third-party app captures | New experiments produce fresh data; nothing personal or device-identifying is published. |
| Pinned catalog counts (8/38/53) in code | The catalog will change after the experiments; consumers check against counts derived from the generated manifest instead. |

## Experiments

New experiments follow the preregistration rules in [`experiments/README.md`](experiments/README.md):
write and commit the preregistration before the first capture, append amendments only, keep raw
JSON unmodified, and never record a device serial.

## Licence and citation

TamperProbe-Lab is licensed under the GNU General Public License, version 3 only (GPL-3.0-only);
see [`LICENSE`](LICENSE). Third-party material keeps its own licence:

- `tamperprobe/src/main/cpp/nlohmann/` is nlohmann/json, under the MIT License.
- Part of the package list in `DangerousPackageList.kt` is taken from Duck-Detector's
  `DangerousAppsCatalog` (eltavine/Duck-Detector-Refactoring), under the Apache License 2.0.
- The kernel identity cross-check in `KERNEL_CHECK` (`kernel_identity_coherence.cpp`) adapts the
  idea of Duck-Detector's `KernelIdentityConsistencyUtils` (Apache License 2.0); no code was copied.

A citation entry will be added when the paper is accepted.
