# Process-memory detections

This directory owns structural evidence from the current process: mappings, file descriptors,
public linker visibility, and `SU_CONTEXT` process-domain observations. It does not own
function-entry or code-byte comparison; those checks remain in `../runtime-integrity/`. Root-provider
installation alone is not a positive control for this family.

All three detectors follow the same active path:

`CMakeLists.txt` -> `REGISTER_DETECTION` -> native registry -> `native_bridge.cpp` -> wire payload ->
`EvidenceAdapterRegistry.kt` typed runtime binding.

The shared `common/proc_maps.{h,cpp}` parser records address range, permissions, file offset,
device, inode, path, and the `(deleted)` state. `parseProcMapLine` is the pure fixture seam; the live
collector passes `/proc/self/maps` through the same parser.

## `MEMORY_FD_ANOMALY` (`memory_fd_anomaly.cpp`)

- **Payload schema:** 1.
- **Threat model:** an injected native runtime may leave an executable memfd/ashmem mapping, a
  deleted executable backing, or a live memfd descriptor in the target process.
- **Inputs:** `/proc/self/maps` and `/proc/self/fd` symlink targets.
- **Decision:** a known instrumentation/framework marker (`frida`, Gum, Gadget, linjector,
  Zygisk/Riru, LSPosed/Xposed) or a deleted executable originating from `/data/adb` or
  `/data/local/tmp` is a moderate finding. Marker-free executable memfd/ashmem and deleted
  executable mappings are `candidates` only. Pipes, sockets, ordinary anonymous descriptors, ART
  JIT caches, WebView/Chromium and common graphics caches are not findings.
- **Payload:** `findings`, `candidates`, `collectionErrors`, source-readability flags, scan counts,
  malformed map-line count, and finding/candidate counts. Each observation records its source and
  classification.
- **Failure semantics:** unreadable/empty maps or an unreadable FD directory returns `INCONCLUSIVE`
  when no finding exists, with a collection warning. Collection failure is never converted to
  clean evidence.
- **False positives:** direct marker text can appear in a legitimately named developer library;
  `/data/local/tmp` is suspicious provenance but not proof of a particular tool. App updates can
  transiently leave deleted executable mappings, which therefore remain candidate telemetry unless
  another suspicious signal exists.
- **False negatives:** renamed memfd objects, unlinked descriptors closed after mapping, procfs
  filtering, and coordinated source spoofing can hide the evidence.
- **Tool attribution:** direct Frida/Gum/LSPosed/Zygisk names are `DIRECT_MARKER` for a process
  artifact, not proof that the corresponding root provider is active. Marker-free memfd/deleted
  evidence is `GENERIC_ANOMALY`. Zygisk dirty-page semantics remain owned by `ZYGISK_SMAPS`, and
  LSPosed-specific map attribution remains owned by `LSPOSED_MAPS`.

## `MEMORY_MAPS_ANOMALY` (`memory_maps_anomaly.cpp`)

- **Payload schema:** 1.
- **Threat model:** runtime code generation or injection may produce writable-executable (W+X),
  non-runtime anonymous executable, or deleted executable mappings.
- **Input:** `/proc/self/maps`, parsed by the shared parser.
- **Decision:** W+X and deleted executable mappings have moderate assessment impact; marker-free
  anonymous executable mappings have weak impact. Known ART/JIT/WebView/Chromium code caches are
  excluded. The detector reports structural anomalies and never labels them Magisk or KernelSU.
- **Payload:** typed `findings`, collection errors, readability/scan/malformed-line diagnostics,
  and `findingCount`.
- **Failure semantics:** unreadable maps returns `INCONCLUSIVE`; a readable clean snapshot returns
  `NOT_OBSERVED`.
- **False positives:** native runtimes, browser engines, profilers, debuggers and OEM components can
  create legitimate executable anonymous mappings. The allow-list is intentionally narrow, and no
  clean-device baseline exists.
- **False negatives:** W^X transitions can leave no simultaneous W+X mapping; file-backed injected
  code may look structurally normal; procfs concealment can rewrite the snapshot.
- **Tool attribution:** all findings are `GENERIC_ANOMALY`. They support a mechanism hypothesis only
  when correlated with a direct marker or a controlled injection state.

## `MEMORY_LINKER_VISIBILITY` (`memory_linker_visibility.cpp`)

- **Evidence schema:** 1.
- **Threat model:** loader-list hiding or inconsistent userspace views may make a public linker
  object's `PT_LOAD` ranges disagree with `/proc/self/maps`.
- **Inputs:** public `dl_iterate_phdr` output and `/proc/self/maps`.
- **Decision:** a linker object's load ranges not covered by the maps snapshot is a moderate
  `linkerOnlyModules` finding. An executable `.so`/APK library mapping not overlapping a public
  linker object is `mapsOnlyModules` telemetry because manual mapping and namespace behavior can be
  legitimate.
- **Payload:** linker-only findings, maps-only telemetry, collection errors, maps/linker counts,
  malformed-line diagnostics and `findingCount`.
- **Failure semantics:** unreadable maps or an empty public linker enumeration returns
  `INCONCLUSIVE`. Maps-only modules alone do not change the assessment from `NOT_OBSERVED`.
- **False positives:** races during `dlopen`/`dlclose`, loader namespaces, split APK layouts and
  unusual OEM loaders can temporarily disagree. Device baselines are required before promotion.
- **False negatives:** an adversary that consistently filters both channels, or a manually mapped
  module intentionally absent from the public linker list, can avoid a finding.
- **Tool attribution:** a mismatch is `GENERIC_ANOMALY`, not a tool-specific marker.

## Adoption record

- **Duck Detector snapshot:** `eltavine/Duck-Detector-Refactoring` at
  `1786f14beddf30d02432c781208cd93f9e8415cc` (Apache-2.0). We adopted the multi-channel idea from
  `memory/maps_anomaly_detector.cpp`, `fd_detector.cpp`, and `linker_detector.cpp`, but separated
  direct markers from generic telemetry and removed fixed loader-layout assumptions.
- **Overt snapshot:** `leemikepop/Overt` at
  `3783c9ad53daf30012953b7c392fc3bbc8659823`. We studied `zProcMaps.cpp` and `zProcInfo.cpp` as a
  read-only comparison. No tracked license was present in the inspected tree, so no Overt code was
  copied. Private linker internals, CRC/layout constants and tool claims unsupported by an active
  caller were not adopted.

## Validation status

- A debug-only native fixture bridge exercises structured/malformed/deleted-memfd map parsing and
  contiguous versus missing linker-range coverage. The nine-case bridge is excluded from release
  and RASP builds and passed on the two x86_64 VMs and the arm64 Redmi stack.
- Kotlin fixtures cover direct findings, generic candidates, collection warnings, W+X findings,
  linker-only findings and maps-only telemetry.
- Debug native builds cover `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`.
- Clean and positive device baselines are still required before either detector's findings can be
  interpreted. The evaluation must distinguish root-provider presence from actual target-process
  injection.
