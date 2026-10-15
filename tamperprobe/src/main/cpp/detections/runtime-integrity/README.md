# Native hook and code-integrity detections

This directory owns control-flow and executable-code integrity in the current app process. The
`process-memory/` owns mapping/FD/linker-view structure; this domain owns resolved function
entries, runtime instrumentation markers, file-backed code bytes, and VDSO consistency. Root
provider installation alone is not a finding.

The active path for every detector is:

`CMakeLists.txt` -> `REGISTER_DETECTION` -> native registry -> `native_bridge.cpp` -> wire payload ->
`EvidenceAdapterRegistry.kt` typed runtime binding.

`elf_text_integrity.cpp` is the registered detector and owns module selection, aggregation,
assessment and payload policy. `elf_integrity.{h,cpp}` is not a second detector: it is the shared,
ABI-aware comparison seam used by both `PROLOGUE_SCANNER` and `ELF_TEXT_INTEGRITY`. It accepts a
parsed maps snapshot, resolves ELF file offsets, verifies memory permissions, reads process memory
without changing page protections, and compares it with the backing file. Both files are required;
their pure inputs allow controlled maps/module/byte fixtures without coupling policy to JNI.
`entry_pattern.{h,cpp}` is likewise a helper rather than a detector. It independently classifies
Duck-derived AArch64/x86-64 branch and trampoline entry shapes for diagnostic telemetry.

## `PROLOGUE_SCANNER` (`prologue_scanner.cpp`)

- **Payload schema:** 1.
- **Threat model:** an inline hook or resolver redirection changes selected `libc.so` or dynamic
  linker function entries in the target process.
- **Inputs:** `dlopen`/`dlsym`, `dladdr`, `/proc/self/maps`, and the resolved backing ELF.
- **Targets:** eleven `libc.so` entries (`open`, `openat`, `read`, `write`, `access`, `readlink`,
  `readlinkat`, `stat`, `mmap`, `mprotect`, `ioctl`) plus `dlopen`, `dlsym`, and `dlclose`, whose
  resolved owner may be `libdl.so`, `linker`, or `linker64` according to the Android build.
- **Decision:** resolving outside the expected `libc.so` module or differing from the corresponding
  backing-ELF bytes is a moderate finding. A branch, veneer, NOP, or hardening instruction is not
  a finding when it matches the file. On AArch64 and x86-64, the first sixteen bytes are also
  classified as ordinary, expected-prologue, branch-like, or trampoline-like; this observation has
  `patternAssessmentImpact=diagnostic_only` and never changes native assessment by itself.
- **Payload:** `checks` records target/expected libraries, function, status, reason, resolved module
  and backing-file offset plus architecture, raw entry bytes, pattern flags/classification, and the
  diagnostic-only policy. Top-level pattern observation/branch/trampoline counts are telemetry;
  target/checked/unavailable library arrays and legacy function-name arrays are also retained.
- **Failure semantics:** any unresolved/unreadable entry with no finding produces `INCONCLUSIVE`.
  Unavailability is emitted as a collection warning, never as a clean comparison.
- **False positives:** a legitimately patched backing file or resolver interposition intentionally
  supplied by the app can differ from the expected module policy. Legal export stubs, linker
  veneers, tail branches and toolchain hardening can match the entry-pattern telemetry, which is why
  those flags are not findings.
- **False negatives:** coordinated modification of memory and backing bytes, spoofed `dladdr`/maps,
  GOT slots not exercised by the selected symbols, and hooks outside the fourteen entries remain
  invisible. Overt's `libart.so`/`libinput.so` CRC candidates do not define portable entry symbols,
  so they belong to segment integrity rather than this entry detector.
- **Tool attribution:** byte mismatch is `MECHANISM_MATCH`; an unexpected module path may become a
  `DIRECT_MARKER` only when that path itself contains a validated tool marker.

## `RUNTIME_INSTRUMENTATION` (`runtime_instrumentation.cpp`)

- **Payload schema:** 1.
- **Threat model:** Frida, Zygisk/Riru, LSPosed/Xposed, Play Integrity Fix/TrickyStore,
  concealment tooling or another instrumentation runtime leaves a named library, map, FD target,
  or thread inside the target process.
- **Inputs:** `/proc/self/maps`, `/proc/self/fd`, `/proc/self/task/*/comm`, and public
  `dl_iterate_phdr` objects.
- **Decision:** configured names for Frida/Gum, Zygisk/Riru, LSPosed/Xposed,
  Play Integrity Fix/TrickyStore, Shamiko and MagiskHide families are moderate `directMarkers`.
  Generic executable memfd and generic GLib-like thread names are `genericAnomalies` telemetry
  only.
- **Payload:** direct markers, generic anomalies, per-source collection errors, source availability,
  scan counts, malformed map lines, linker object count and evidence counts.
- **Failure semantics:** a required source failure with no direct marker returns `INCONCLUSIVE`.
  Generic telemetry alone remains `NOT_OBSERVED`.
- **False positives:** an app can legitimately use a marker word in its own library/thread name;
  the short `pif` compatibility marker is especially broad. `gmain`, `gdbus` and `pool-spawner`
  are explicitly not findings.
- **False negatives:** renamed objects/threads, closed FDs, anonymous manual mapping and coordinated
  procfs/linker filtering can remove all markers.
- **Tool attribution:** an explicit in-process name is `DIRECT_MARKER` for that artifact, not proof
  that a root provider is installed or active globally and not a Google server-side Play Integrity
  verdict. Marker-free evidence is `GENERIC_ANOMALY`. Specialized Zygisk dirty-page and LSPosed map
  ownership remains in their own detector categories.

## `ELF_TEXT_INTEGRITY` (`elf_text_integrity.cpp`)

- **Payload schema:** 1.
- **Threat model:** inline instrumentation changes executable bytes in a selected file-backed ELF
  beyond the small set of function entries checked by `PROLOGUE_SCANNER`.
- **Inputs:** public `dl_iterate_phdr` records for loaded `libc.so`, `libart.so`, and `libinput.so`,
  their non-writable executable `PT_LOAD` segments, `/proc/self/maps`, process-memory reads, and the
  resolved backing files. `libc.so` is required; ART and input are optional because a target app may
  not load them or may be unable to see them through its linker namespace.
- **Decision:** any byte mismatch is a moderate modified-segment finding. Only `PF_X && !PF_W`
  file-backed bytes are compared. The detector never calls `mprotect`.
- **Payload:** target/required libraries, resolved modules, missing required/optional libraries,
  comparison method, checked/modified/unavailable segment records, collection errors and segment
  counts. A modified record includes its owning library and first mismatch offset.
- **Failure semantics:** missing required `libc.so`, an unreadable loaded target, execute-only range
  or partial segment read produces `INCONCLUSIVE` when no mismatch is present. An unloaded optional
  `libart.so` or `libinput.so` is telemetry and does not make an otherwise complete scan
  inconclusive.
- **False positives:** legitimate runtime text patching, vendor hot patching or backing-file races
  can differ. The wider three-library policy increases this compatibility surface, and no
  clean-device baseline exists.
- **False negatives:** GOT/PLT-only hooks, writable data redirection, modified memory plus modified
  backing file, and channels filtered consistently are outside the byte comparison.
- **Tool attribution:** all mismatches are `MECHANISM_MATCH`; no tool name is inferred from bytes.

## `VDSO_INTEGRITY` (`vdso_integrity.cpp`)

- **Payload schema:** 1.
- **Threat model:** a remapped, writable, structurally invalid or inconsistently owned VDSO may
  redirect selected kernel-helper calls.
- **Inputs:** the `[vdso]` map, `AT_SYSINFO_EHDR`, in-memory ELF header/program headers, public
  linker ownership and any resolvable `__kernel_*` helper symbol.
- **Decision:** multiple maps, unexpected permissions, auxv/base mismatch, invalid ELF/load ranges,
  missing public linker ownership, or a resolved helper outside the VDSO are moderate findings.
  Missing ABI-specific helper symbols are optional telemetry, not findings.
- **Payload:** map/auxv addresses, permissions, ELF/load validation, linker and symbol ownership,
  typed findings, collection errors and `findingCount`.
- **Failure semantics:** missing maps/auxv or unreadable headers return `INCONCLUSIVE` when no finding
  can be established.
- **False positives:** Android/ABI linker enumeration and exported VDSO symbols can vary; the symbol
  channel is therefore only enforced when a symbol resolves. Device baselines are required.
- **False negatives:** this is a structural cross-check. With no trusted disk baseline it does not
  claim complete VDSO byte integrity, and coordinated userspace source spoofing remains possible.
- **Tool attribution:** all findings are `GENERIC_ANOMALY`/`MECHANISM_MATCH`, never a root-tool
  identity claim.

## Adoption and rejection record

- **Duck Detector snapshot:** `eltavine/Duck-Detector-Refactoring` at
  `1786f14beddf30d02432c781208cd93f9e8415cc` (Apache-2.0). We adopted module-range checking,
  its `libc.so` plus `libdl.so`/linker entry targets, the scoped `ioctl` backing-byte comparison,
  multi-channel runtime evidence and the maps/auxv VDSO cross-check. We also adapted its selected
  AArch64/x86-64 branch/prologue/trampoline shapes as diagnostic telemetry. We rejected those shapes
  as standalone findings because legal veneers and toolchain hardening can start with branch
  instructions; TamperProbe requires unexpected ownership or backing-byte disagreement.
- **Overt snapshot:** `leemikepop/Overt` at
  `3783c9ad53daf30012953b7c392fc3bbc8659823`. We studied `zProcInfo.cpp`, `zLinkerInfo.cpp`,
  `zProcMaps.cpp`, `zElf.cpp` and `zLinker.cpp` read-only. No tracked license was present, so no Overt
  code was copied. Its active `zManager::round_tasks()` includes the `linker_info` task, whose source
  lists `libc.so`, `libart.so`, and `libinput.so` as CRC targets; the separately commented
  `zInfoTest.cpp` call is not the activation owner. TamperProbe independently applies that list only
  to loaded public-phdr modules and rejects the fixed four-map-segment assumption, private
  `solist_get_head`/`soinfo` symbols, fixed linker paths/layouts and a generic `gmain`-style thread as
  direct proof of Frida.

## Validation status

- A debug-only native fixture bridge covers backing-ELF match, modified bytes, unavailable maps,
  exact module provenance, and a branch-shaped legal veneer that remains clean when its bytes match
  the backing ELF. It now also classifies an AArch64 direct-branch veneer and an x86-64 indirect-jump
  trampoline as research observations, for eleven native seam cases total. The bridge is excluded
  from release/RASP builds and the eleven-case suite passed on Android 14 x86-64.
- Kotlin fixtures cover clean/modified/unavailable Prologue entries with module provenance, direct
  versus generic runtime evidence, modified/unavailable ELF segments, VDSO findings and collection
  warnings.
- Full debug native builds cover `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64` with the new
  classifier, ELF read seam, Prologue scanner and native fixtures.
- One Android 14 x86_64 Magisk/DenyList compatibility smoke completed all fourteen prologue entries
  and one executable segment each from loaded `libc.so`, `libart.so`, and `libinput.so`, with no
  modified or unavailable result. On the updated entry-pattern run, `libdl.so!dlclose` was
  `branch_like` but clean against its backing ELF; the detector remained `NOT_OBSERVED` and exposed
  one entry-pattern `RESEARCH` record within the `prologue-scanner.entry-pattern` unit. The eleven
  native seam cases passed on that configuration.
- `RUNTIME_INSTRUMENTATION`, `ELF_TEXT_INTEGRITY` and `VDSO_INTEGRITY` still require clean and
  injected device baselines. Evaluation must
  record Zygisk/module/Frida/LSPosed state separately from Magisk or KernelSU provider presence.
