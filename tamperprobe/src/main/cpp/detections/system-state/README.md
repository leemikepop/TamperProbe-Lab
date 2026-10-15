# Property and SELinux Detectors

This directory owns the published `CUSTOM_ROM`, `DANGEROUS_PROPS`,
`SYSTEM_PROPERTIES_TAMPER`, and `SELINUX_CHECK` detectors. All published detector payload schemas
start at version 1. They
preserve source availability explicitly and do not turn missing or inaccessible
observations into findings.

## Shared Android property observations

`property_observation.cpp` reads the same Android property namespace through:

- Bionic's opaque `prop_info` API and read callback, with the legacy property-get
  fallback required by API 24-25;
- `android.os.SystemProperties` through JNI;
- one time-bounded `/system/bin/getprop` snapshot executed directly without a
  shell; and
- parsed files under `/dev/__properties__`.

The shared state model is `present`, `missing`, or `unavailable`. Java
`System.getProperty()` is intentionally excluded because JVM properties are not
Android system properties.

`property_area_parser.cpp` checks that each file is a root-owned regular file and
is not group- or world-writable. It bounds-checks the current Bionic property-area
magic and version, `bytes_used`, allocation alignment, the trie, property records,
the dirty-value backup area, long-value offsets, strings, overlapping allocations,
and cycles. Unsupported or malformed layouts remain unit issues.
Unreferenced allocation ranges are Research only; they are not attributed to
`resetprop` and do not change the assessment.

## `DANGEROUS_PROPS`

This detector evaluates explicit values from the Bionic source. Moderate findings
are:

- `ro.secure=0`;
- `ro.boot.verifiedbootstate=orange` or `red`;
- `ro.boot.flash.locked=0`;
- `ro.boot.vbmeta.device_state=unlocked`; and
- `service.adb.root=1` together with `ro.debuggable=1`.

Weak findings are `ro.debuggable=1`, `eng` or `userdebug` build types, and build
tags containing `test-keys` or `dev-keys`. The detector also publishes
non-assessment Research data for QEMU properties set to `1`, USB configuration
tokens containing `adb`, and a standalone `service.adb.root=1` request. The last
item is omitted when `ro.debuggable=1` makes the combined moderate rule applicable.
Encryption state remains outside this detector. The native assessment uses the
strongest explicit rule hit; Research data and counts never escalate strength.

A ninth rule reads `Settings.Global` `adb_enabled` through the app's
`ContentResolver`: an integer above 1 is WEAK, MODERATE when `sys.usb.config` or
`persist.sys.usb.config` lists `adb`; a negative or unparsable value is WEAK. From
API 37 (Android 17 QPR1) the platform returns 0 for this setting to every
third-party app, so on API 37+ a read that parses as 0 is recorded as
`redacted_by_platform` with a `collectionWarnings` entry and is not an answered
rule. A non-zero read cannot come from the redaction and is graded as usual.

The v1 payload contains `overview`, `observations[]`, `findings[]`, `telemetry[]`,
`collectionErrors[]`, and `collectionWarnings[]`.

## `SYSTEM_PROPERTIES_TAMPER`

This detector compares only equivalent observations for the security-property set
listed above. A strong finding requires at least two available sources for the same
property and different values. A missing or inaccessible source cannot create a
mismatch. Parsed property-area allocation maps and unreferenced ranges are retained
as Research data.

The result is `INCONCLUSIVE` only when no property has two available sources and no
property area was parsed successfully. The v1 payload contains `sources[]`,
`comparisons[]`, `propertyAreas[]`, `findings[]`, and `collectionErrors[]`.

## `SELINUX_CHECK`

This detector observes:

- the filesystem type at `/sys/fs/selinux` and the enforce-file value;
- when that read fails with `EACCES`, a read-denial inference (`selinuxfs_read_denial`):
  the kernel creates `enforce` as `S_IRUGO|S_IWUSR` (`sel_fill_super` in
  `security/selinux/selinuxfs.c`), so on a node confirmed as selinuxfs whose DAC mode
  (from `stat()`, or the kernel constant 0644 when `stat()` is refused) permits the read,
  the refusal can only be SELinux enforcing a denial on the app's own domain;
- optional global enforcement state dynamically resolved from `libselinux`;
- a non-writing `O_WRONLY` permission probe for `/sys/fs/selinux/enforce`; and
- `/proc/self/attr/current` as process-context diagnostics.

A writable enforce node or two contradictory *read* enforcement sources is
strong evidence. A confirmed global Permissive or Disabled mode is moderate
evidence, as is a contradiction that needs the inferred source. The inferred source
answers whether the app's own domain is enforced; it says nothing about other
domains and is defeated by a hook that makes `open()` return `EACCES`. Missing files, linker-namespace restrictions, inaccessible sources, and a
process domain that behaves differently from the global mode are not findings by
themselves. Shell `getenforce`, Logcat or AVC scanning, audit callbacks, and policy
mutation queries are intentionally not used.

The v1 payload contains `filesystem`, `enforcementSources[]`, `readDenialInference`,
`writeProbe`, `processContext`, `findings[]`, and `collectionErrors[]`.

## Evidence roles and comparison projects

Public adapters bind these payload fields to declared units and explicitly emit `SIGNAL`,
`OBSERVATION`, `RESEARCH`, or issues. Record codes do not encode role. Unavailable sources always
map to `PARTIAL/UNAVAILABLE` issues, never Signals.

Duck Detector revision `1786f14beddf30d02432c781208cd93f9e8415cc` was inspected
under its Apache-2.0 license. Its active property path informed the choice to adapt
opaque Bionic callbacks, explicit availability, and current property-area concepts;
TamperProbe independently implements its own collector, parser, payload, and
assessment rules. Overt revision `3783c9ad53daf30012953b7c392fc3bbc8659823`
was used as research input only: the relevant property and Logcat callers are
inactive in the inspected revision and no tracked license file was found.

## False-positive limits

- Development and custom ROMs can legitimately trigger weak property findings.
- Emulator identity and enabled ADB transport are visible posture Research data, not
  proof of root or property tampering, and do not change the detector verdict.
- An unlocked bootloader or non-green Verified Boot state is security-relevant but
  does not identify a particular root provider.
- OEM property-area allocation patterns are not yet baselined, so holes remain Research data.
- Global SELinux enforcement and per-domain policy behavior are different claims.
- A source failure reduces coverage; it is never treated as evidence of tampering.
