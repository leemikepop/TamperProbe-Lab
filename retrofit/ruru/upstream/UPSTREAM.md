# Vendored: Ruru 30694c2

| | |
| --- | --- |
| Project | [byxiaorun/Ruru](https://github.com/byxiaorun/Ruru), a fork of [Dr-TSNG/ApplistDetector](https://github.com/Dr-TSNG/ApplistDetector) |
| Revision | `30694c211c63e8bc48c4db84a1cb525868c2bc41` (2026-08-20, the latest commit when vendored; the last tagged release is v1.1.1, `638f631`, 2024-01-09) |
| Licence | Apache-2.0 ([`LICENSE.md`](LICENSE.md)) |
| Taken | `library/src/main/java` → `java/`, `library/src/main/cpp/src` → `cpp/`, `LICENSE.md` |
| Modified | Nothing. Line endings are LF, as in the upstream blobs. |

Between v1.1.1 and this revision the library changed in two files: one item label in
`AbnormalEnvironment.kt`, and `XposedModules.kt`. The latter matters when comparing with a v1.1.1
black-box run: v1.1.1 first enumerated every installed app (`getInstalledApplications`) and fell
back to apps with a MAIN activity only when that found nothing; this revision enumerates only apps
with a MAIN activity, so a module without a launcher entry is invisible to it. It also adds
`META-INF/xposed/module.prop` (libxposed API 101) and NPatch metadata.

## Files from elsewhere

| File | Source | Why |
| --- | --- | --- |
| `external/linux_syscall_support/linux_syscall_support.h` | [linux-syscall-support](https://chromium.googlesource.com/linux-syscall-support) at `e1e7b0ad8ee99a875b272c8e33e308472e897660`, the submodule commit Ruru pins; BSD-3-Clause (header comment) | Included by `cpp/file_detection.cpp` |
| `assets/stub.apk` | `assets/stub.apk` of the Ruru 1.1.1 release APK (`Ruru.1.1.1.15.apk`, SHA-256 `8a2856cd13353c18402f1ba31bb1a7320d8aaa4aedd7391f1bd7d75ef889b056`); the file's SHA-256 is `c43e89bc1e6edfdc6f4160be67022bff08b99c99b2904c052fa6054713a74ba1`. It is Magisk's stub APK (GPL-3.0). | `MagiskApp` compares launcher apps with it. The source repository ignores `*.apk`, so a build from source has no stub and `MagiskApp` silently finds nothing. |

`BLOBS` lists the git blob ID of every file here. The Ruru files equal the upstream blobs at the
revision above; the header equals the blob in the linux-syscall-support tree at the pinned commit.
`python retrofit/tools/verify_upstream.py` checks the files against `BLOBS`.

## How the host builds it

- `java/` is added as a Kotlin source directory of `:retrofit:ruru`. Ruru compiles against SDK 33;
  SDK 37 marks `PackageInfo`'s fields `@android.annotation.Nullable`, so the module compiles with
  `-Xnullability-annotations=@android.annotation:warn`, which gives those fields the platform
  types they had upstream. The bytecode does not gain null checks.
- Upstream builds `libapplist_detector.so` with ndk-build (`Android.mk`, `Application.mk`). The host
  describes the same build in `../src/main/cpp/CMakeLists.txt`: the same two sources, the same
  include paths, the same static library (`io.github.vvb2060.ndk:xposeddetector:2.2` through
  prefab, the version upstream pins) and the common flags of `Application.mk`.
- Ruru's app loads the library in `MyApplication`'s initialiser; the host does the same in
  `RuruRetrofitApplication`.

`Accessibility.kt`, `Account.kt` and `SettingProp.kt` are compiled but not run; see
`../src/main/java/io/leemikepop/tamperprobe/lab/retrofit/ruru/RuruSpecs.kt` for why.
