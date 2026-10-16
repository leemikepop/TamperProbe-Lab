# Third-party code in `retrofit/`

TamperProbe-Lab is GPL-3.0-only. The retrofits vendor or link the following, each under its own
licence; the vendored files are unmodified (see each `upstream/UPSTREAM.md`).

| Component | Where | Licence |
| --- | --- | --- |
| RootBeer, revision `de7bc7b`, © 2015 Scott Alexander-Bown, Mat Rollings (its README) | `rootbeer/upstream/` | Apache-2.0, [`rootbeer/upstream/LICENSE`](rootbeer/upstream/LICENSE) |
| Ruru (fork of ApplistDetector), revision `30694c2`, by byxiaorun and the ApplistDetector authors | `ruru/upstream/java`, `ruru/upstream/cpp` | Apache-2.0, [`ruru/upstream/LICENSE.md`](ruru/upstream/LICENSE.md) |
| `basicAppList`, the marker paths and the binary directories, copied from Ruru | `ruru/src/main/java/.../RuruConstants.kt` | Apache-2.0, as above |
| linux-syscall-support, commit `e1e7b0a`, © Google Inc. | `ruru/upstream/external/linux_syscall_support/` | BSD-3-Clause, in the file's header |
| Magisk stub APK, as shipped in Ruru 1.1.1's assets | `ruru/upstream/assets/stub.apk` | GPL-3.0 (Magisk) |
| xposed-detector 2.2 (`io.github.vvb2060.ndk:xposeddetector`), linked statically into Ruru's library | Maven Central, not vendored | Apache-2.0 (its POM) |

Apache-2.0 and BSD-3-Clause code may be combined into a GPL-3.0 work; the notices above and the
licence files next to the code are kept as those licences require.
