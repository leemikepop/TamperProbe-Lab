# Vendored: RootBeer de7bc7b

| | |
| --- | --- |
| Project | [scottyab/rootbeer](https://github.com/scottyab/rootbeer) |
| Revision | `de7bc7b4b09c9db148b62b331b4a44076b2eb480` (release 0.1.2, the revision the thesis examined) |
| Licence | Apache-2.0 ([`LICENSE`](LICENSE)) |
| Taken | `rootbeerlib/src/main/java` → `java/`, `rootbeerlib/src/main/cpp` → `cpp/`, `LICENSE` |
| Modified | Nothing. Line endings are LF, as in the upstream blobs. |

`BLOBS` lists the git blob ID of every file here, and each equals the upstream blob at that revision
(`git rev-parse de7bc7b:<upstream path>`). `python retrofit/tools/verify_upstream.py` checks the
files against `BLOBS`.

## How the host builds it

- `java/` is added as a source directory of `:retrofit:rootbeer`.
- `cpp/CMakeLists.txt` is used as is to build `libtoolChecker.so`, with the arguments rootbeerlib's
  `build.gradle.kts` passes (`-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON`, `-fPIC`, four ABIs).
- RootBeer's own manifest is empty. The host declares the packages its checks look up under
  `<queries>` (see `../src/main/AndroidManifest.xml`).

The retrofit adds one file to RootBeer's Java package,
`../src/main/java/com/scottyab/rootbeer/UpstreamConstants.kt`, which only reads `Const`.
