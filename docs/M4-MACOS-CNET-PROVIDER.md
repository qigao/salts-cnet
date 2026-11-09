# M4.5 — macOS pinned-provider CNet native execution (Draft)

Stacked on SaltsCore PR #17, where Linux CNet already has a verified TLS
CA/SAN regression. The target is **real macOS runtime**, not merely
cross-compilation or a provider-free Core SDK smoke test.

## Toolchain and dependency closure

The unified `.github/workflows/ci.yml` qualifies both macOS-15 ARM64 and
macOS-15 Intel x64 through the checked-in `llvm-native-release-user` preset,
also used for local POSIX LLVM builds. It restores the
manifest through the pinned vcpkg-cache action and consumes the checked-in
custom registry that pins GmSSL 3.2.0#13.

Host build tools include re2c and Ninja, installed via Homebrew if missing.
The vcpkg manifest requests the explicit `cnet` feature, building
GmSSL/KCP/c-ares/SIMDe. Binary caching uses a **local files-only provider**,
never Mono/NuGet or an unversioned system TLS fallback.

## Runtime gates

- Compile/link **all CNet source** and install `Salts::CNet` dylib.
- Run the full source CTest suite in macOS kqueue mode.
- Explicitly run the TCP accepted-loopback retained ownership test,
  real TLS trusted CA + correct SAN / wrong CA / wrong DNS identity test,
  GmSSL public TLS ABI callbacks and ShangMi provider KAT.
- Build the complete configured graph once and run its formal CTest suite.

A failed macOS source/provider test must not be marked success on the
strength of the unrelated Linux job. Existing Linux qualification remains
unchanged. No production deployment or original Salts/ACE cutover is implied.

## Remaining after this job

Windows LLVM-MinGW + IOCP provider-enabled build, CNet native cancellation/shard
close and DSO unload races, Linux ASan/UBSan and TSan, UDP/KCP/WebSocket
wire traffic, independently implemented TLS peer interoperability, Android
and iOS SDK/runtime, and explicit ABI/SONAME ownership handoff.
