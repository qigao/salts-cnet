# Handoff

## 2026-11-01 public header path flattening

- Public headers no longer use `include/salts/`, `include/salts_core/`, or
  `salts_*.h` filenames. Include them from their module include root directly;
  functional directories that already own a namespace, such as `cnet/`,
  `crypto/`, `cserde/`, and `tinytest/`, remain unchanged.
- This is a source-path migration only. Existing C ABI symbol prefixes and
  CMake target names remain stable. Do not restore forwarding headers or
  compatibility directory trees for the retired paths.
- Frozen donor inventories and `serial/original/` retain historical upstream
  names as provenance evidence; they are not current public include paths.

## 2026-11-01 Windows LLVM release identity

- CMake's MinGW platform defaults add a `lib` prefix to Windows DLLs. Keep
  `CMAKE_SHARED_LIBRARY_PREFIX` empty on Windows so MSVC and llvm-mingw publish
  the same versioned `saltscore_<module>-0.1.dll` ABI identity. Do not loosen
  the installed-owner auditor to accept compiler-dependent DLL names.

## 2026-11-01 LLVM preset and CI convergence

- `vcpkg-cache` compiler actions reject protected Release setup when
  `build-type: Release` is combined with `obfuscator: false`. SaltsCore does
  not enable obfuscation, so CI requests `build-type: toolchain-only`; the
  checked-in CMake preset independently selects the Release configuration.
- The outer CMake toolchain is the vcpkg manifest toolchain. Native LLVM or
  the Android NDK is supplied only through `VCPKG_CHAINLOAD_TOOLCHAIN_FILE`.
  Reversing these two toolchains bypasses manifest-mode dependency ownership.
- Existing product CI path filters include production sources and public
  headers, plus native test sources, root CMake settings and the workflow
  itself. These test-only changes qualify the actual native owner graph;
  documentation/packaging-only edits do not trigger new product jobs.
  No separate probe or synthetic installer/consumer workflow is introduced.
- Do not restore installed-consumer/smoke CMake projects. Configure owns the
  complete graph, build runs it without `--target`, and formal tests run only
  through CTest.
- When removing an installer/consumer source tree, remove its native-graph
  registration in the same change. A stale `add_executable` is detected only
  at CMake generation, even when configure has otherwise found all packages.
- `setup-vcpkg-curl-cache` is a binary-only admission gate and fails on the
  first absent immutable ABI package. After the package registry is cleared,
  product CI must use `setup-vcpkg-cache` in read mode so vcpkg can compile a
  cache miss from the pinned source graph without publishing from the product
  repository.

## 2026-11-01 CNet numeric-host endpoint

- A c-ares numeric-host result cannot be trusted to preserve the service port
  byte order on every platform. `cnet_resolver_submit()` retains the caller's
  host-order port and the callback writes `htons(requested_port)` into the
  validated IPv4/IPv6 sockaddr before transport admission. Do not add retry,
  provider fallback, or timeout relaxation for this failure.
- Local configure/build/test requires the tracked root
  `CMakeUserPresets.json`; do not qualify an older checkout that lacks the
  versioned root presets.

## 2026-11-01 Windows LLVM-MinGW qualification

- Windows CI uses the pinned `vcpkg-cache/setup-llvm-mingw` action for both
  x64 and ARM64. Its `QIGAO_COMPILER_TOOLCHAIN_FILE`, overlay triplets and
  `qigao-*-windows-llvm-mingw` identities are the contract; a local clang-cl
  build is useful for diagnosis but is not equivalent CI evidence.
- LLVM-MinGW 20261020 with CMake 4 exposed a zstd overlay bug: a C-only
  project must guard C++ flag probes with `CMAKE_CXX_COMPILER_LOADED`, not the
  mere presence of `CMAKE_CXX_COMPILER`. This is fixed in vcpkg-cache PR 262,
  merge commit `529019437597fa71f7d8dcc561d26fc7b0603ae6`.
- MinGW's libusb provider may be a static `.a` archive. Stage a runtime DLL
  only when the discovered provider is an MSVC `.lib` or MinGW `.dll.a`
  import library; do not require or invent a DLL for a static archive.
- MinGW DLL import libraries require explicit public API export annotations.
  Do not rely on `WINDOWS_EXPORT_ALL_SYMBOLS` to recover legacy Platform
  functions.
- LLVM-MinGW LLD map files use `Address Size Align Out In Symbol`, unlike
  MSVC maps. Native-Crypto ownership auditing must combine the LLD input
  member with `llvm-nm` archive-member definitions and use `llvm-readobj` for
  PE imports; unsupported linker diagnostics are not a substitute.
- Use `SALTS_THREAD_LOCAL` for shared Core TLS declarations. Selecting
  `__declspec(thread)` from `_WIN32` alone makes LLVM-MinGW ignore the
  attribute and silently turns logger caches into process globals.
- After adding source checkout rules to `.gitattributes`, rematerialize the
  locked source tree with `core.autocrlf=false`; otherwise the index contract
  and the working bytes can disagree.
- The TLS close fix from PR 129 depends on the reciprocal shutdown machinery;
  do not cherry-pick the close-only change onto an older owner state machine.
- The exact LLVM-MinGW TLS 1.3 `send_buffer_and_close` scenario from PR 129
  passes when invoked directly. Do not globally enable
  `SALTSCORE_CNET_PRODUCTION_REQUIRED_MTLS_TEST` yet: its pre-existing TLS 1.2
  invalid-EKU negative case leaves the Python peer waiting for alert/EOF until
  its socket timeout, while the native server waits for the peer to close
  before its IOCP receive becomes terminal. CancelIoEx, graceful shutdown and
  abortive-close experiments did not establish a safe fix and were reverted;
  keep this as a separate fail-closed handshake-termination issue.
- `setup-re2c-tools` uses `actions/setup-python`, which narrows
  `PKG_CONFIG_PATH` to the hosted Python prefix. On Linux this hides native
  multiarch `.pc` files from vcpkg's `pkgconf`, even after the SDK packages
  are installed. Append `/usr/lib/$(dpkg-architecture
  -qDEB_HOST_MULTIARCH)/pkgconfig`, `/usr/lib/pkgconfig` and
  `/usr/share/pkgconfig` after the action, and probe the required PipeWire
  module before configure.
- The full Android preset must use `ANDROID_PLATFORM=android-26`. Capture's
  retained MediaProjection ABI calls `ANativeWindow_toSurface`, and its
  compiler guard intentionally rejects API 24; do not weaken that guard or
  add a lower-API fallback.
- The Intel macOS runner can provide `autoreconf` without Automake's
  `aclocal`. Install Homebrew `automake` and `libtool` before vcpkg configures
  libusb; otherwise a cleared binary cache fails before the Salts graph is
  generated.
- `SaltsCore.Native` publication stays inside the existing eight-RID LLVM CI.
  The tag run installs the already-qualified graph and packages those install
  trees; do not restore the removed standalone consumer/installer workflow or
  publish from a locally assembled SDK.

## 2026-11-01 downstream physical-owner audit

- `tools/audit_runtime_owner.py` is the Core-owned cross-platform parser used
  by CMeta's installed physical-owner audit and is referenced by
  `docs/M4-RUNTIME-ONE-OWNER.md`. Do not remove it as migration-only tooling;
  keep `tests/test_audit_runtime_owner.py` registered in the formal CTest graph
  so downstream source pins cannot lose the auditor silently.

## 2026-11-01 SIMD owner migration

- `Salts::SIMD` moved to SaltsUtils following qigao/salts-utils#732. SaltsCore
  0.1.1 must not build, install or export a second SIMD target. SIMDe remains a
  private base dependency because CNet Reed still uses its SSE2 facade.
- The next immutable package/tag is `SaltsCore.Native 0.1.2` / `v0.1.002`.
  Downstreams that own `Salts::SIMD` must reject the previous 0.1.0 package,
  which still exports that target.

## 2026-11-01 Serial module directory

- The active native Serial owner lives at `serial/`; `salts_serial/` is only
  the historical donor path recorded in frozen migration inventories and must
  not return as a root source directory. Public `salts_serial_*` ABI names and
  `<serial.h>` remain unchanged.
