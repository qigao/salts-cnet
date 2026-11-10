# SaltsCore network SDK

## Upstream dependency versions

Select the upstream SDK release through `VCPKG_CACHE_VERSION` in the parent
environment (for example, by loading the local `.env`). Use the same version
for the `VCPKG_CACHE_REPOSITORY_ROOT` checkout. Values contain the version
without the `v` prefix; missing variables fail rather than choosing `latest`.
The shared `resolve-release` entry point is required (not present in v0.1.2).

The per-triplet files in `cmake/dependencies/` are release descriptors. Their
historical `.lock.json` suffix is retained; `source.kind=github-release`
distinguishes them from generated literal URL/hash locks. Resolve the selected
release into the build directory before restoring it:

```sh
python "$VCPKG_CACHE_REPOSITORY_ROOT/scripts/restore-native-dependency.py" resolve-release \
  "cmake/dependencies/$VCPKG_TARGET_TRIPLET.lock.json" \
  --output-lock "build/dependencies/$VCPKG_TARGET_TRIPLET.lock.json"
python "$VCPKG_CACHE_REPOSITORY_ROOT/scripts/restore-native-dependency.py" locked \
  "build/dependencies/$VCPKG_TARGET_TRIPLET.lock.json" \
  --destination "build/dependencies/$VCPKG_TARGET_TRIPLET-$VCPKG_CACHE_VERSION" \
  --payload vcpkg_installed
```

Set `VCPKG_INSTALLED_DIR` to the reported root for the selected preset. The
resolver requires the published asset's SHA-256 digest; the existing restore
checks downloaded bytes and preserves immutable installations. Changing a
version never overwrites an old SDK. CMake does not load `.env` or download
the dependency SDK implicitly. Existing host-tool package locks remain exact.

CI uses the same named repository Actions variables and selects local shared
actions from the chosen infrastructure checkout. SaltsBase and SaltsCore
prepare jobs resolve once, then distribute generated locks and verified blobs
to all matrix workers. Set the CI variables before enabling these changes;
the selected infrastructure release must contain `resolve-release`.

This keeps consumer version policy in the environment, asset digests in the
upstream release, and generated restore locks in build inputs. Updating a
release no longer requires editing a digest table for every platform. SDK
manifests, compiler/ABI selection and product tests remain mandatory. To roll
back, choose the previous exact release and restore into its own directory.

`SALTS_BASE_VERSION` selects the SaltsBase release and must match the
installed `SALTS_BASE_ROOT` exactly. The API compatibility floor stays
0.1.1; CI still validates the release manifest and successful producer.

The current example selects SaltsBase 0.1.3 and vcpkg-cache 0.1.3. When
upgrading, update the relevant nonsecret `.env` version and SDK-root fields
together, preserving credentials and other machine settings. The infrastructure
checkout must match its selected release; a dirty older checkout is not reset
or overwritten. Restore into a version-specific directory and use the reported
SDK root. After changing an SDK, compiler or triplet, configure explicitly with
`cmake --fresh --preset <user-preset>` so cached GmSSL/JPEG package locations
cannot retain the previous installation. Normal builds do not clear caches.


This checkout builds the `SaltsNet` CMake project. It owns Crypto, CNet and
SCTP. The installed package remains `SaltsCore` with the existing `Salts::*`
targets. The integration branch is `chore-housing-keeping`.

The foundation modules now belong to [SaltsBase](https://github.com/qigao/salts-base).
They are consumed as an installed SDK; this repository does not rebuild or copy
Core, NativeIO, ASN1, URI, TinyTest, Media or their implementations.

| Module | Public targets | Tests and support files |
| --- | --- | --- |
| `crypto/` | `Salts::Crypto` | `crypto/tests/{algorithms,asn1,tls,x509}` |
| `cnet/` | `Salts::CNet` | `cnet/tests/`, including owner, independent peers and static-owner fixtures |
| `sctp/` | `Salts::SCTPWire`, `Salts::SCTP`, `Salts::SCTPDTLS` | `sctp/tests/`, including private engines, independent peers and secure DTLS tests |

Each module adds its own test graph with `BUILD_TESTS`. `BUILD_BENCHMARK`
selects the existing optional measurement cases and requires `BUILD_TESTS`.
There is no root test aggregator or module-subset switch. Private SCTP engines
are built only with their module's tests. The SCTP public headers are
`<sctp_wire.h>`, `<sctp_session.h>` and `<sctp_dtls.h>`.

## Dependencies and ownership

Set `SALTS_BASE_ROOT` to a matching released SaltsBase SDK (0.1.1 or newer). Configuration
uses only that root and fails if the package or its required components are
missing. Core thread, memory and IPC calls use SaltsBase's current public names
and headers; no compatibility aliases or private source paths are added.
CNet listener composition uses SaltsBase's installed `<native_io_accept.h>`.
Socket creation, bind/listen, accept, readiness, address codecs, options,
shutdown and close use `<native_io_socket.h>` / `<native_io_transport.h>`.
CNet retains connection/protocol policy and adapts its existing public values;
it contains no first-party native socket I/O implementation. The c-ares provider
continues to own DNS protocol execution on the same progress owner.

This boundary requires the released [SaltsBase 0.1.1 SDK](https://github.com/qigao/salts-base/releases/tag/v0.1.1).
Version 0.1.0 lacks these headers/symbols and fails the package version check.
CI consumes immutable published SDKs; local builds can extract the same archives
into separate installation prefixes.

Crypto links the required vcpkg `GmSSL::GmSSL` provider (`3.2.0#44`), including
the reviewed extensions pinned by `crypto/gmssl-extensions/source-lock.json`.
Like SaltsBase, this checkout consumes the preinstalled SDK selected by
`VCPKG_CACHE_VERSION` from [qigao/vcpkg-cache](https://github.com/qigao/vcpkg-cache/releases).
Each supported triplet has an environment-selected descriptor in `cmake/dependencies/`.
Resolve it as described above, then restore the generated lock;
set `VCPKG_INSTALLED_DIR` to the reported payload root and select its exact
`VCPKG_TARGET_TRIPLET`. For example, from this checkout:

```powershell
python "$env:VCPKG_CACHE_REPOSITORY_ROOT/scripts/restore-native-dependency.py" locked build/dependencies/qigao-x64-windows-llvm-mingw.lock.json --destination build/dependencies/vcpkg-windows-x64 --payload vcpkg_installed
```

Use the printed `root` value as `VCPKG_INSTALLED_DIR`. The restore validates
SHA-256, safely extracts the archive and records its provenance. This prefix
contains GmSSL, c-ares, KCP, zstd, SIMDe and SaltsBase's JPEG/libyuv
imports. `vcpkg.json` and `vcpkg-configuration.json` retain the dependency and
source inventory; configure no longer runs a vcpkg resolver or builds ports.
Missing packages fail configuration. Refreshing dependencies means reviewing
and selecting an exact upstream release; there is no port-build fallback.

This uses the same prebuilt dependency owner as SaltsBase instead of rebuilding
an overlapping graph or depending on cache hits. It trades automatic manifest
resolution for explicit SDK updates and requires matching compiler/ABI assets.
Use a fresh configure when migrating from the previous toolchain model; do not
reuse a cache that still selects `vcpkg.cmake`. Compiler selection is independent:
LLVM-MinGW uses explicit target drivers, native LLVM uses `clang` from PATH,
and Android uses CMake's NDK support.

CNet remains the shared runtime owner of its linked Crypto/GmSSL implementation.
Its library output name is `cnet`, without a version suffix (`cnet.dll` on
Windows, `libcnet.so` on Linux, `libcnet.dylib` on macOS). This keeps it distinct
from SaltsBase's `salts` library. Link through the
existing `Salts::CNet` CMake target.
SCTP stays provider-independent; the explicit `SCTPDTLS` target composes it with
CNet. TLS verification, retained buffers, completion ownership, cancel/drain
and exact mode semantics are preserved. See [Crypto coverage](crypto/docs/SHANGMI-COVERAGE.md)
for the finite supported profiles and remaining qualification gates.

SaltsBase's package also resolves its Media archive's JPEG/libyuv dependencies;
the preinstalled dependency prefix supplies those imports without adding a Media implementation here.
Runtime paths include the selected vcpkg prefix, SaltsBase's runtime and, for
Windows llvm-mingw, the selected compiler's runtime directory.

## Build and test

Use the versioned `CMakeUserPresets.json`. Populate the required environment
inputs from [.env.example](.env.example); CMake does not load `.env` itself.
On Windows, enter the configured Visual Studio developer environment, or use
`cmake/WithVs.cmd` after setting `VSDEVCMD_BAT`.

```powershell
cmake/WithVs.cmd cmake --fresh --preset native-release-user
cmake/WithVs.cmd cmake --build --preset native-release-user
cmake/WithVs.cmd ctest --preset native-release-user --output-on-failure
cmake/WithVs.cmd cmake --build --preset install-native-release-user
```

POSIX LLVM uses `llvm-native-release-user`; existing sanitizer and Android
profiles remain in the user presets. CI configures the complete graph, builds
it without target filtering, and runs the formal tests through CTest. Android
is build-only unless an explicit device runner is provided.

For `llvm-mingw-arm64-release-user`, supply
`LLVM_MINGW_ARM64_SALTS_BASE_ROOT`, `LLVM_MINGW_ARM64_VCPKG_INSTALLED_DIR`,
and `LLVM_MINGW_ARM64_INSTALL_PREFIX` in the parent environment. Both SDKs must
target Windows ARM64; the preset selects `qigao-arm64-windows-llvm-mingw`
and `aarch64-w64-mingw32` independently of native x64 settings. Restore the
vcpkg SDK with `cmake/dependencies/qigao-arm64-windows-llvm-mingw.lock.json`.
SaltsBase v0.1.3 has no Windows ARM64 release asset, so a matching SDK must be
provided separately. After changing dependency roots, configure with
`cmake/WithVs.cmd cmake --fresh --preset llvm-mingw-arm64-release-user`
before building that same preset.

CI resolves the exact stable SaltsBase release selected by `SALTS_BASE_VERSION`.
The independent `prepare` job resolves it once, checks the release API's
manifest digest, and downloads the required SDKs from the canonical public
release asset URLs. The matrix lives in `.github/ci/sdk-matrix.json` and is
also the download plan: shared SDKs and dependency triplets are downloaded
once through the vcpkg-cache helper and addressed by SHA-256. The compiler
archive and exact infrastructure snapshot join the same prepared inputs.

An Actions artifact distributes these original archives to all nine jobs.
Qualification verifies the SaltsBase archive size/hash and safely extracts it;
dependency/compiler restores use `QIGAO_PREPARED_INPUTS` for offline restoration.
A missing or corrupt prepared blob fails rather than downloading another copy.
The source release manifest retains producer-CI and commit provenance. This
workflow-local distribution artifact carries released SDKs, not a build of
moving SaltsBase master. Host tools and test-oracle setup keep their existing
installation steps. This reduces duplicate source requests without adding
workflow/job retries or alternate-source recovery. The released downloader's
existing bounded transfer policy remains in effect; terminal failures stop preparation.

Release 0.1.3 provides Windows x64 MSVC/LLVM-MinGW, Linux x64 and ARM64
Clang/GCC, macOS ARM64, and Android arm64/x64 SDKs. It includes the public
NativeIO socket/transport/accept headers and the retained startup repairs. Its Core headers use `<core/...>`, ASN1 uses
`<asn1.h>` and `<asn1_value.h>`, and coroutine headers use `<salts/coro_*.h>`.
Consumers use these public headers directly without draft-layout aliases.

Core CI explicitly selects seven of those published platform/compiler SDKs: Windows x64 MSVC and LLVM-MinGW, Linux x64 GCC and Clang, macOS ARM64
Clang, and Android arm64/x64 NDK. Each lane selects its exact manifest entry;
no architecture or compiler substitution is performed. The two Linux ARM64 SDKs
passed producer CI; consumer ARM64 qualification is not yet in this matrix.
Windows ARM64 and macOS x64 still require producer SDKs.
ASan/UBSan additionally uses the ordinary Linux x64 Clang foundation and
instruments this network graph; that does not qualify the prebuilt foundation
under ASan/UBSan. TSan requires the matching `linux-clang-x64-tsan` SDK,
published in SaltsBase 0.1.2, so its shared synchronization is instrumented too.
There are nine qualification jobs covering eight released SDK profiles.

Android links Core's own `libcnet.so` with explicit 16 KiB maximum/common
page alignment, matching the Base 0.1.3 SDK. Both Android CI profiles install
through their existing user presets and inspect every installed ELF LOAD
segment for alignment of at least 16384 bytes. This checks SDK layout; Android
device execution and full application packaging remain separate qualification.

The historical fixed-tag `v0.1.002` eight-RID NuGet publisher has a broader
packaging contract and is not qualified by this seven-SDK matrix. It requires
its own coordinated release migration; changing this CI scope does not create
or replace a published package or tag.

## WebSocket SIMD measurements

CNet uses SaltsBase's public `<simd.h>` / `Salts::SIMD` to scan complete
16-byte ASCII runs during strict UTF-8 validation. Pending continuation bytes,
non-ASCII sequences and short tails retain the strict state machine. Loads stay
inside the borrowed payload; no padding, ownership change, allocation, new ISA
requirement or public API is introduced. Reed-Solomon's existing SIMDe kernel
is retained rather than replaced with per-operation abstraction calls.

The formal `cnet/tests/websocket_utf8_test.c` covers alignment, block boundaries,
invalid scalar values, incomplete sequences, fragment state and protected page
ends. The optional `websocket_utf8_benchmark.c` measures the public send path
with a synchronous memory sink. It includes validation, framing and copy;
binary sends provide a same-copy control. It does not measure network throughput.

```powershell
cmake/WithVs.cmd cmake --preset native-benchmark-user
cmake/WithVs.cmd cmake --build --preset native-benchmark-user
cmake/WithVs.cmd ctest --preset native-benchmark-user -R ^saltscore_websocket_utf8_benchmark$ -V
```

Measured on Windows x64 (AMD Ryzen 9 7940HX), LLVM-MinGW Clang 23.1.4 Release,
SaltsBase 0.1.0 and
the locked v0.1.2 dependencies. Each case uses seven samples of approximately
16 MiB, with initialization and assertions outside timing. Baseline is the
scalar validator from `5f330f7`, with the same benchmark and dependencies.

| Payload | Scalar MiB/s | SIMD MiB/s | Change |
| --- | ---: | ---: | ---: |
| ASCII, 64 bytes | 1547.06 | 1832.26 | +18.4% |
| ASCII, 2048 bytes | 2740.83 | 3564.30 | +30.0% |
| ASCII, 65536 bytes | 2782.69 | 3557.09 | +27.8% |
| Mixed ASCII / three-byte UTF-8, 65536 bytes | 2055.83 | 2708.02 | +31.7% |
| Three-byte UTF-8 only, 65535 bytes | 1120.66 | 1053.90 | -6.0% |

The pure multi-byte case does not use the fast path and showed a decrease;
sample ranges overlap (scalar 13.956–15.090 ms, SIMD 14.204–16.076 ms).
The 64 KiB binary control measured 61198.84 / 59350.33 MiB/s. These observations
support ASCII-heavy workloads on this host, not a universal speedup or a claim
for other CPUs/platforms. Revert the ASCII block alone to roll back this
optimization; the dependency and public API contracts remain unchanged.

## Integration and rollback

This branch retains the module split while carrying forward the Crypto/CNet/
DTLS/SCTP changes through merged master `ffade4c280286e247ea67733432b6fd9226fb5e1`,
including #274/#275/#277 and their formal regression cases. Tests, fixtures and
registration move together; the independent Go peers require Go 1.26.10.
Shared fixtures retain one owner: Crypto owns direct TLS helpers and PKCS12
creation; CNet owns the independent protocol peers reused by policy tests.

Media/#197 is a reference-only draft in its separate branch. Its Frame V2/GPU
proposal is not integrated into this network SDK and has no release or device
qualification claim. Issues #188/#219/#276 retain their independent gates.

Rollback the repository split as a coordinated SDK/configuration change, with
separate installation prefixes. Do not restore removed modules beside their
SaltsBase owners or install parallel compatibility implementations.
