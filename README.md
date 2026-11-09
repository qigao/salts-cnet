# SaltsCore network SDK

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

Set `SALTS_BASE_ROOT` to a matching released SaltsBase SDK (0.1.0 or newer). Configuration
uses only that root and fails if the package or its required components are
missing. Core thread, memory and IPC calls use SaltsBase's current public names
and headers; no compatibility aliases or private source paths are added.
CNet listener composition uses SaltsBase's installed `<native_io_accept.h>`.

Crypto links the required vcpkg `GmSSL::GmSSL` provider (`3.2.0#44`), including
the reviewed extensions pinned by `crypto/gmssl-extensions/source-lock.json`.
Like SaltsBase, this checkout consumes the preinstalled SDK published by
[qigao/vcpkg-cache v0.1.2](https://github.com/qigao/vcpkg-cache/releases/tag/v0.1.2).
Each supported triplet has a URL/SHA-256 lock in `cmake/dependencies/`.
Restore that lock with the release's `scripts/restore-native-dependency.py`;
set `VCPKG_INSTALLED_DIR` to the reported payload root and select its exact
`VCPKG_TARGET_TRIPLET`. For example, from this checkout:

```powershell
python "$env:VCPKG_CACHE_REPOSITORY_ROOT/scripts/restore-native-dependency.py" locked cmake/dependencies/qigao-x64-windows-llvm-mingw.lock.json --destination build/dependencies/vcpkg-windows-x64 --payload vcpkg_installed
```

Use the printed `root` value as `VCPKG_INSTALLED_DIR`. The restore validates
SHA-256, safely extracts the archive and records its provenance. This prefix
contains GmSSL 3.2.0#44, c-ares, KCP, zstd, SIMDe and SaltsBase's JPEG/libyuv
imports. `vcpkg.json` and `vcpkg-configuration.json` retain the dependency and
source inventory; configure no longer runs a vcpkg resolver or builds ports.
Missing packages fail configuration. Refreshing dependencies means reviewing
and updating the locks; there is no port-build fallback.

This uses the same prebuilt dependency owner as SaltsBase instead of rebuilding
an overlapping graph or depending on cache hits. It trades automatic manifest
resolution for explicit SDK updates and requires matching compiler/ABI assets.
Use a fresh configure when migrating from the previous toolchain model; do not
reuse a cache that still selects `vcpkg.cmake`. Compiler selection is independent:
LLVM-MinGW uses explicit target drivers, native LLVM uses `clang` from PATH,
and Android uses CMake's NDK support.

CNet remains the shared runtime owner of its linked Crypto/GmSSL implementation.
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

CI resolves the latest stable [SaltsBase release](https://github.com/qigao/salts-base/releases/latest).
It checks the release API's manifest digest, selects the exact platform/compiler
entry, checks the archive SHA-256 and extracts the SDK with Python's safe data
filter. The manifest records source and producer-CI provenance. It does not
require a build of moving master or consume expiring workflow artifacts.

Release 0.1.0 provides Windows x64 MSVC/LLVM-MinGW, Linux x64 Clang/GCC,
macOS ARM64, and Android arm64/x64 SDKs. It includes the public accept header
and the retained startup repairs. Its Core headers use `<core/...>`, ASN1 uses
`<asn1.h>` and `<asn1_value.h>`, and coroutine headers use `<salts/coro_*.h>`.
Consumers use these public headers directly without draft-layout aliases.

The existing Windows ARM64, Linux ARM64 and macOS x64 qualification lanes have
no matching SDK in 0.1.0. They fail with an explicit missing-platform error;
they do not select another architecture or skip tests. The sanitizer lanes use
the released Linux x64 Clang foundation and instrument this network graph;
that does not qualify the prebuilt foundation itself under sanitizers.

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
