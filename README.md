# SaltsCore

**Status: bootstrap / Draft qualification. Not a production replacement yet.**

SaltsCore is an independently built **C11 foundation SDK**. It does not depend
on the historical `qigao/salts`, `qigao/salts-utils`, CMeta, CFlow, or CSTL
packages. Development is tracked by [migration epic #1](https://github.com/qigao/salts-core/issues/1).

The original M0 bootstrap implements an **owned-by-caller, non-owning counted byte view**
in `Salts::Core`. The stacked M1/M2 migration candidate adds
`Salts::Platform` (clock, OS CSPRNG, thread/synchronization) and
`Salts::Concurrency` (SPSC, bounded deadline queue, RCU, Disruptor,
ThreadPool and Leader/Followers). The next stacked candidate adds
`Salts::Coroutine` (the original minicoro-backed lifecycle, pool and
bounded sharded executor). These are imported from exact Salts sources and
have no CMeta/CFlow dependencies. The next Core foundation slice extracts
`mem_buffer_t`, `mem_slice_t` and the bounded slab allocator and the original single-owner bipartite `ring_buffer`
from old `salts/utils`, with only the independent Platform synchronization API. A further stacked candidate moves the
original NativeIO backend and Sharded/IPC ownership to
`Salts::NativeIO` (IOCP, epoll, io_uring, kqueue); the ACE completion-token
adapter remains in Salts and is not installed by Core. They require exact-head Linux/Windows/macOS
CI and installed C11/C++17 qualification before this candidate is accepted. It is not yet a replacement for any
published `Salts::Core` binary, and no old APIs or CMake aliases have been
cut over.

## Source layout and original module ownership

The optional `media/` module compiles the existing native Capture and Playback implementations into a single `Salts::Media` static archive. It keeps the existing C headers and symbol names but has no legacy CMake target aliases.

The repository root has **no** catch-all `include/` or `src/`. Each
existing module owns its own source and header tree:

- The explicitly retained `core/include`, `core/src` hold the Core byte and
  pool foundation and the **only** native `base64_utils.h` / `tn_base64_*`
  implementation. `fs/include, fs/src` and `process/include, process/src`
  retain their selected module names.
- `platform/`, `concurrency/`, `coroutine/`, `native-io/`, `cnet/`
  and `uri/` keep their existing names and private/public layout.
  The generated URI grammar remains under `uri/parser/`, and SCTP retains
  its independent `sctp/` subtree.
- Already-owned `unicode/`, `idna/`, `cserde/` and `tinytest/`
  keep their own layouts. Migration does not create source-path shims,
  duplicate providers or old module aliases.

The **installed** C11/C++17 SDK maintains documented include spellings
(`<base64_utils.h>`, `<random.h>`, `<cnet/cnet.h>`) and
`Salts::*` target identities; flat installed includes do **not** imply
flat root source ownership. `tools/check_module_layout.py` gates this
invariant on Linux, Windows and macOS.

## Default and optional modules

| Mandatory | Optional on supported platforms |
|---|---|
| Core byte views, Platform, Concurrency, FS, Coroutine, NativeIO, ASN1, Crypto, URI, CNet | Process, Unicode, IDNA, Serial, Media (Capture + Playback) |

Unicode stays pinned to Unicode 17.0.0 with re2c as a **build-time** tool only;
IDNA depends only on the new Unicode module. FS and Process are native system
components; they **must not require** CFlow IO Actors or CMeta Reflection.
Advanced CMeta/CFlow/CSTL/Component/ACE functionality remains in `qigao/salts`
and consumes the new Core, never the other way round. The plain CNet transport
implementation is part of the default Core candidate; CMeta/ACE-specific
CNet integrations stay in Salts. Enabling a module does not establish its
cross-platform or release qualification.

See [architecture](docs/ARCHITECTURE.md) for ownership and migration gates.

## Default local Crypto and CNet build (Draft)

The default graph builds the whole CNet transport source tree, including the
original IPC FIFO, peer index and native-path changes. Production CNet links
the first-party static `Salts::Crypto` facade and the **separately installed**
vcpkg `GmSSL::GmSSL` static library (GmSSL 3.2.0#26). No local native GmSSL
source mirror is compiled into `Salts::Crypto`; Ed448 remains first-party
under `crypto/vendor/libecc/`. CNet is the single production DSO owner of the
linked native TLS implementation; two independently loaded plugins must import
CNet instead of copying GmSSL/Crypto static archives.

Installed `find_package(SaltsCore CONFIG REQUIRED)` imports the shared runtime
without loading the separate static Crypto package or locating GmSSL. CMeta
and other shared-runtime users need only the Core SDK. Programs that directly
link `Salts::Crypto` must explicitly `find_package(Crypto CONFIG REQUIRED)`
and provide that static package's declared dependencies. CNet's private TLS
implementation and the Core source-build dependency graph are unchanged.

Use CMake 3.21 or newer, a C11 compiler, and a C++17 compiler when testing.
Provide the canonical pinned c-ares, KCP and SIMDe dependencies and an installed
host re2c 4.6 with the pinned Unicode 17 data. The checked-in manifest makes
these base dependencies mandatory. The `cnet` feature remains an empty
compatibility feature and does not control the production target:

```sh
python3 crypto/tools/check_local_native_source.py
cmake -S . -B build-cnet -DBUILD_TESTING=ON \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/verified-vcpkg-toolchain.cmake
cmake --build build-cnet --parallel
ctest --test-dir build-cnet --output-on-failure
```

### Mandatory native unit test framework

When `BUILD_TESTING=ON`, the source graph requires
`SALTSCORE_BUILD_TINYTEST=ON` and fails configuration if it is disabled.
C11 native test suites include `tinytest.h`; C++17 suites include
`tinytest.hpp`; their executables link `Salts::TinyTest` and register
real `spec/it/check` cases. CTest remains the sole runner for timeouts,
sanitizers and platform test selection. No private `spec/it` facade or
separate unit-test harness is permitted; empty suites and missing case
filters must return failure.

The existing Linux native and TSan LLVM jobs enable
`CNET_SCTP_TEST_OWNER_THREADS=ON` to run the actual POSIX Owner,
Provider DSO and opaque Session DSO lifecycle tests. Worker-thread
fatal invariants remain process-fail-closed; TinyTest checks joined
owner/post-unload state from the main test thread. These are not
synthetic consumer or installer projects. With `BUILD_TESTING=OFF`,
production-only consumers may explicitly disable the TinyTest library.

The checked-in vcpkg manifest declares GmSSL and CNet dependencies directly.
Compiler, ccache, host-data and dependency setup Actions use published
`qigao/vcpkg-cache@v0.1.6`, which supplies native Windows pkg-config and
preserves `PKG_CONFIG` in vcpkg's
port environment. The manifest requests `pkgconf` only on non-Windows targets;
Windows uses that native host tool without acquiring pkg-config from MSYS2.
The custom registry selects `reference: v0.1.6` and pins baseline
`e5ce681a8d95f5330999dad66f4ea33214d7faff`. GmSSL 3.2.0#26
includes TLS 1.2 negotiation, RSA-PSS, enabled ShangMi algorithms, SM9 retry/secret
cleanup, TLCP dual-key/signature-extension fixes and mandatory TLS 1.3 KeyUpdate
responses with correct partial-write continuation, cipher/version filtering
and signature-policy enforcement; its complete port tree is
pinned in the Crypto source lock. The USB module and its libusb dependency
have been removed from the SDK. The remaining dependency graph does not
request the libusb Autotools/MSYS2 tool bundle.

CI must use the shared `qigao/vcpkg-cache` setup Actions. Normal builds set
`restore-packages: "false"` and restore vcpkg binary/download caches through
GitHub Actions before configuring the complete `cnet,media,zstd` graph.
vcpkg builds missing ABI packages from the pinned manifest and saves them to
the local files cache; CI preserves that cache after configure, before product
builds and tests. Cache misses are supported; dependency build errors fail the
job. These Actions caches are repository-scoped and do not share package bytes
with cmeta or salts-utils. Compiler-cache restoration is independent of registry
revisions. Publishing dependency packages to a shared feed is a separate operation.

An unavailable dependency fails configuration, without substituting another
TLS provider or an implicit transport fallback. Local source ownership does
not make the retained GmSSL-derived implementation third-party-free. Exact
current-source platform CI, TLS/CA/SAN and independent peer tests, sanitizers,
and physical runtime ownership still gate acceptance.
No downstream cutover or production release is implied by this candidate.

## Local build

```sh
cmake --preset native-release-user
cmake --build --preset native-release-user
ctest --preset native-release-user
```

The parent environment supplies the vcpkg and LLVM chainload toolchains,
triplets and install prefix consumed by the preset. Missing inputs fail at
configure time. Installed-consumer and smoke projects are intentionally not
part of the build or CI contract.

The standalone install exports `Salts::Core` through
`find_package(SaltsCore CONFIG REQUIRED)`. Optional targets will be exported
only when their independent implementations and platform gates are qualified.

## Native LLVM thread and scheduler contract

The mandatory TinyTest / CTest division, exact native module ownership,
worker-thread failure rules, and opt-in original CNet Crypto test admission are
documented in [Native Test Ownership](docs/NATIVE-TESTING.md).


The unified CI workflow uses the shared vcpkg-cache compiler setup on
Linux/macOS x64 and ARM64 (runner-native Clang), and Windows x64 and ARM64
(llvm-mingw/UCRT 20261020). It builds the complete configured graph and runs
its formal native CTest suite. The workflow does not build installer/consumer
projects or run compiler/source preflight probes.

Platform public declarations explicitly export/import their one shared DLL
owner, including native thread, clock, random, readiness and fast-key APIs.
The coroutine scheduler uses the same compiler-selected thread-local storage
contract as Platform/Executor. The existing coroutine test overlaps two live
OS threads and verifies that each sees only its own scheduler, then restores
an empty current-scheduler state on thread exit.

The migration integration must pass the same full native graph before a
The 0.1.002 source release carries the flattened public headers. SIMD execution
is owned by SaltsUtils and
is no longer built or exported by SaltsCore.
