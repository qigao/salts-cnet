# Native test ownership and TinyTest gate

This repository uses **one** C11/C++17 test framework: `Salts::TinyTest`.
CTest schedules the real native executable tests, platform matrix, timeouts,
resource locks, and external Python/formal test drivers. It is not a second
unit-test assertion framework.

## Native test admission

- `BUILD_TESTS` controls native test registration. TinyTest is an unconditional
  module; there is no separate framework or module-selection switch.
- The project declares `Salts::TinyTest` before any first-party module's
  native source-owned tests. All registered C/C++ native behavior test
  executables in the default Core graph link this target.
- Native test suites must register real `spec/it` or
  `TEST_CASE/SECTION` cases. Zero registered specs, zero discovered cases,
  and explicit filters matching no cases return failure, never a false green.
- Compile-only/static ABI/source-parity checks, Python external TLS peers and
  Promela/formal tests use their original mechanisms under CTest.
- Source/fixture/CMake changes trigger the existing unified LLVM CI. No extra
  installer/consumer test projects, probe CMake jobs or test runtimes.

## Module-owned test layout

Each module owns its test sources and CMake registration in `tests/` (or its
existing `test/` directory). The module adds that directory under `BUILD_TESTS`;
the package root assembles modules without a separate test aggregator.

Core, Platform, Concurrency, Coroutine, NativeIO, FS and Process own their
corresponding runtime suites. Crypto owns direct GmSSL/TLS tests and certificate
fixtures in `crypto/tests/`. CNet owns transport integration and dynamic-owner
tests in `cnet/tests/`, including `owner/` and `crypto-static/`; its URI parser
tests live in `cnet/uri/tests/`. CSerde, Unicode, IDNA and TinyTest register their
existing source-owned suites locally. Repository-wide build/migration policy
tests live under `cmake/tests/migration/`.

This replaces the root `tests/CMakeLists.txt` and `tests/native-modules`
aggregators. Keeping those aggregators would leave registration, fixture paths
and directory-scoped CTest properties detached from the code owner. Existing
target names, CTest names, platform guards and assertions are retained; shared
TLS workload support has one owner in `crypto/tests/tls/`. Reverting this layout
requires moving both the files and their registrations together, rather than
adding forwarding directories or duplicate tests.

## Ownership-sensitive integrations

The following tests have an original entrypoint whose exact return code,
external subprocess protocol, `goto cleanup` unwinding, thread joining or
loader lifetime is part of the test oracle. Their native driver runs as a
registered TinyTest case; its **original** exit code is checked after the
native owner has completed its cleanup.

- Real CNet TLS CA/SAN positive/negative tests, two-plugin CNet owner
  identity, CNet static-Crypto test-only Owner, and shared Crypto DSO loader
- Actual Process spawn/reap, native FS rooted files, mmap and Serial PTY
- Existing X.509 P-256/P-384 and historical SaltsNet certificate fixtures

External process modes (`--core-child` with exit code **19**, CNet Python
`--mtls` and `--external-san`) retain their original output and exit
semantics; they **bypass** TinyTest's reporter intentionally, because the
external peer is an independent test process.

FS and Process boundary regressions use the same `saltscore.fs_owner_and_root`
and `saltscore.process_spawn_reap` CTest registrations. Run them from the prepared
toolkit environment (use `llvm-native-release-user` on Linux/macOS):

```sh
ctest --preset native-release-user -R '^saltscore\.(fs_owner_and_root|process_spawn_reap)$'
```

FS covers independent directory scans spanning multiple
native buffers, directory rename identity and rejection of non-regular files;
its POSIX FIFO case must complete without a writer. Process covers stdin EOF
with another child alive, all seven POSIX combinations of closed standard
descriptors, exec-error reporting, and descendant pipe EOF after a non-shell
root exits. Pipe EOF also works when a POSIX descendant is dead but has not yet
been reaped by the system; PID existence alone cannot establish that boundary.

Each spawn owns its process group/Windows Job Object. Remaining members are
terminated when the root exits, before publishing its result. POSIX descendants
that leave the owned process group are outside that ownership. POSIX retains
the exited root with `WNOWAIT` until group cleanup, so cleanup never acts on a
reaped/reused PGID. Linux uses
atomic close-on-exec pipe creation; platforms without `pipe2` serialize this
module's pipe setup and fork. Windows Process DLL naming follows the same ABI
epoch as FS for both MSVC and llvm-mingw. Existing applications that imported
the old unversioned llvm-mingw Process DLL must relink against the rebuilt SDK.

On Windows, root-directory enumeration opens a fresh native directory object
relative to the retained handle using an empty `NtCreateFile` name. This keeps
the admitted identity after rename and separates scan state. `DuplicateHandle`
shares the original object's scan; `ReOpenFile` returned access denied for this
directory in the native regression. Guest relative paths still reject empty
names. The 240-entry interleaved-scan and host-rename cases pass on Windows
llvm-mingw; POSIX-specific regressions require Linux/macOS execution.

The asynchronous FS/Process extraction has these additional formal CTest entries:

| Test | Behavioral coverage |
|---|---|
| `saltscore_fs_async_test` | Copied paths, bounded metadata/directory operations, close/cancel, reentry and initialization failure |
| `saltscore_fs_watch_test` | Real native events, rename, rescan/acknowledgment, overflow, shutdown and initialization failure |
| `saltscore_fs_file_test` | Shared/private runtimes, positional binary I/O, EOF/short reads, capacity, scoped cancellation, completion races, MPSC producers and lifecycle |
| `saltscore_fs_async_cpp_test` | C++ public FS service/watch/file handles and signatures |
| `saltscore_process_async_test` | Binary standard streams, independent stderr, partial reads/EOF, queued/in-flight cancellation, bounded admission, shell mode and close/drain |
| `saltscore_process_async_cpp_test` | C++ Process and Shell header contracts |
| `saltscore_shell_test` | 256 KiB duplex input, binary capture, shared output quota, timeout, blocked stdin, cancellation, environment/cwd and nonzero exit |

Use the prepared preset environment (including the configured compiler runtime
on `PATH`):

```sh
cmake --build --preset native-release-user
ctest --preset native-release-user -R '^(saltscore_fs_.*_test|saltscore_process_async(_cpp)?_test|saltscore_shell_test|saltscore[.](native_io|fs_owner_and_root|process_spawn_reap))$'
ctest --preset native-release-user
cmake --build --preset install-native-release-user
```

The Shell registration intentionally sets its working directory to
`process/tests` and supplies a parent sentinel environment variable; its cwd
and clean-environment regressions depend on both fixtures. The async Process
test executable has a private child mode that bypasses the test reporter.
Accepted buffers and callback probes live through failure cleanup as well as
successful completion. Every owning test closes, drains and destroys its
resources before releasing borrowed storage.

Windows llvm-mingw runs cover IOCP files/pipes and the Windows directory watcher.
POSIX source and CMake selection are reviewed here, but this Windows host has
no Linux/macOS runtime; io_uring, Darwin AIO, inotify and FSEvents execution and
Android/iOS cross-build qualification are unverified locally.

Local result on 2026-11-08: `native-release-user` full build succeeded; all ten
FS/Process/NativeIO registrations in the focused command passed. The retired
runtime-owner auditor's parser test and CTest registration have been removed.
After removal, the full `ctest --preset native-release-user` run passed 182/182.
The normal `install-native-release-user` preset succeeded at the configured
`C:/projects/cpp/external/pkg/salts-core/release` prefix, including the new
public headers, libraries and SDK export set. No separate consumer project was
created. Executable API examples, including failure cleanup, are the formal
[file tests](../fs/tests/test_fs_file.c),
[process stream tests](../process/tests/test_process_async.c) and
[Shell tests](../process/tests/test_shell.c).

SCTP real Owner handoff, Provider DSO and opaque Session DSO tests must join
their actual POSIX worker threads and prove drained/destroyed/unloaded state
from TinyTest's main test thread. Internal worker/callback invariants retain
**process-fatal** assertions. They must never attempt TinyTest C's `longjmp`
from a foreign OS thread or from code whose DSO could unload. A future
per-assertion diagnostic migration requires a synchronized failure recorder
that cannot strand a mutex, leave callback code in-flight, or mask the
original process-failure contract.

## Original CNet Crypto qualification

The existing `cnet/tests/crypto-static` graph remains **test-only**. Its
independent M5 static Crypto Owner TLS1.2/1.3 and M6 two-plugin shared DSO
cases do **not** establish that production CNet has fully switched to
Crypto TLS/TLCP. The current architecture remains tracked in Issue #147;
historical Issue #81's closure does not certify that cutover.

The additive opaque Crypto TLS v1.4 `crypto/tls_close.h` provides a
read-only, authenticated reciprocal peer `close_notify` signal. The private
GmSSL adapter reports it **only** after TLS1.2 MAC or TLS1.3 AEAD validation
and parsing of the peer's actual alert. The test-only CNet adapter continues
to read buffered close ciphertext after it sends its own alert. TCP EOF,
local output, fatal alerts and `CRYPTO_TLS_CLOSED` alone are NOT evidence.
The independent Issue #152 owns the complete negative shutdown/cancel gate.
A green M5/M6 test-only graph does not imply full public production CNet TLS
provider cutover.

For real source-tree acceptance inside the **existing** native project,
after setting the required vcpkg/LLVM environment for the shared public preset
(the example below uses POSIX LLVM; Windows uses `native-release-user`):

```sh
cmake --preset llvm-native-release-user
cmake --build --preset llvm-native-release-user
ctest --preset llvm-native-release-user --output-on-failure
```

CI installs the complete autotools host prerequisites (autoconf,
autoconf-archive, automake and libtool), including on Android's Linux hosts.
The formal Python TLS tests use CPython 3.12 and cryptography 46.0.3 binary
wheels, which cover Windows ARM64 and Intel macOS as well as the other native
lanes. The setup-python interpreter is selected through the runner's PATH. Missing wheels
fail installation immediately; fixture setup never starts an OpenSSL/Rust
source build. This Python dependency is test-only and is not part of the SDK.

All existing native CI lanes, including sanitizers, enable M5/M6 and the
production Python TLS/mTLS/SAN tests. Android remains compile-only. The
existing provider TinyTest suite also establishes real TLS1.2/1.3 CipherBIO
pairs and checks reciprocal alerts, EOF, truncated/corrupt records, cancelled
sessions, and sticky terminal errors. Production Python peers independently
exercise valid mTLS, raw half-close, truncated/corrupt close_notify, encrypted
fatal alerts, and reciprocal application/final-send closure for both versions.
Each native failure must publish one terminal and drain before destruction.

Python server-process diagnostics go to private temporary files: an unread
stderr pipe can block certificate rejection before the TLS alert is sent,
making a valid negative test look like an IOCP protocol hang. Failure reports
include bounded phase/status and source-line metadata rather than certificate
dumps. All these cases remain inside the existing formal CMake/CTest graph.
Issue #152 still requires exact-head platform CI acceptance; local success
alone does not close it or qualify the complete production provider cutover.

The obsolete `crypto/tests/x509/standalone` project was removed with the
independent ASN1 package. Its certificate inspection and migrated fixture cases
remain in `crypto.x509.real_der_and_negative` and
`crypto.x509.migrated_saltsnet_fixture` in the root-owned formal graph.
The obsolete `sctp/tests/independent/dtls` consumer project was also removed;
its referenced `dtls_records.c` no longer exists. The root-owned
`saltscore.sctp_dtls_native` test retains the native SCTP/DTLS peer and
independent Go peer suite. Independent peer tests remain part of the module's
formal graph rather than separate package configuration projects.

## CI dependency and compiler caches

The LLVM workflow persists the shared action's writable local vcpkg binary
cache and `VCPKG_DOWNLOADS` with GitHub Actions cache. The remote NuGet feed
remains read-only. Each OS/architecture, matrix lane, preset and shared cache
revision has its own namespace. Runner image, Windows LLVM-MinGW version,
dependency manifests, options, presets and workflow changes produce a new
save key. Earlier entries in that namespace can seed a new run; vcpkg still
checks package ABI hashes before reuse.

CMake configure always resolves and installs the requested dependencies.
After successful configure, CI saves a new cache entry before building and
running the formal CTest suite, so a later project failure does not discard
newly compiled dependencies. Exact cache hits are not uploaded again. The
cache contains only downloads and binary archives, not CMake build trees,
installed SDKs or the temporary NuGet credentials. A cold or evicted cache
still requires normal dependency downloads/builds; vcpkg itself is set up by
the existing shared action on every runner.

The same workflow installs ccache 4.14.2 from checksum-pinned official native
archives, including Windows ARM64, and sets CMake's C/C++ compiler launcher
environment for configure. Each lane keeps a separate compiler cache, bounded
to 256 MiB. Its key includes the dependency/toolchain configuration and commit;
the restore prefix reuses earlier commits with the same configuration. Ccache
also checks compiler contents, command lines and source/header inputs. Normal
linking and formal tests still run. CI resets statistics before configure,
reports hits/misses after build, and saves successful compilations before tests.

## Merge gate

Require the **exact PR HEAD**, not an earlier green commit: Linux/macOS/
Windows x64/ARM64 native test execution, Linux ASan/UBSan and TSan tests,
and Android build coverage. Do not count a green compile-only job as a runtime
test. An optional qualification is verified only when its options are
actually enabled, its targets built, and its CTest cases executed.

Do not merge or publish a Draft solely because the default graph is green.
