# Native test ownership and TinyTest gate

This repository uses **one** C11/C++17 test framework: `Salts::TinyTest`.
CTest schedules the real native executable tests, platform matrix, timeouts,
resource locks, and external Python/formal test drivers. It is not a second
unit-test assertion framework.

## Native test admission

- `BUILD_TESTING=ON` requires `SALTSCORE_BUILD_TINYTEST=ON`; turning the
  component off is a configuration error rather than silently deleting cases.
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

SCTP real Owner handoff, Provider DSO and opaque Session DSO tests must join
their actual POSIX worker threads and prove drained/destroyed/unloaded state
from TinyTest's main test thread. Internal worker/callback invariants retain
**process-fatal** assertions. They must never attempt TinyTest C's `longjmp`
from a foreign OS thread or from code whose DSO could unload. A future
per-assertion diagnostic migration requires a synchronized failure recorder
that cannot strand a mutex, leave callback code in-flight, or mask the
original process-failure contract.

## Original CNet Crypto qualification

The existing `tests/cnet-crypto-static` graph remains **test-only**. Its
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
after setting the required vcpkg/LLVM environment used by the CI presets:

```sh
cmake --preset ci-native \
  -DSALTSCORE_TEST_CNET_CRYPTO_QUALIFICATION=ON \
  -DSALTSCORE_CNET_PRODUCTION_REQUIRED_MTLS_TEST=ON \
  -DSALTSCORE_CNET_M6_SHARED_DSO_TEST=ON \
  -DSALTSCORE_CRYPTO_TEST_FIXTURES="$PWD/crypto/tests/fixtures"
cmake --build --preset ci-native
ctest --preset ci-native --output-on-failure
```

CI installs the complete autotools host prerequisites (autoconf,
autoconf-archive, automake and libtool), including on Android's Linux hosts.
The formal Python TLS tests use CPython 3.12 and cryptography 46.0.3 binary
wheels, which cover Windows ARM64 and Intel macOS as well as the other native
lanes. CMake receives that exact setup-python interpreter. Missing wheels
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

The pre-existing standalone drivers are reconciled in the root test graph:

| Legacy driver | Preserved behavior and current owner |
| --- | --- |
| `crypto/tests/x509/standalone` | The two existing TinyTest executables compile the actual `crypto_x509_der.c` and link only ASN1/TinyTest. Real P-256/P-384, malformed DER, concatenated chains and the SaltsNet fixture retain the provider-free link boundary. |
| `media/capture/tests/native_tsan` | The root TSan preset builds five TinyTest cases against the one instrumented `Salts::Media` archive, including miniaudio. A private PulseAudio null monitor supplies synthetic PCM. Fresh cycles, same-device restart, blocked-callback stop/destroy and invalid device/format rejection remain tested. |
| `sctp/tests/independent/dtls` | Removed under the explicit no-OpenSSL/BoringSSL-link policy. Its encrypted-record, fingerprint/exporter and DTLS-bound generation evidence is retired, not relabeled as plaintext coverage. Production replacement remains #188. |
| Pion SCTP peer | The OpenSSL DTLS mode was removed; original UDP I-DATA/I-FORWARD loss/recovery cases run as two CTests in Linux x64 CI. Unsupported legacy DTLS arguments fail. |

Capture's fixture script owns only the private virtual audio service and PCM
feeder; CTest owns the test invocation/status. It neither configures another
project nor invokes nested CTest or installed SDK/linkage checks. Each Capture
TinyTest case runs in a fresh copy of the formal executable, so a failure
cannot return past stack storage still borrowed by a live native callback.
No physical audio source is admitted. Missing requested tools fail configure.
Python `ssl`/`cryptography` and separate CLI peers remain permitted independent
test processes; no project target links OpenSSL/BoringSSL.

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
