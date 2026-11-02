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

The standalone `sctp/tests/independent/dtls` and
`crypto/tests/x509/standalone` CMake projects predate this migration and
remain **outside** the default first-party native graph. They are external
independent/installed-consumer drivers, not a reason to add a new consumer
project or test framework to the Core build. Their retirement/in-tree
rehosting must preserve the actual independent peer oracle and owner boundary
rather than dropping the behavior to satisfy a CMake naming rule.

## Merge gate

Require the **exact PR HEAD**, not an earlier green commit: Linux/macOS/
Windows x64/ARM64 native test execution, Linux ASan/UBSan and TSan tests,
and Android build coverage. Do not count a green compile-only job as a runtime
test. An optional qualification is verified only when its options are
actually enabled, its targets built, and its CTest cases executed.

Do not merge or publish a Draft solely because the default graph is green.
