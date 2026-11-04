# Independent TLS bulk/control workload

This #189 cohort compares direct NativeIO + production Crypto with CNet native
admission and an extra per-connection admission callback. Reuse the existing
Crypto TLS ABI and CNet TLS formal executables. Each process has one physical
TLS provider; do not link Crypto into the CNet executable or add a test project.

## Protocol before implementation

One fixed caller Owner progresses two independent TLS connections and both
peer ends. Each endpoint has its own 2-endpoint / 8-request / batch-4 NativeIO
backend: four backends total, budgets 8/32/16. This is not a shared-single-backend
cohort. Both modes use the production standard TLS profile, the same p384
CA/certificate/key and localhost SAN, NODELAY, 17-KiB TLS I/O and 32-KiB
plaintext receive capacity. Require matching authenticated versions/ciphers
at all four ends. Setup and handshakes finish before warm-up and measurement.

The shared private workload owns three canonical Core buffers: immutable 32-KiB
bulk, one-byte request and one-byte reply. The transport adapter retains one
reference per admitted logical send until local terminal; rejection retains
nothing. Raw retains plaintext through whole Crypto acceptance and complete
ciphertext transmission. Native buffers remain borrowed until actual matching
NativeIO completion; native prefixes may continue under new request identities.
Host owns each observer and routes its entire observed batch even after errors.

Bulk replenishes to depth 1 or 8 before each progress round. Depth 8 deliberately
attempts one additional write and requires ENOBUFS with unchanged references.
This is admission saturation, not an OS-pressure claim. Raw qualifies depth 1
without adding an application queue. A separate short raw case limits native
cipher writes to 4 KiB and requires actual continuation, not synthetic shorts.

Control permits one request/reply exchange at a time. The client sends a
sequence-derived byte; the server validates it and the host offers a derived
reply on a later ordinary host step. Receive callbacks only validate/update
state and never reenter CNet. RTT starts before request admission and ends when
the client validates the actual reply. Reuse waits for both local send terminals,
both receive validations and sole source references. At most one receive-demand
credit is outstanding per receiving end. Bulk receives validate every byte
across arbitrary TLS record/callback boundaries using the same shared code.

The Owner visits bulk client/server, then control client/server each round in
all modes. It keeps bulk offered until control exchanges, local terminals and
references are settled. Record actual bulk application bytes during that
interval, including partial logical writes. The offered rule is closed-loop;
different wrappers can perform different bulk work per control interval. This
is not a fixed open-loop rate or isolated wrapper-cost/fairness experiment.

Warm eight exchanges, seal replenishment, and drain all admitted bulk bytes and
local terminals before resetting counters. Measure 512 exchanges; five rotated
repetitions cover raw depth 1, native/callback depth 1 and native/callback depth
8. Existing formal TinyTest filters select one long case per fresh process.
Default CI uses eight measured exchanges in the six short scenarios. No extra
target, consumer/smoke project, CMake verification script or benchmark-only CI.

Record RTT p50/p95/p99, interval/process CPU, verified bulk bytes, admissions,
host rounds, refusals, scoped provider/policy calls, logical/backing peaks and
actual physical source capacities. Count native submissions separately for the
bulk and control connection pairs. Stop interval counters before draining the
remaining bulk; record its additional bytes/time. Process CPU includes both
ends of both TLS connections, host adapters, polling and validation. Provider
zeros do not instrument Crypto/GmSSL, NativeIO/global allocation or copies.

After each phase require all sources at refcount one, zero logical usage,
exact send terminals and every admitted byte received. Close each pair through
authenticated reciprocal close_notify, then require zero native requests and
endpoints before destroying clients/streams, contexts and backends. Keep parent
state, provider/callback contexts and all sources alive through complete cleanup.
Every loop has a deadline. On failure stop admission and attempt bounded native
drain; preserve the whole still-borrowed fixture if quiescence cannot be proved.
The reported close time sums the two sequential pair close/drain sections,
excluding object destruction between them, rather than a continuous wall interval.

This cohort supplies the independent TLS workload, not global allocation/copy
instrumentation or other-platform timing evidence. No production policy API or
optimization is justified merely by successful correctness tests.

Evidence: [Windows x64, 2026-11-04](benchmarks/cnet-tls-mixed-windows-x64-2026-11-04.md).

## TLS adapter memory instrumentation protocol

The follow-up uses private `BUILD_TESTING` diagnostics in the same production
`crypto_tls_stream.c` instance. The direct executable snapshots its Crypto
archive; the CNet executable calls a private bridge into its existing CNet DSO.
It does not link another Crypto archive. `BUILD_TESTING=OFF` builds expand the instrumented
sites to the original libc operations and contain no counters or bridge.

One calling thread owns a fixed-size, thread-local set of cumulative saturating
counters. Snapshots copy values, never reset, allocate, progress a stream or
borrow stream storage. No worker aggregation, cross-thread publication or
stream/context ownership change is introduced. Overflow invalidates a sample.
Allocation counters cover actual malloc/calloc/realloc requests in this source,
requested/successful request bytes, failures and non-null free calls. Realloc
bytes count the entire request, not net growth; releases do not establish live
bytes or leak freedom. Caller buffer initialization, calloc zeroing, realloc's
internal movement, GmSSL internals, NativeIO/Core/OS allocation, metadata struct
assignments and compiler-generated copies are outside this scope.

Copy counters distinguish explicit memcpy operations for metadata, native
cipher input into its ring, ring reads by the provider, provider output into its
ring, cipher output into native staging, record-header peeks, initial plaintext
delivery and pending-plaintext delivery. Ring splits count their actual two
source operations and byte lengths. Counts describe source operations, not
instructions, memory-bus traffic, encryption cost or a process-wide copy total.

Keep setup, warm control traffic, warm bulk drain, measured control traffic,
measured bulk drain and authenticated close/destruction as separate snapshot
deltas. Transfer/drain must perform zero adapter allocation/release or metadata
copy; their initial plus pending plaintext copies must equal the actual delivered
bulk/control bytes. Every existing byte/refcount/identity/terminal/drain check
still applies. Forced TLS 1.2/1.3 cases additionally verify over-capacity input refuses
before any input copy and three-byte plaintext reads account the short pending
remainder. The bounded direct short case combines 4-KiB native writes with
1,023-byte plaintext reads and requires both actual ciphertext continuation and
pending-plaintext delivery. Long samples retain the matched 32-KiB read capacity.
A formal worker case constructs/destroys a real stream and proves those counts
do not change the caller thread's snapshot.

Use the existing opt-in cases and rotation; output `TLS_ADAPTER_MEMORY_CSV` for
all six phases alongside the original timing rows. Treat these as a new
instrumented cohort and retain all repetitions. Do not pool their timing with
the previous uninstrumented copy workload. This closes the TLS adapter accounting
gap only; global/provider-internal allocation/copy and other-platform timing
evidence remain outstanding in #189.
