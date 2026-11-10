# TLS adapter allocation and copy counts — Windows x64, 2026-11-04

Measured source: `36c740dfe8a0e373b427341c469913b52a914174`.
[All 150 phase rows](cnet-tls-adapter-memory-windows-x64-2026-11-04.csv) and
[25 corresponding timing rows](cnet-tls-adapter-memory-timing-windows-x64-2026-11-04.csv)
preserve collection order. Later changes add evidence and clarify comments;
they do not change executable code. The
[protocol](../CNET-TLS-MIXED-BENCHMARK.md#tls-adapter-memory-instrumentation-protocol)
defines the measured boundary and ownership.

## Reproduction and qualification

Windows 11 10.0.26200, AMD Ryzen 9 7940HX, 16 cores/32 threads, without
affinity, frequency or background-load control. LLVM-MinGW 20261020, Clang
23.1.4 (`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`),
x86_64-w64-windows-gnu; full `native-release-user` Release graph.
Canonical vcpkg-cache v0.1.5 (`f1caf997152e4830d7e1089fceaf77aa9127ec25`),
unchanged GmSSL 3.2.0#18 port tree `3b06c785649c2cd632c319375e9bc08e53296b39`.
The full build restored no new dependency and passed all six relevant
Crypto/CNet TLS/mTLS CTests in 11.66 seconds, including the independent Python
peers. The unfiltered direct suite passed 20 cases / 668 assertions; the CNet
suite passed 11 cases. New assertions cover TLS 1.2/1.3 input rejection and
pending plaintext, actual bounded native continuation, thread-local isolation,
byte/copy accounting and phase-local allocation behavior.

Use the existing opt-in TinyTest cases and filters described in the protocol:
`SALTSCORE_NATIVE_TLS_MIXED_BENCHMARK=1` and
`cnet_TLS_MIXED_BENCHMARK=1`. Five fresh-process repetitions rotate
direct depth 1, native depth 1, callback depth 1, native depth 8 and callback
depth 8. Each sample warms eight control exchanges, drains, then measures 512.
All 25 selected formal cases passed; direct invocations filter 25 other cases,
CNet invocations filter 31. These selected measurements do not replace the
unfiltered qualification suites. No extra project, target, consumer/smoke
check or CMake verification script was added.

One caller Owner drives both ends of two independent TLS connections, using
four 2-endpoint / 8-request / batch-4 backends, aggregate 8/32/16. All four
ends in every row negotiated TLSv1.3 / TLS_AES_128_GCM_SHA256. Certificates,
verified localhost SAN, NODELAY, 17-KiB TLS I/O, 32-KiB plaintext receive
capacity and offered workload match the previous mixed TLS cohort. The new
1,023-byte read capacity applies only to the bounded short correctness case.

## Observed adapter operations

These are source-level allocation requests and explicit memcpy operations in
the production `crypto_tls_stream.c` instance, measured through private test
counters. The CNet executable calls a bridge into its existing DSO, without
linking another Crypto archive. Counts are cumulative per calling thread;
phase deltas exclude the snapshot's structure copy. No phase overflowed or
reported an allocation failure. `BUILD_TESTS=OFF` keeps the original libc
operations and compiles out the counters and bridge.

Every sample's setup made **26 allocation requests / 1,591,144 requested and
successful request bytes**, with six non-null frees. Close/destruction made
zero further adapter allocation requests and 20 non-null frees. The measured
warm, warm drain, transfer and measured drain phases all made **zero adapter
allocation requests, zero releases and zero metadata-copy bytes**. Realloc
bytes are whole successful requests, not net growth or retained capacity.
The 26 frees across setup/destruction balance these observed requests, but
these counts alone do not establish process leak freedom.

For each sample, sum measured transfer and its bulk drain to avoid confusing
pending ciphertext at the interval boundary with missing work. All five
repetitions of each scenario produced the following exact byte totals:

| Mode / bulk depth | Each of four ciphertext-copy boundaries | Delivered plaintext copy bytes | Header-peek bytes |
| --- | ---: | ---: | ---: |
| Direct NativeIO / 1 | 28,045,000 | 27,984,896 | 13,660 |
| Native or callback / 1 | 25,223,168 | 25,166,848 | 20,480 |
| Native or callback / 8 | 25,452,852 | 25,396,224 | 20,620 |

The four boundaries are native read buffer -> input ring, input ring ->
provider, provider -> output ring and output ring -> native write staging.
The table gives **each** boundary's byte sum; it does not count a byte only
once across all four copies. Initial plus pending plaintext-copy bytes equal
the actual bulk bytes plus both one-byte control directions. The long cases
deliver whole provider records with no pending-plaintext copy bytes. Separate
forced-version and bounded short cases require actual pending copies.

For example, one direct transfer copied 28,029,596 / 28,012,188 / 28,030,625 /
28,029,596 bytes at these four boundaries. Its drain copied 15,404 / 32,812 /
14,375 / 15,404 more, respectively; each full phase pair totals 28,045,000.
Snapshot boundaries preserve real staging differences rather than forcing
the four interval values equal.

The CSV also retains actual explicit call counts. Direct transfer + drain
performed 4,252 input and 4,252 output copy operations; native/callback depth
1 performed 3,927 of each, depth 8 performed 3,954. Ring splits can make these
different from native completion counts. Native and callback produced the
same TLS adapter copy counts at each matched depth. That observation does
not measure copies elsewhere in CNet or establish a callback overhead.

Each source reference, whole logical/backing reservation, actual native
identity, local terminal and delivered byte still passes the shared workload
checks. Transfer and drain end with sole source ownership and zero logical
usage. Authenticated reciprocal close_notify precedes complete native
endpoint/request drain and destruction. Source physical capacity totals
32,784 bytes; peak accounted backing is 32,776 at depth 1 or 262,152 at depth
8. The latter is an admission-accounting bound over reused sources, not RSS.

## Instrumented timing and limits

These are medians of five per-sample values; RTT uses nearest-rank quantiles
within each sample. CPU covers all four TLS ends, host polling, accounting
and every-byte validation. Observed GetProcessTimes increments are 15.625 ms.

| Bulk depth | Mode | Bulk MiB/s median (range) | RTT p50 / p95 / p99 ms | CPU microseconds/exchange |
| --- | --- | ---: | ---: | ---: |
| 1 | Direct NativeIO | 19.15 (18.82–19.51) | 2.748 / 3.204 / 3.487 | 2716.06 |
| 1 | Native CNet | 18.65 (17.30–19.40) | 2.675 / 3.265 / 3.698 | 2471.92 |
| 1 | Callback | 19.01 (18.24–19.52) | 2.647 / 3.153 / 3.556 | 2471.92 |
| 8 | Native CNet | 19.40 (19.16–19.72) | 2.628 / 3.042 / 3.410 | 2380.37 |
| 8 | Callback | 19.07 (18.33–19.42) | 2.646 / 3.163 / 3.514 | 2410.89 |

Intervals span 1.217–1.416 seconds. No affinity/frequency/load controls were
applied. These instrumented timings are a separate cohort; neither their
difference from earlier measurements nor small within-cohort differences
establish a stable speedup or instrumentation cost. No policy API or data-path
optimization follows without a relevant profile and controlled comparison.

The workload remains closed-loop and performs different bulk work: direct
verifies 26.65625 MiB in 2,560 rounds then drains 32,768 more bytes; CNet
verifies 24 MiB in 1,536 rounds. CNet depth 1 drains zero bytes; depth 8 drains
229,376 more and rejects 1,536 excess offers without retained references.
Actual native submissions and pending reads cross phase boundaries; no
synthetic completion is introduced to equalize the paths. CPU per control
exchange therefore is not a fixed-work efficiency comparison.

The counters exclude GmSSL internals, NativeIO/Core/system allocations,
compiler-managed thread-local storage, calloc zeroing, realloc's internal
movement, struct assignments, compiler-generated copies and kernel traffic.
They are not process-wide allocation/copy instrumentation, live heap, RSS,
memory-bus traffic or a zero-copy TLS claim. The first snapshot precedes
setup, so any compiler TLS initialization is outside timing. #189 remains
open for global/provider-internal allocation/copy coverage and broader
platform timing. Native policy implementation #156 is already complete.
