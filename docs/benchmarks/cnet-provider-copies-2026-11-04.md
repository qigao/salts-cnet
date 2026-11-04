# Direct GmSSL copy counters — 2026-11-04

Measured source: `09dee68fcb83be3738f1b7a8fa417f692c0d09c4`.
[LLVM CI #269](https://github.com/qigao/salts-core/actions/runs/41788627508)
passed all ten matrix jobs and aggregate SUCCESS. Linux first passed the
ordinary 155/155 CTests, then the separate instrumented full graph passed
180/180 in 60.12 seconds, including all 25 rotated fresh-process measurements
(43.19 seconds). The [protocol](../CNET-PROVIDER-COPY-MEASUREMENTS.md) was
committed before collection. Existing real transport, byte/reference/capacity,
native identity, refusal, authenticated close and complete drain checks ran.

Preserved data:

- [150 provider phase rows](cnet-provider-copies-provider-2026-11-04.csv).
- [150 matching adapter phase rows](cnet-provider-copies-adapter-2026-11-04.csv).
- [25 diagnostic timing/work rows](cnet-provider-copies-timing-2026-11-04.csv).
- [Artifact, compiler, host and package identity](cnet-provider-copies-provenance-2026-11-04.csv).

Each sample reports setup, warm, warm_drain, transfer, drain and close_destroy.
All four ends negotiated TLSv1.3 / TLS_AES_128_GCM_SHA256. The prior matched
workload remains: one fixed caller Owner, two independent TLS connections,
four 2-endpoint/8-request/batch-4 backends, verified localhost SAN, NODELAY,
17-KiB TLS I/O and 32-KiB immutable bulk sources. Each process warms/drains
eight request/replies, measures 512 and drains every admitted bulk write.

## What was counted

The same pinned GmSSL archive target compiles forced-include wrappers around
explicit source `memcpy/memmove`, and a single private counter implementation.
These counters include fixed-size calls normally inlined by the compiler.
They count operations executed in compiled GmSSL C code, not every movement
of memory in the process. Assignments, handwritten loops, generated copies,
libc internals, cryptographic transformations and kernel traffic are excluded.
Adapter source operations remain separate. There is no second TLS runtime,
replacement allocator, additional test executable, consumer or CMake probe.

Counters use fixed per-thread storage with no explicit allocation, locks,
callbacks or retained payload/pointers. Compiler-managed TLS storage is outside
the allocation counters. Overflow fails the formal interval. Ordinary SDK
graphs do not compile these provider wrappers/counters. Diagnostic timings
include instrumentation and are not compared with ordinary timing cohorts.

Formal TLS1.2/TLS1.3 single-record tests check actual bytes and the TLS1.3
two-encrypt/one-decrypt memcpy relation, including both 8-byte nonce copies.
Short pending plaintext preserves that relation. Over-capacity input rejection
does no provider copy. A real stream construction/destruction on another owner
thread advances that thread's provider counters while the main thread remains
unchanged. Full mixed intervals also check encrypted/decrypted record equality
and exact delivered application bytes after drain.

## Direct results

The table sums warm, warm_drain, transfer and drain, excluding setup/close.
Every value was identical in all five repetitions for each mode/depth.
All source memmove counts/bytes were zero in these observed intervals;
all overflow flags were false.

| Mode / depth | GCM encrypt memcpy calls / bytes | GCM decrypt memcpy calls / bytes | Other provider memcpy calls / bytes |
| --- | ---: | ---: | ---: |
| Direct NativeIO / 1 | 5,552 / 28,465,872 | 2,776 / 22,208 | 22,208 / 56,989,344 |
| Native CNet / 1 | 5,200 / 25,580,880 | 2,600 / 20,800 | 20,800 / 51,215,840 |
| Callback / 1 | 5,200 / 25,580,880 | 2,600 / 20,800 | 20,800 / 51,215,840 |
| Native CNet / 8 | 5,256 / 26,039,856 | 2,628 / 21,024 | 21,024 / 52,134,352 |
| Callback / 8 | 5,256 / 26,039,856 | 2,628 / 21,024 | 21,024 / 52,134,352 |

The pinned GCM encrypt function copies an 8-byte nonce and its input; decrypt
copies the matching nonce. Subtracting measured decrypt nonce bytes from
measured encrypt bytes gives 28,443,664 / 25,560,080 / 26,018,832 input bytes
for direct / CNet depth 1 / CNet depth 8. Each equals actual warm/transfer/drain
delivery, including control bytes. This agrees with the earlier independently
collected heap-derived estimate in [#213's report](cnet-portable-tls-2026-11-04.md),
and now rests on directly executed source-copy counters. The other provider
copies are directly measured as well. No cost or removable-copy claim follows
from their byte totals alone.

Setup/close rows are preserved individually: certificate/handshake data varies
slightly across processes, so those rows are not substituted with traffic-only
totals. Whole-case GCM encrypt calls are 5,580 / 5,228 / 5,284 respectively.
This is not a process-global memcpy total: test setup, NativeIO and other
libraries are outside the provider counters.

## Reproducibility and decision

Host: Ubuntu 24.04.5, runner image `20261025.353.1`, kernel
`7.0.0-1017-azure`, AMD EPYC 9V74, four logical CPUs; no affinity, frequency or
background-load control. Project graph: Clang 18.1.3, Ninja, Release,
`gmssl-copy-user`, no sanitizers/heaptrack. GmSSL 3.2.0#18 retains the canonical
vcpkg-cache v0.1.5 baseline `f1caf997152e4830d7e1089fceaf77aa9127ec25`,
port tree `3b06c785649c2cd632c319375e9bc08e53296b39` and upstream
`7c9f02904ef33e59c87b4f16621cc8fd434e7579`. Its diagnostic package ABI is
`2157e8fca2ce18272c8831ac8c5d14662547acc3f0070aecf9eef73f8f9590f6`.
The vcpkg compiler probe reports `/usr/bin/c++`; the artifact's Clang version
identifies the project compiler, not an assertion about the package compiler.
Package compiler version/flags are not independently captured in this cohort.

Artifact `13302860825`, `gmssl-copy-measurements-linux-x64`, ZIP SHA256
`1ce9c0a1a6e072672ec6632e2fd6af164639b7d64a984111c0557efd24a43e01`
matches GitHub's artifact digest. Full CTest log SHA256:
`ba6a51afefe7301c7eabcd809365e9b8d7dfd89aad392f773b1d25eb65625b21`.
Host/compiler/vcpkg status and successful formal output are in that artifact;
all numeric rows are retained here beyond artifact expiration.

The first diagnostic triplet build is a legitimate package-cache miss; its
artifacts are saved separately. Ordinary Linux compilation used 457/467 ccache
hits (97.86%). The later cumulative counter is 1,040/2,342 (44.41%), including
new dependency/profile compilation; it is not a warm diagnostic hit rate.
Compiler content and input validation remain enabled.

Together with the prior matched plaintext, saturated/stalled, multiple-Owner,
TLS, six-platform timing and process-heap slices, this supplies #189's final
provider-copy metric. Keep the existing policy API. Provider scratch reuse
remains the separate measured candidate [#214](https://github.com/qigao/salts-core/issues/214),
requiring CPU/capacity/latency evidence before an implementation or dependency
change. No throughput, fairness, QoS, zero-copy or speedup guarantee is inferred.
