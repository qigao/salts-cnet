# Portable TLS traffic and Linux heap profile — 2026-11-04

Measured source: `bff1158381ed8d0287ee496f54856c45d87633a8`.
[Manual LLVM qualification](https://github.com/qigao/salts-core/actions/runs/41780119864)
passed all ten matrix jobs and aggregate SUCCESS. The
[collection protocol](../CNET-PORTABLE-MEASUREMENTS.md) reuses existing formal
TinyTest cases through plain CMake/CTest, with no additional executable,
consumer/smoke project, CMake verification script, second runtime or product
dependency change.

Preserved data:

- [175 timing rows](cnet-portable-tls-timing-2026-11-04.csv): 150 native and 25
  separately labelled Linux heaptrack samples.
- [1,050 adapter-memory phase rows](cnet-portable-tls-memory-2026-11-04.csv).
- [Six host/compiler records](cnet-portable-tls-hosts-2026-11-04.csv) and
  [artifact identities/digests](cnet-portable-tls-artifacts-2026-11-04.csv).
- [25 process-heap summaries](cnet-portable-tls-heap-2026-11-04.csv), each with
  a source trace SHA256, and [1,649 allocation-size rows](cnet-portable-tls-heap-sizes-2026-11-04.csv).

Every platform runs five rotated repetitions of direct NativeIO depth 1,
native CNet depth 1, callback depth 1, native depth 8 and callback depth 8.
Each sample is a fresh formal-test process, warms/drains eight exchanges and
then measures 512. CTest DEPENDS orders the 25 registrations and RUN_SERIAL
excludes overlap, including the local `--parallel 4` qualification. Normal
unfiltered short suites remain separate. All 150 native long cases and all
25 profiled long cases passed their actual byte/refcount/capacity/identity,
authenticated shutdown and complete native-drain assertions.

## Configuration and provenance

All four ends in every row negotiated TLSv1.3 / TLS_AES_128_GCM_SHA256.
One caller Owner advances both ends of two independent connections, four
2-endpoint / 8-request / batch-4 backends, aggregate 8/32/16. Certificates,
verified localhost SAN, NODELAY, 17-KiB TLS I/O, 32-KiB plaintext receive
capacity and offered algorithms match the existing mixed TLS protocol.
Windows uses IOCP, Linux epoll and macOS kqueue. Actual amounts of completed
bulk work can differ; no single shared backend or fixed-work CPU comparison
is claimed.

Every graph is `ci-native` Release without sanitizers. Canonical vcpkg-cache
v0.1.5 baseline `f1caf997152e4830d7e1089fceaf77aa9127ec25` and unchanged
GmSSL 3.2.0#18 port tree `3b06c785649c2cd632c319375e9bc08e53296b39`.

| RID | OS / reported CPU | Logical processors | Configured C/C++ compiler |
| --- | --- | ---: | --- |
| linux-x64 | Ubuntu 24.04.5; Intel Xeon Platinum 8370C | 4 | Clang 18.1.3 |
| linux-arm64 | Ubuntu 24.04.5; Neoverse-N2 | 4 | Clang 18.1.3 |
| macos-x64 | macOS 15.7.9; Intel Core i7-8700B | 4 | Clang 18.1.8 |
| macos-arm64 | macOS 15.8.2; Apple M1 (Virtual) | 3 | Clang 18.1.8 |
| windows-x64 | Windows 10.0.26100; AMD EPYC 7763 | 4 | LLVM-MinGW Clang 23.1.4 |
| windows-arm64 | Windows 10.0.26200; Cobalt 100 | 4 | LLVM-MinGW Clang 23.1.4 |

The initial host artifact queried `clang` on PATH. Both macOS runners reported
Apple clang 17 there, while the configured graph actually used Homebrew
Clang 18.1.8. The host CSV preserves the incidental PATH banner separately
and records the actual version/path from each job's compiler-identification
and working-compiler lines. Linux and Windows identities agree. The workflow
now preserves a plain CMake-generated compiler record rather than guessing
from PATH. This metadata correction changes no runtime C code or scenario
assertion from the measured source.

Linux x64 passed 180/180 ordinary CTests and another 25/25 under heaptrack;
Linux ARM64 passed 177/177; Windows and macOS each passed 176/176. Both
Android builds and both Linux sanitizer lanes also passed, with their normal
short tests rather than timing collection. Local full Release configuration,
build and 25 selected measurement CTests passed in 33.88 seconds; later
compiler-provenance generation required no runtime rebuild.

The collection also exposed a compiler-cache restore-key limitation: every
native lane missed the archive because its only restore prefix contained the
complete vcpkg archive key, including the changed workflow hash. Logged ccache
hit rates were 0.21–1.77%. A subsequent workflow correction adds a prefix
limited to the same ccache version, OS/architecture/RID/preset and dependency
contract, while preserving compiler-content/input validation. This changes
cache discovery, not the measured source or its timing data.

## Native observations

Each cell is **median bulk MiB/s / median control RTT p99 in milliseconds**
over five per-sample values. Quantiles are nearest rank within each sample;
samples and platforms are not pooled. The CSV also preserves CPU and RTT
p50/p95, all intervals, native submissions, rejection and drain data.

| RID | Direct / 1 | Native / 1 | Callback / 1 | Native / 8 | Callback / 8 |
| --- | ---: | ---: | ---: | ---: | ---: |
| linux-x64 | 16.85 / 3.310 | 16.73 / 3.322 | 16.66 / 3.348 | 16.74 / 3.317 | 16.80 / 3.314 |
| linux-arm64 | 19.36 / 2.842 | 19.14 / 2.883 | 19.18 / 2.872 | 19.16 / 2.870 | 19.17 / 2.873 |
| macos-x64 | 8.35 / 7.107 | 10.70 / 6.042 | 10.82 / 5.730 | 11.60 / 5.635 | 10.63 / 5.825 |
| macos-arm64 | 13.87 / 8.645 | 12.63 / 18.584 | 14.07 / 6.985 | 13.74 / 10.315 | 13.77 / 8.934 |
| windows-x64 | 15.12 / 4.705 | 15.03 / 4.038 | 14.97 / 3.989 | 15.09 / 4.107 | 14.91 / 4.067 |
| windows-arm64 | 16.91 / 3.410 | 16.58 / 3.477 | 16.59 / 3.406 | 16.57 / 3.450 | 16.62 / 3.388 |

No affinity, frequency or background-load control was applied. Different
hardware, kernels, compilers and timer accounting prevent a platform/ISA
ranking. Preserve the wide macOS variation: native depth-1 rates were
9.18–13.83 MiB/s on x64 and 11.32–14.70 on ARM64. These observations do not
establish a stable wrapper/callback overhead, fairness bound or optimization.
The adapter's warm/transfer/drain counters remain allocation-free while
recording real nonzero copies; those source counters have a narrower scope
than the following process profile.

## Linux process heap observations

Heaptrack and heaptrack_print 1.5.0 launch each formal case from startup.
Built-in and embedded leak suppressions are disabled. The unprofiled full
suite output is preserved first. Profiled latency/throughput rows have their
own condition and must not be ranked against the unprofiled data.

The format-v3 trace's successful allocation/free events reconstruct requested
byte totals and high-water marks. Their counts and byte sums agree with the
CLI totals and size histograms for all 25 traces. These are requested bytes,
not allocator usable capacity, system heap metadata, RSS or memory-bus traffic.
Scope includes TinyTest discovery/formatting, fixtures, TLS setup, both warm
and measured traffic/drains, authenticated close and destruction, as well as
intercepted allocations inside Core/NativeIO/CNet and the single GmSSL provider.

| Mode / depth | Allocation calls in every sample | Requested-byte range | Peak requested-heap-byte range | GmSSL GCM calls in every sample |
| --- | ---: | ---: | ---: | ---: |
| Direct / 1 | 3,249 | 31,129,577–31,129,579 | 1,874,104 | 2,790 |
| Native / 1 | 3,886 | 28,509,628–28,509,708 | 2,107,282–2,107,362 | 2,614 |
| Callback / 1 | 3,886 | 28,509,595–28,509,660 | 2,107,250–2,107,314 | 2,614 |
| Native / 8 | 3,914 | 28,976,203–28,976,285 | 2,107,938–2,108,018 | 2,642 |
| Callback / 8 | 3,914 | 28,976,205–28,976,285 | 2,107,938–2,108,018 | 2,642 |

These whole-process figures are not isolated CNet overhead: fixtures and test
discovery differ, and raw performs more bulk work. Each trace ends with 37
outstanding allocations / 10,048 requested bytes. Representative native
depth-1 stacks account for 4,096 bytes in libc stdio, 1,280 in Platform mutex
initialization, 528 in global-buffer setup and 4,144 in slab allocation.
Global pool/cache/stdio lifetime is distinct from connection teardown; this
profiler exit snapshot alone does not establish a CNet leak. Formal transport
teardown and sanitizer evidence remain separate.

### Provider hotspot and one calculated copy component

The allocation leaf `tls13_gcm_encrypt` occurs below
`tls13_record_encrypt -> tls13_send -> crypto_tls_stream_write` in both
production paths. Stacks also include `tls_mixed_phase`, proving that many
of these requests occur during traffic/drain, beyond context construction.
The pinned [upstream implementation](https://github.com/guanzhi/GmSSL/blob/7c9f02904ef33e59c87b4f16621cc8fd434e7579/src/tls13.c)
requests `inlen + 256`, copies the input into that temporary storage and frees
it after GCM encryption. Observed bulk requests include 16,640-byte buffers.
The adapter provider counters do not cover this allocation leaf.

| Mode / depth | GCM allocation calls below warm/measured phase stacks | Observed requested bytes there | Calculated GCM input-copy bytes there |
| --- | ---: | ---: | ---: |
| Direct / 1 | 2,776 | 29,154,320 | 28,443,664 |
| Native or callback / 1 | 2,600 | 26,225,680 | 25,560,080 |
| Native or callback / 8 | 2,628 | 26,691,600 | 26,018,832 |

Each value is identical across its five repetitions. The final column is an
explicit **source-derived calculation**, observed request bytes minus 256
times those allocation calls. It covers that one unconditional input-copy
site, including warm-up and both bulk drains. It is not an instrumented
provider memcpy counter or a total for provider/compiler-generated copies.
Other cryptographic state movement and kernel traffic remain outside it.

This identifies a concrete provider allocation candidate while preserving
the current dependency and policy APIs. Frequency alone does not quantify
CPU cost or a speedup from scratch reuse. Any bounded workspace proposal must
measure CPU, throughput, tail latency and retained capacity while preserving
TLS profiles, verification, retry/record state and owner-safe teardown. #189
still lacks exhaustive provider-internal copy instrumentation; the global
heap and six-platform timing gaps now have reproducible evidence.
