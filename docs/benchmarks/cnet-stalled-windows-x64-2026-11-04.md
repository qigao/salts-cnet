# Control RTT with a kernel-stalled bulk send — Windows x64, 2026-11-04

Measured source: `bf2203162c704b1d0acb3988a1a5c2881d412a9a`.
[All 15 raw rows](cnet-stalled-windows-x64-2026-11-04.csv) are retained.
This cohort implements the [pressure protocol](../CNET-STALLED-BENCHMARK.md).
Do not pool it with the continuously replenished 32-KiB
[mixed baseline](cnet-mixed-nativeio-windows-x64-2026-11-04.md).

## Reproduction and real pressure evidence

Windows 11 10.0.26200, AMD Ryzen 9 7940HX, 16 cores/32 threads; no affinity,
CPU-frequency or background-load control. LLVM-MinGW 20261020, Clang 23.1.4
(`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`), x86_64-w64-windows-gnu,
`native-release-user` Release. Local collection was 2026-11-04 Asia/Shanghai.
The full graph built, then the existing TCP CTest ran with
`cnet_STALLED_BENCHMARK=1`; other benchmark flags were unset.
All 58 TinyTest cases passed in 6.08 seconds, including all 15 long samples.

One fixed caller Owner/backend (2 endpoints, 8 requests, batch 4) serves two
independent TCP connections and their native peers. All sockets use NODELAY.
Direct mode creates no CNet client or application queue; CNet modes each use
two external clients. Bulk retains one immutable 8-MiB source at logical depth
one; control has one retained byte and a 256-byte receive buffer. The peer's
receive buffer is set before connect. Effective bulk SO_SNDBUF/SO_RCVBUF values
were 4,096/65,536 bytes in every row. These settings are recorded, not treated
as proof of a stall.

Each fresh sample warms eight control exchanges with its own full pressure/drain
cycle, then prepares pressure again and measures 4,096 exchanges. Five
repetitions rotate mode order. The pressure gate permits at most four complete
priming writes before a pending write, using the same immutable source.

Every measured row admitted three 8-MiB bulk writes while the peer read nothing:
two completed locally, and the third remained a real native STREAM_SEND. The
gate required **two actual 25-ms NativeIO observation timeouts**, zero returned
completions, one active native request, the same request slot/generation, one
logical write and source reference count two. It did not hold a returned
completion or infer pressure from ENOBUFS.

Bulk replenishment then stopped, while bulk peer reads stayed paused. The same
native request and retained source remained outstanding through all 4,096
control request/replies. Each measured interval used exactly 8,192 native
submissions and 8,192 host rounds; bulk application reads remained zero.
Afterward, the same host resumed bounded bulk reads, routed the pending native
terminal and verified all three writes: **24 MiB** per sample. Source references,
zero usage/requests, peer FINs and zero endpoints were checked before teardown.

## Scoped results

Medians of five samples; the elapsed range is minimum–maximum. RTT quantiles
are medians of per-sample nearest-rank quantiles. They end on a validated
actual peer reply; source reuse additionally waits for the local send terminal.

| Mode | Control interval ms (range) | RTT p50 µs | RTT p95 µs | RTT p99 µs | Process CPU µs/exchange | Preparation ms | Resume drain ms | Close/FIN µs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Direct NativeIO | 32.65 (31.24–35.88) | 6.8 | 7.1 | 16.7 | 7.63 | 72.56 | 37.41 | 32.4 |
| Native CNet | 36.10 (35.54–36.26) | 8.3 | 8.8 | 20.4 | 7.63 | 71.45 | 37.15 | 33.8 |
| Callback | 35.71 (35.41–38.67) | 8.4 | 9.4 | 20.4 | 7.63 | 70.23 | 37.34 | 35.4 |

Preparation includes priming and the two observation waits. Control timing/CPU
exclude preparation, resumed bulk reads and final connection close. Resumed
drain includes peer byte validation; it is not an isolated transport benchmark.
The third Windows IOCP send completed after reads resumed without additional
native submissions in the drain interval. POSIX may require actual prefix
resubmissions, so this count must be recorded rather than assumed zero.

This is not a bulk-throughput measurement during the paused interval: the host
deliberately reads zero bulk bytes then. Control executes without concurrent
bulk replenishment or peer byte verification, unlike the busy mixed workload.
Do not attribute the lower RTT versus that different workload to a production
optimization. Only the three modes within this cohort have matched pressure,
capacities, sources, control offering and peer work.

All rows had peak logical send usage 8,388,609 bytes and conservative backing
8,388,616 bytes, equal to 8,388,616 bytes of physical send sources. This excludes
receive buffers, CNet/NativeIO object storage and TCP/kernel buffering for the
earlier locally completed writes. CNet storage-provider and pooled receive
acquisition counts were zero during the control interval; admission and priming
precede it. Direct mode does not call those CNet providers. None of these zeros
measure global allocations or kernel/user copies. Callback counts were exactly
4,096 during control; priming bulk admissions are outside that counter interval.

CPU accounting has 15.625-ms steps, equivalent to 3.81 µs/exchange here, so equal
7.63-µs medians do not prove equal CPU cost. Direct p99 values ranged 8.0–21.7 µs,
overlapping CNet's 20.0–21.9 µs and callback's 13.0–20.9 µs. Five samples on one
uncontrolled host do not isolate callback overhead or establish a QoS guarantee.
No production optimization/API change follows from this cohort.

The existing formal TCP CTest runs all three short pressure/control/drain cases
on native/sanitizer CI; local timings qualify only this recorded Windows host.
Android builds provide no device-runtime evidence. Multiple Owners, TLS,
global allocation/copy instrumentation and broader platform timings remain open
in #189. Production code, dependencies, CMake, targets, presets and workflows
are unchanged; no consumer/smoke/probe project is added.
