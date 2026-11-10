# Fixed Owner topology comparison — Windows x64, 2026-11-04

Measured source: `ff8076ac053cac9cc7ffde1cd238bdeae6bed478`.
[25 one-Owner rows](cnet-fixed-single-windows-x64-2026-11-04.csv) and
[25 two-Owner rows](cnet-fixed-two-windows-x64-2026-11-04.csv) are retained.
The [protocol](../CNET-FIXED-OWNERS-BENCHMARK.md) defines the sampling windows.
These are new 4-endpoint cohorts; do not pool them with earlier 2-endpoint mixed
or kernel-stalled results, even when payload sizes look similar.

## Reproduction and ownership

Windows 11 10.0.26200, AMD Ryzen 9 7940HX, 16 cores/32 threads; no affinity,
CPU-frequency or background-load control. LLVM-MinGW 20261020, Clang 23.1.4
(`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`), x86_64-w64-windows-gnu,
`native-release-user` Release. Local collection was 2026-11-04 Asia/Shanghai.
The full graph built, then the existing TCP CTest ran with
`cnet_OWNERS_BENCHMARK=1`; other benchmark flags were unset.
All 63 TinyTest cases passed in 15.27 seconds, including all 50 long samples.

One caller Owner advances both connections. Two fixed SG Owners place bulk on
shard 0 and control on shard 1, using distinct live threads/backends. Each Owner
creates and services its own native peer, client/source and connection. Main
submits lifecycle/phase tasks, waits and reads results; it does no socket I/O or
NativeIO observation. SG host leases remain alive until all client/native work
drains, and observation uses the leased SG context exclusively. Raw mode creates
no CNet client and preserves the actual SG-wrapped completion identity/result.

Aggregate backend capacities match: 4 endpoints, 8 requests and completion batch
4. One Owner reserves 4/8/4; two reserve 2/4/2 each, satisfying CNet's minimum
two-endpoint requirement per Owner. Two connections are active in either case.
CNet clients have one connection, four request slots, completion capacity two,
command capacity eight and 256-byte receive buffers. All connection/peer sockets
use NODELAY. Listeners retire before warm-up.

Each fresh sample warms eight exchanges and fully drains, then measures 4,096.
Five repetitions rotate mode order and alternate topology order. Bulk replenishes
an immutable 32-KiB source at depth 1 or 8; control reuses its byte only after the
prior local send and actual reply complete. Depth 8 deliberately rejects an
additional offer without a lasting reference. Direct NativeIO qualifies only
depth 1; eight native bulk requests exceed its four-request shard capacity.

## Observations and the different amounts of work

Values are medians of five samples. RTT entries are medians of per-sample
nearest-rank quantiles, not pooled quantiles. Bulk rate uses that Owner's own
replenishment interval. CPU is process CPU per control exchange, including the
different amount of concurrent bulk/peer/coordination work.

| Depth | Mode | Owners | Bulk MiB/s | Bulk MiB in its interval | RTT p50 µs | RTT p95 µs | RTT p99 µs | Process CPU µs/exchange |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Direct NativeIO | 1 | 568.27 | 256.00 | 57.4 | 63.8 | 69.4 | 110.63 |
| 1 | Direct NativeIO | 2 | 564.39 | 24.06 | 10.2 | 12.1 | 14.3 | 22.89 |
| 1 | Native CNet | 1 | 551.89 | 256.00 | 64.8 | 78.3 | 87.2 | 110.63 |
| 1 | Native CNet | 2 | 531.36 | 27.78 | 12.6 | 14.4 | 16.1 | 22.89 |
| 1 | Callback | 1 | 552.87 | 256.00 | 64.8 | 79.7 | 85.8 | 114.44 |
| 1 | Callback | 2 | 548.60 | 25.34 | 12.0 | 13.9 | 15.4 | 22.89 |
| 8 | Native CNet | 1 | 540.63 | 256.00 | 64.5 | 79.8 | 86.9 | 114.44 |
| 8 | Native CNet | 2 | 530.96 | 27.94 | 12.4 | 14.5 | 16.4 | 22.89 |
| 8 | Callback | 1 | 549.67 | 256.00 | 65.3 | 78.2 | 88.0 | 110.63 |
| 8 | Callback | 2 | 526.28 | 27.94 | 12.7 | 14.7 | 16.9 | 22.89 |

Control RTT and process CPU/exchange decrease with the partitioned fixture, but
the workload per control interval also changes substantially. One Owner executes
bulk peer reads and per-byte verification in control's progress loop. Two Owners
execute that work independently and stop bulk when control finishes earlier.
One-Owner intervals each verify 256 MiB; two-Owner bulk intervals verify
20.5–28.625 MiB. Similar bulk rates and far fewer bulk bytes per control interval
do not establish a pure CNet speedup, fixed-work CPU efficiency gain or isolated
callback cost. The byte-verification loop and coordination are timed fixture work.

One-Owner control intervals have 8,192 rounds and 16,384 native submissions.
Depth 1 admits 8,192 bulk writes; depth 8 admits 8,199 and drains seven afterward.
Two-Owner control intervals have 8,192 rounds and exactly 8,192 native submissions;
bulk has its own recorded admissions, rounds and native submissions. Depth-8 bulk
retains work after each batch and drains seven additional writes after sealing.
The refill rule is closed-loop rather than a fixed byte rate.

## Sampling skew, capacity and drain

Bulk publishes readiness only after a real progress round has received peer
bytes. Its measured start precedes control by 47.8–131.5 µs in these rows.
Bulk observes control's stop signal 3.3–67.0 µs after control completion. Both
values are explicit in the two-Owner CSV. Bulk bytes/rate include the initial
round and stop-observation delay; they are not an exact control-window byte count.

| Depth | Mode | Two-Owner control ms | Bulk start minus control µs | Stop-observation delay µs | Bulk drain µs | Close/FIN span µs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Direct NativeIO | 44.39 | -53.7 | 48.0 | 0.3 | 46.3 |
| 1 | Native CNet | 53.03 | -54.1 | 21.1 | 0.3 | 66.2 |
| 1 | Callback | 46.88 | -52.0 | 32.4 | 0.2 | 63.4 |
| 8 | Native CNet | 52.54 | -52.9 | 44.4 | 383.9 | 60.5 |
| 8 | Callback | 52.98 | -54.7 | 32.3 | 396.5 | 56.7 |

Peak logical accounting is 32,769/262,145 bytes at depths 1/8. Two-Owner peak
fields conservatively sum per-Owner maxima, rather than sampling a concurrent
global maximum. Physical send-source capacity varies 32,776–33,024 bytes despite
identical requested payload sizes; the CSV preserves actual capacities and
corresponding backing accounting. Receive buffers and runtime/object storage
are excluded. Hot CNet allocator and receive-provider counts are zero; direct
mode does not call those providers. Global/NativeIO allocations and copies
remain unmeasured. CPU accounting advances in 15.625-ms steps.

All samples verify byte/sequence/reply values, send sizes and prefix identities,
rejection retention, sole source references and zero logical/native usage before
close. Each Owner requires peer FIN and zero endpoints, destroys its client and
source, then releases its SG host lease. Main requires all SG tasks settled,
no cancelled tasks, shutdown and destruction before releasing fixtures. Contexts
and live resources stay on their original Owner throughout. Failed cleanup keeps
live storage. The close span runs from the first connection close to both FINs
and endpoints retiring; overlapping bookkeeping is not isolated socket-call cost.

Existing native/sanitizer CI runs the five short paired scenarios; optional
timings qualify only this recorded host/compiler/source. Android is build-only.
TLS, global allocation/copy instrumentation, more Owner counts and broader
platform timing evidence remain separate #189 work. No production code,
dependency, CMake, target, preset, workflow or additional consumer/probe project.
