# Mixed direct NativeIO / CNet measurements — Windows x64, 2026-11-04

Measured source: `981440766c18b12220a4998152635bb28cce15ae`.
[All 25 raw rows](cnet-mixed-nativeio-windows-x64-2026-11-04.csv) belong to
this cohort. Earlier [two-mode measurements](cnet-mixed-windows-x64-2026-11-03.md)
remain historical evidence; do not pool cohorts or attribute their timing
differences to this test-only baseline addition.

## Reproduction and scope

Windows 11 10.0.26200, AMD Ryzen 9 7940HX, 16 cores/32 threads. No affinity,
CPU-frequency or background-load control. LLVM-MinGW 20261020, Clang 23.1.4
(`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`), x86_64-w64-windows-gnu;
`native-release-user` Release. Local collection was 2026-11-04 Asia/Shanghai.
The full graph built, then the existing TCP CTest ran with
`cnet_MIXED_BENCHMARK=1`; other benchmark flags were unset.
All 55 TinyTest cases passed in 6.15 seconds, including the 25 long samples.

The [workload protocol](../CNET-MIXED-BENCHMARK.md) fixes one caller Owner,
two independent TCP connections and one IOCP backend (2 endpoints, 8 requests,
batch 4). All connection/peer sockets use TCP_NODELAY. Peers receive bounded
service on the same thread. Listeners retire before warm-up. Every fresh
sample warms/drains eight control exchanges, then measures 4,096 sequential
one-byte request/replies while replenishing an immutable 32-KiB bulk source.
Five repetitions rotate three-mode order at depth 1 and alternate CNet modes
at depth 8. No performance threshold is asserted.

Direct mode creates no CNet client: one retained native write per connection
and a control receive backed by a fixed 256-byte fixture buffer. CNet uses one
external client per connection, command capacity 8 and 256-byte configured
receive buffers. Both source lifetimes, endpoint/request generations, peer
bytes and drain are checked. A separate small direct case bounds native sends
to 4 KiB and verifies real multi-request continuation; long samples use full
32-KiB send bounds. It does not simulate short completions or kernel pressure.

Direct depth 8 remains unqualified: eight bulk native requests plus control
send/receive exceed the matched eight-request backend. CNet's logical FIFO
permits eight retained writes while submitting bounded native work. Adding a
second application FIFO or changing raw backend capacity would change this
comparison.

## Observations

Values are medians of five samples; ranges show minimum–maximum throughput.
RTT quantiles are medians of per-sample nearest-rank quantiles, not pooled
quantiles. A validated actual peer reply ends RTT, while source reuse also
waits for local send completion. This is a fixture exchange, not a business ACK.

| Bulk depth | Mode | Bulk MiB/s (range) | RTT p50 µs | RTT p95 µs | RTT p99 µs | Process CPU µs/exchange | Bulk drain µs | Close/FIN µs |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Direct NativeIO | 1490.74 (1101.86–1600.51) | 23.1 | 35.1 | 39.0 | 41.96 | 2.6 | 38.4 |
| 1 | Native CNet | 1513.68 (1436.46–1539.93) | 30.4 | 34.4 | 51.9 | 41.96 | 2.6 | 38.4 |
| 1 | Callback | 1486.61 (1211.49–1550.72) | 30.7 | 35.1 | 59.2 | 41.96 | 2.1 | 38.9 |
| 8 | Native CNet | 1488.93 (1374.37–1515.39) | 30.6 | 35.8 | 56.3 | 41.96 | 112.7 | 38.2 |
| 8 | Callback | 1507.47 (1333.94–1528.38) | 30.6 | 34.4 | 50.6 | 41.96 | 114.2 | 37.5 |

Each measured control interval verified exactly 256 MiB of bulk peer bytes,
8,192 host rounds and 16,384 native submissions in these rows. Depth 1 admitted
8,192 bulk writes; depth 8 admitted 8,199 and drained seven further writes
(224 KiB) after the control interval. Replenishment matches a closed-loop
offering rule, not an imposed open-loop byte rate; other hosts can execute
different work per control interval, which the raw rows must preserve.

Depth 8 rejects 8,192 deliberate ninth offers without retaining the source and
keeps admitted bulk work after routing. No peer is paused, so these are logical
admission saturation results rather than OS backpressure evidence. Callback
evaluation counts are 12,288/12,295 at depths 1/8, exactly admitted bulk plus
control writes. Hard-limit refusals do not invoke the additional policy.

Peak logical send usage is 32,769/262,145 bytes at depths 1/8, and conservative
backing accounting is 32,776/262,152 bytes. Physical send sources total 32,776
bytes; shared bulk backing is counted once per logical write in the conservative
metric. Receive buffers, NativeIO storage and CNet object storage are excluded.

CNet modes recorded zero hot storage-provider allocations and zero warm/hot
pooled receive acquisitions; admission precedes both intervals. Direct mode
does not call those CNet providers and has its receive buffer in the fixture,
so its zeros do not establish equal allocation behavior or global allocation
absence. Global allocator traffic and kernel/user copy counts remain unmeasured.

Direct mode's p50 RTT was lower in four samples (23.0–24.3 µs) but reached
33.7 µs in the fifth. Throughput ranges overlap. CPU accounting advances in
15.625-ms steps (3.81 µs/exchange at 4,096 exchanges); equal medians do not prove
equal CPU cost. There is no isolated callback-cost attribution, stable overhead
bound or justified production optimization/API change from this one-host cohort.

All samples checked control sequence/reply values, logical send sizes, bulk
peer bytes, sole source references after drain, both peer FINs, zero native
requests/endpoints and complete backend teardown. CNet cases additionally
checked their clean terminal callbacks, zero usage and balanced storage
providers. Direct completion routing checks request/endpoint generations and
tokens, preserving retained sources through actual prefix completions.

The existing native/sanitizer matrix runs the six small correctness scenarios;
it does not measure cross-platform timings. Multiple Owners, TLS, real kernel
stalls, global allocation/copy instrumentation and broader timing evidence
remain open in #189. Production code, dependencies, CMake, targets, presets and
workflows are unchanged.
