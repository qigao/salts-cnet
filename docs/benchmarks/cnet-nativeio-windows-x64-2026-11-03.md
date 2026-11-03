# Direct NativeIO and CNet: Windows x64, 2026-11-03

Measured source: `3d202c54a18ddc6b319d849a347caa524f5acb9c`.
The following evidence commit changes documentation/data only. See the
[measurement contract](../CNET-POLICY-BENCHMARK.md) and
[all 25 raw rows](cnet-nativeio-windows-x64-2026-11-03.csv).

## Matched setup and scope

Windows 11 10.0.26200, AMD Ryzen 9 7940HX, 16 cores/32 threads; no affinity,
frequency or background-load control. LLVM-MinGW 20261020, Clang 23.1.4
(`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`), x86_64-w64-windows-gnu,
`native-release-user` Release. Production dependencies are unchanged.

All modes use IOCP, one fixed caller Owner, one accepted nonblocking stream,
TCP_NODELAY, backend capacities 2 endpoints/4 requests/batch 4, and one immutable
32-KiB source. Every eight logical writes contain one byte followed by seven
32-KiB writes. Each fresh connection warms 64 writes, then measures 2,048 writes
totaling 58,720,512 application bytes. Peer reads/byte validation use the same
thread, sixteen 64-KiB reads per turn. There is no TLS or business response.

At window 1, mode order rotates across direct NativeIO, native CNet and CNet with
an additional per-connection admission callback. Direct NativeIO borrows one
span at a time through its public vector API. The caller retains the source,
validates endpoint/request/tag identity, handles actual prefix completions and
releases its logical reference before publishing completion. It instantiates no
CNet client. The CNet modes use the same single-span retained-send path and
offered write window. Setup differences are outside the measured interval.

Window 8 compares only native CNet and the callback mode. Direct concurrent
logical writes need a separate partial-write/ordering contract; no application
send queue was introduced to fabricate that comparison. Five repetitions per
case produce 25 rows. Each window-8 pair alternates order. Full offers exercise
CNet admission capacity while peer reads continue; they do not establish kernel
backpressure.

Connection drain begins at close and ends after peer FIN plus zero native
requests/endpoints. Object/backend destruction follows outside the interval,
so differing final Winsock reference cleanup is not timed as a connection cost.
The original two-mode run used a different teardown boundary and remains a
separate [historical cohort](cnet-admission-windows-x64-2026-11-03.md).

## Results

Medians of five samples; throughput also shows the observed sample range.
Latency entries are medians of per-sample nearest-rank quantiles, combining
both payload sizes. They end at full local logical completion, not peer/business
acknowledgement. Process CPU includes host, native peer and validation work.

| Window | Mode | MiB/s median (min–max) | Process CPU µs/op | p50 µs | p95 µs | p99 µs | Connection drain µs |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Direct NativeIO | 654.72 (629.86–688.94) | 38.15 | 6.1 | 7.7 | 9.2 | 30.3 |
| 1 | Native CNet | 626.97 (589.36–675.17) | 45.78 | 6.6 | 8.4 | 11.6 | 34.3 |
| 1 | CNet callback | 639.80 (616.31–675.81) | 38.15 | 6.6 | 8.3 | 11.7 | 35.2 |
| 8 | Native CNet | 652.68 (636.06–661.68) | 45.78 | 286.2 | 355.5 | 463.4 | 31.5 |
| 8 | CNet callback | 650.07 (626.90–661.43) | 38.15 | 291.1 | 363.2 | 410.7 | 31.6 |

Every measured sample used exactly 2,048 real native submissions for 2,048
logical writes. Timed data therefore does not claim observed short writes.
The separate 4-KiB-bounded formal NativeIO case exercises continuation with
multiple real requests per logical write, retaining the source until the last
terminal; it does not claim a kernel-generated short completion.

Window-1 samples made no deliberate full offers. Window-8 samples each rejected
2,040 additional offers without a lasting retain. Peak logical usage was
32,768/229,377 bytes at windows 1/8. Peak conservative backing accounting was
32,768/262,144 bytes, while physical source capacity stayed 32,768 bytes.
The raw row's direct-mode usage is the caller's single retained obligation;
CNet usage comes from its public accounting API.

All CNet hot-phase storage-provider allocation counts were zero; direct mode
has no CNet storage provider, so its zero column is not a global or NativeIO
allocation measurement. No kernel copy count is instrumented. Every sample
verified complete peer byte sequence, full logical completion, sole host source
reference, FIN, zero native requests/endpoints and complete final destruction.
The opt-in existing formal CTest passed all 49 TinyTest cases in 3.77 seconds.

## Interpretation and remaining evidence

The throughput ranges overlap at window 1 and at window 8. The earlier run's
lower callback throughput did not reproduce as a stable direction in this
cohort. GetProcessTimes still advances in 15.625-ms steps; the 7.63-µs/op median
CPU difference is exactly one such step over 2,048 writes. It cannot isolate
small callback CPU cost. No fast path, new policy API or general overhead bound
is justified by this single-host run.

Concurrent NativeIO, independent control/bulk connections, several Owners,
matched TLS, actual stalled-kernel workloads, global/copy instrumentation and
other platform timing results remain open in #189. Cross-platform formal CI
qualifies correctness of this path, not timing on unmeasured hosts.
