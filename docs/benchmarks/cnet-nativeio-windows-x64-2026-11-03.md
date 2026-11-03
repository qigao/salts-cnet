# Direct NativeIO and CNet: Windows x64, 2026-11-03

Measured source: `e8372e15393c14e6608e7544e8297a2f6b853305`.
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
offered write window. Both listeners are closed before warm-up, so neither
retains idle accept work. Setup differences are outside the measured interval.

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
| 1 | Direct NativeIO | 641.12 (547.89–666.04) | 45.78 | 6.3 | 7.8 | 10.3 | 33.5 |
| 1 | Native CNet | 603.68 (551.71–649.91) | 45.78 | 7.0 | 9.0 | 11.7 | 35.2 |
| 1 | CNet callback | 614.66 (545.14–658.58) | 45.78 | 6.9 | 8.8 | 12.1 | 39.2 |
| 8 | Native CNet | 637.03 (547.07–645.77) | 45.78 | 289.9 | 372.7 | 545.6 | 34.0 |
| 8 | CNet callback | 623.91 (567.74–653.19) | 38.15 | 300.9 | 367.2 | 406.3 | 50.6 |

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
The opt-in existing formal CTest passed all 49 TinyTest cases in 4.04 seconds.

## Interpretation and remaining evidence

The throughput ranges overlap at window 1 and at window 8. The earlier run's
lower callback throughput did not reproduce as a stable direction in this
cohort. GetProcessTimes still advances in 15.625-ms steps. All three window-1
CPU medians are identical; the window-8 7.63-µs/op median CPU difference is exactly
one such step over 2,048 writes. It cannot isolate small callback CPU cost.
No fast path, new policy API or general overhead bound
is justified by this single-host run.

Concurrent NativeIO, independent control/bulk connections, several Owners,
matched TLS, actual stalled-kernel workloads, global/copy instrumentation and
other platform timing results remain open in #189. Cross-platform formal CI
qualifies correctness of this path, not timing on unmeasured hosts.
