# Retained TLS admission — Windows x64, 2026-11-04

Measured source: `032755024f14e91c78fbe82d07d24232483c349d`.
[All 20 rows](cnet-tls-windows-x64-2026-11-04.csv) preserve rotated sample order.
The [protocol](../CNET-TLS-BENCHMARK.md) defines ownership and metric scopes.

## Reproduction

Windows 11 10.0.26200, AMD Ryzen 9 7940HX, 16 cores/32 threads; no affinity,
frequency or background-load control. LLVM-MinGW 20261020, Clang 23.1.4
(`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`), x86_64-w64-windows-gnu,
`native-release-user` Release, GmSSL 3.2.0#18. Collection was 2026-11-04
Asia/Shanghai. Full graph build followed by the existing TLS CTest with
`SALTSCORE_CNET_TLS_BENCHMARK=1` passed all 27 TinyTest cases, including the
20 long samples, in 57.68 seconds. Five separate existing CNet TLS/mTLS CTests
also passed in 8.83 seconds, including independent Python TLS 1.2/1.3 peers.

One caller Owner progresses the production CNet client and server, with two
external IOCP backends, each 2 endpoints / 8 requests / batch 4. Clients use
one connection, 16 commands/events, 8 requests, batch 4, 32-KiB send/receive,
the existing minimum TLS I/O buffer and NODELAY. The standard security profile
verifies the fixture CA and localhost SAN. All 20 rows negotiated **TLSv1.3 /
TLS_AES_128_GCM_SHA256** at both ends. The API profile negotiates its version;
these are not version-pinned TLS 1.2/1.3 cohorts. No new provider/dependency or
second Crypto linkage was used.

Each sample has a fresh connection, 64 warm writes and 2,048 measured writes.
Groups of eight contain one one-byte write and seven 32-KiB writes from one
immutable pooled source. Five repetitions rotate the four mode/depth scenarios.
Depth 8 fills admission and deliberately attempts one extra offer before each
progress round. Its refusals are admission saturation, not kernel pressure.

## Observations

Values are medians of five rows. Latencies are medians of the individual
nearest-rank quantiles. Local-send latency ends at the FIFO local terminal;
throughput ends only after all actual plaintext peer bytes are verified.

| Depth | Mode | MiB/s median (range) | Send p50 / p95 / p99 ms | Process CPU µs/write | Handshake ms | Close/drain ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Native CNet | 21.06 (20.31–21.32) | 1.064 / 1.466 / 1.697 | 1297.00 | 11.079 | 0.331 |
| 1 | Callback | 20.15 (18.85–20.80) | 1.088 / 1.603 / 1.799 | 1358.03 | 11.142 | 0.349 |
| 8 | Native CNet | 20.34 (20.19–21.70) | 9.862 / 12.758 / 14.320 | 1342.77 | 11.088 | 0.360 |
| 8 | Callback | 20.36 (19.22–21.48) | 10.089 / 12.589 / 14.572 | 1342.77 | 10.978 | 0.363 |

Depth-1 native throughput is higher in this cohort's medians, while depth-8
medians are nearly equal and both depths' ranges overlap. This does not isolate
callback cost or establish a stable overhead bound. Both TLS ends, polling and
per-byte validation run on the same thread and belong to measured work. Local
terminals are not peer acknowledgments or RTTs. Process CPU uses Windows
GetProcessTimes with 15.625-ms increments. Handshake covers connect admission
through authenticated READY at both ends, including the client policy setup;
server-context and client/backend initialization precede it. Close covers clean
terminals and client/native stop/drain, ending before object/backend destruction.

Every measured row verified **58,720,512 plaintext bytes** and 2,048 FIFO sends,
with 7,680 combined native submissions. Callback rows invoked the additional
gate exactly 2,048 times; native rows invoked none. All depth-8 rows recorded
3,825 deliberate ENOBUFS refusals with unchanged source references. Hard-limit
refusals do not invoke the callback. Refusal count depends on this host's
progress shape and is not a portable invariant.

Depth-1 logical/backing peaks were 32,768/32,768 bytes. Depth-8 peaks were
229,377/262,144 bytes: the observed queue contains one short and seven large
writes, while every retained operation accounts the full backing capacity.
The single physical source was 32,768 bytes in every row. Backing accounting
therefore counts shared storage conservatively; it is not RSS.

Measured CNet storage allocations and receive acquisitions were zero. Those
receive buffers were admitted before measurement. These counters exclude
Crypto/GmSSL and NativeIO/global allocation, TLS transformations and OS copies;
neither an allocation-free TLS path nor zero-copy transport is established.
Every phase ended with zero send usage and sole source ownership. Every sample
then reached exactly one clean terminal per end, zero native requests/endpoints,
balanced CNet storage releases and complete destruction.

This qualifies a production TLS native-admission/callback workload. Direct secure
NativeIO, independent TLS bulk/control traffic, global allocation/copy counters
and platform timing cohorts remain open under #189. Existing plaintext cohort
rates are not a matched TLS overhead comparison.
