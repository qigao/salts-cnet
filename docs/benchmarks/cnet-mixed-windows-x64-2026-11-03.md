# Independent bulk/control: Windows x64, 2026-11-03

Measured source: `aa9dd023a01667db0c10c0b403c31de717f2d318`.
See the [workload contract](../CNET-MIXED-BENCHMARK.md),
[20 full-length raw rows](cnet-mixed-windows-x64-2026-11-03.csv) and
[20 pilot rows](cnet-mixed-windows-x64-2026-11-03-pilot512.csv).
The pilot used source `a1d04601650ed22ba526ac902f0015201ef10946` and 512
exchanges; its approximately 20-ms intervals were too close to the observed
15.625-ms CPU accounting step. The main run increases each sample to 4,096
exchanges. Keep the two cohorts separate.

## Reproduction and matched offering

Windows 11 10.0.26200, AMD Ryzen 9 7940HX, 16 cores/32 threads; no affinity,
CPU-frequency or background-load control. LLVM-MinGW 20261020, Clang 23.1.4
(`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`), x86_64-w64-windows-gnu,
`native-release-user` Release. The full build and existing TCP formal CTest ran
with `SALTSCORE_CNET_MIXED_BENCHMARK=1`; other benchmark flags were unset.
All 53 TinyTest cases passed in 5.49 seconds, including the 20 main samples.

One fixed caller Owner advances two independent external CNet clients sharing
one IOCP backend (2 endpoint slots, 8 requests, batch 4). Each client has one
connection, command capacity 8, receive buffer configuration 256 bytes and
TCP_NODELAY; the native control peer also uses NODELAY. Listeners retire before
warm-up. Pure admission callbacks are either absent or applied to both clients.
Production dependencies and code are unchanged.

Each fresh sample warms eight request/replies and drains that phase completely,
then measures 4,096 sequential one-byte request/replies while replenishing bulk
from one immutable 32-KiB source. A single control source is changed only after
its prior send and reply retire. Depth 1 fills one bulk slot; depth 8 fills eight
and deliberately rejects a ninth offer on each host turn. Both peers receive
bounded service on the same thread. Five repetitions alternate mode order.

The rule is matched closed-loop offering, not an open-loop fixed byte rate.
In these recorded rows, each control interval happened to take 8,192 host rounds
and verify exactly 256 MiB of bulk peer data. Depth 1 admitted 8,192 bulk writes;
depth 8 admitted 8,199 and drained seven additional writes (224 KiB) after the
control interval. Other hosts may produce different progress counts; record
them rather than assuming equal bulk work.

## Observations

Values are medians of five samples; throughput ranges show minimum–maximum.
RTT entries are medians of per-sample nearest-rank quantiles, not pooled
quantiles. RTT ends at the validated fixture reply callback on the independent
control connection. It is distinct from local send completion and business ACK.

| Bulk depth | Mode | Bulk MiB/s (range) | RTT p50 µs | RTT p95 µs | RTT p99 µs | Process CPU µs/exchange | Bulk drain µs | Close/FIN µs |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Native CNet | 1414.05 (1235.14–1477.77) | 31.9 | 39.6 | 49.3 | 45.78 | 2.5 | 39.0 |
| 1 | Callback | 1443.79 (1424.08–1476.82) | 31.0 | 37.7 | 47.8 | 41.96 | 2.3 | 40.5 |
| 8 | Native CNet | 1446.14 (1203.07–1461.59) | 31.2 | 38.0 | 59.8 | 45.78 | 113.7 | 38.1 |
| 8 | Callback | 1406.56 (1370.34–1454.03) | 31.7 | 38.4 | 51.2 | 41.96 | 120.6 | 44.8 |

Each full-length row recorded 16,384 native submissions during the control
interval. Depth-8 rows retained admitted bulk work after every routed batch and
rejected 8,192 deliberate full offers without a lasting retain. No peer was
paused; these are admission-capacity observations, not kernel-stall evidence.
Callback evaluation counts were 12,288/12,295 at depths 1/8, matching accepted
bulk plus control sends; hard-bound refusals did not invoke the extra policy.

Peak logical send usage was 32,769/262,145 bytes at depths 1/8. Peak conservative
backing accounting was 32,776/262,152 bytes, versus 32,776 bytes of physical send
sources in both modes/depths. This excludes the receive buffers and backend
storage. All rows recorded zero measured CNet storage-provider allocation calls
and zero pooled receive acquisitions during warm-up and measurement. Session
admission precedes both intervals; the borrowed receive path reuses its active
buffer (`cnet_owner_finish_receive_publication`). These zeros are not global
allocation or OS-copy counts.

Every sample checked control sequence/reply bytes, successful send sizes,
all bulk peer bytes, zero post-drain usage, sole host source references, two
clean connection terminals/FINs, zero native requests/endpoints, storage-provider
balance and complete client/listener/backend destruction. Bulk replenishment
stops before transfer drain; connection close is separately timed through FIN
and zero native usage, with object destruction outside the interval.

## Interpretation and remaining #189 work

The native/callback throughput ranges overlap. Per-sample p99 ranges overlap
as well: depth 1 native 44.9–60.6 µs versus callback 45.7–69.5 µs, and depth 8
native 44.4–70.6 µs versus callback 49.0–60.9 µs. CPU intervals are longer than
the pilot, but one 15.625-ms step still equals 3.81 µs per 4,096 exchanges—the
observed median CPU difference. CPU includes host, bulk, peer and validation
work. These data do not isolate callback cost or justify a new API/fast path.

The peer validation loop and workload differ from the earlier single-connection
dataset, so do not compare absolute MiB/s across those harnesses as a transport
speedup. Direct NativeIO for two connections, multiple Owners, matched TLS,
real kernel-stalled loads, global/copy instrumentation and other platform timing
results remain open. The present result qualifies this fixed one-Owner
plaintext workload, not general fairness, scheduler QoS or production latency.
