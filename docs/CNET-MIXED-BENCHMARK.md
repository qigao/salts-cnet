# Independent bulk/control connection measurements

This slice of #189 measures native CNet admission versus an additional
per-connection callback using two independent plaintext TCP connections. Both
clients borrow one NativeIO backend on one fixed caller Owner. The host advances
both clients once, observes one batch, routes the whole batch and services both
native peers with bounded work. There is no second poller, worker or application
send queue. This slice does not add direct concurrent NativeIO, TLS or several
Owners, and does not close #189.

## Offering and lifetime protocol

Both modes use the same backend bounds (2 endpoints, 8 requests, batch 4), one
connection per client, command capacity 8 and TCP_NODELAY on both connections and
the native control peer. Listeners retire before warm-up. Bulk retains one
immutable 32-KiB source; control retains one one-byte source, changed only after
the previous local send and reply have both completed and its reference count
returns to one. The configured receive buffer is 256 bytes; send-source capacity
accounting excludes receive buffers and backend storage. Receive views are
callback-scoped borrows. A counting receive
provider delegates to the existing Core buffer pool; its count is acquisitions,
not malloc calls.

Normal load fills bulk to one admitted write per host turn. Saturated load fills
to eight, then deliberately offers one additional write and requires ENOBUFS
without a lasting reference. The full eight-write workload must retain bulk
work after routing while each control exchange progresses. Peer reads continue,
so this is admission saturation rather than proof of kernel backpressure.

Control sends one sequence byte and waits for the native peer's corresponding
one-byte reply before the next exchange. Latency begins immediately before
request send admission and ends at the validated receive callback. A subsequent
exchange also waits for the prior local send terminal; it never mutates bytes
borrowed by a native send. No request is replayed after successful admission.

The bulk offering rule and capacities match across modes, rather than a fixed
offered byte rate: replenishment runs every host turn until the last control
reply. Actual bulk bytes and host rounds can therefore vary with progress.
Report them for every sample. Process CPU/control-exchange includes that varying
bulk work and cannot isolate callback CPU cost.

After the final control completion, stop replenishment, drain every admitted
bulk write and verify every peer byte, both zero usage snapshots and sole host
source references. Only then close both connections, require both peer FINs and
zero native requests/endpoints. Client/listener/backend destruction and storage
provider balance are verified after the separately timed connection close.
Keep callback storage alive on any unexpected incomplete teardown.

## Cases, measurements and metrics

Four small scenarios (native/callback, bulk depth 1/8) belong to the existing
formal TCP CTest. Larger measurements opt in with
`SALTSCORE_CNET_MIXED_BENCHMARK=1`; other values fail. No CMake target, dependency,
preset or workflow is added. Use the normal full build preset, then:

```powershell
$env:SALTSCORE_CNET_MIXED_BENCHMARK = '1'
ctest --preset native-release-user -R '^saltscore\.cnet_tcp_loopback$' -V
Remove-Item Env:SALTSCORE_CNET_MIXED_BENCHMARK
```

Five repetitions alternate native/callback order at each bulk depth, yielding
20 rows. Every fresh sample warms eight exchanges and fully drains that phase,
then measures 4,096 sequential exchanges with sustained bulk. No performance
threshold is asserted. Existing native and sanitizer CI qualifies the small
transfer/RTT/drain scenarios; optional timing runs qualify only their recorded
host/compiler/source revision.

`CNET_MIXED_CSV` records elapsed/process CPU nanoseconds, control RTT nearest-rank
p50/p95/p99, bulk bytes actually read during the control interval, total admitted
bulk writes, host rounds, full refusals, policy evaluations, CNet storage-provider
allocations, pooled receive acquisitions, peak logical/backing usage, physical
source capacity, native submissions, separate bulk/connection drain times and
warm-up receive acquisitions (to distinguish warmed reuse from no acquisition).
Native submission counts cover the control interval, including its outstanding
bulk request at cutoff. Bulk drain covers the remaining admitted writes.

Bulk throughput uses verified peer bytes during the control interval, counted
once. RTT is a real fixture request/reply on a separate connection, not a local
send completion or a business ACK. Accounting is conservative per logical write
and can repeatedly count the shared source. CPU includes host, peers and byte
verification and retains platform accounting granularity. Global allocations,
kernel copies, path MTU, general scheduler QoS and production latency guarantees
remain unmeasured. The TinyTest summary includes drain/bookkeeping; explicit CSV
intervals are authoritative for the scoped metrics.
