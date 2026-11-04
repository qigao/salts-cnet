# Independent bulk/control connection measurements

This slice of #189 compares direct NativeIO, native CNet admission and an
additional per-connection callback using two independent plaintext TCP
connections on one fixed caller Owner/backend. CNet clients borrow that backend;
direct mode creates no CNet client. The host advances both clients when present,
observes one batch, routes the whole batch and services both native peers with
bounded work. There is no second poller, worker or application send queue.
TLS, several Owners and the remaining #189 acceptance remain open.

## Direct NativeIO ownership protocol

Direct mode qualifies bulk depth 1 with the same backend bounds (2 endpoints,
8 requests, batch 4), TCP_NODELAY, peer loop and offering rule as CNet. Each
connection has one retained send source and at most one native send request;
control additionally owns one receive request and a fixed 256-byte receive buffer.
Admission retains the source until the entire logical write completes. Real
prefix completions resubmit only the uncompleted suffix, matching endpoint,
request generation and routing token. Rejection retains nothing. A subsequent
control exchange waits for both local send and validated peer reply before
mutating its source or rearming its receive buffer.

NativeIO completion observation retires the native borrow; routing releases the
logical source only after full completion. Cancellation never releases backing
before its matching real terminal. Cleanup seals resubmission, cancels active
requests and drains the whole observed batch before releasing endpoints or
fixture storage. Both phases end with zero requests and source references of
one. Connection close requires both peer FINs and zero backend endpoints.

Depth 8 continues to compare only the CNet modes. CNet retains eight logical
writes in its existing FIFO while submitting bounded native work. Eight direct
bulk requests plus control send/receive would exceed the matched backend's
eight-request capacity; adding another application FIFO would change this
direct baseline. No raw depth-8 equivalence is claimed.

## Offering and lifetime protocol

All three modes use the same backend bounds (2 endpoints, 8 requests, batch 4),
TCP_NODELAY on both connections and both native peers. CNet uses one connection
per client and command capacity 8. Listeners retire before warm-up. Bulk retains one
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

Six small scenarios (native/callback at bulk depth 1/8 and direct NativeIO at
depth 1 with complete/4-KiB-bounded native sends) belong to the existing formal
TCP CTest. The bounded direct case validates real multi-request continuation;
it is not a fabricated short completion or kernel-pressure measurement.
Larger measurements opt in with
`SALTSCORE_CNET_MIXED_BENCHMARK=1`; other values fail. No CMake target, dependency,
preset or workflow is added. Use the normal full build preset, then:

```powershell
$env:SALTSCORE_CNET_MIXED_BENCHMARK = '1'
ctest --preset native-release-user -R '^saltscore\.cnet_tcp_loopback$' -V
Remove-Item Env:SALTSCORE_CNET_MIXED_BENCHMARK
```

Five repetitions rotate all three modes at depth 1 and alternate native/callback
at depth 8, yielding 25 rows. Every fresh sample warms eight exchanges and fully drains that phase,
then measures 4,096 sequential exchanges with sustained bulk. No performance
threshold is asserted. Existing native and sanitizer CI qualifies the small
transfer/RTT/drain scenarios; optional timing runs qualify only their recorded
host/compiler/source revision. Direct measurements use full 32-KiB native send
bounds; the 4-KiB case is a separate correctness scenario.

`CNET_MIXED_CSV` records elapsed/process CPU nanoseconds, control RTT nearest-rank
p50/p95/p99, bulk bytes actually read during the control interval, total admitted
bulk writes, host rounds, full refusals, policy evaluations, CNet storage-provider
allocations, pooled receive acquisitions, peak logical/backing usage, physical
source capacity, native submissions, separate bulk/connection drain times and
warm-up-phase receive acquisitions. Session-admission acquisitions precede both
intervals, so zero in both does not mean the provider was never used.
Native submission counts cover requests submitted during the control interval,
including any still outstanding at cutoff. Bulk drain covers the remaining admitted writes.
Direct mode creates no CNet client, so CNet allocator and pooled-receive counters
are zero by construction; its receive buffer lives in the preallocated fixture.
Those fields do not measure NativeIO/global allocator traffic. Its logical send
usage is the single retained full write per connection, including any remaining
prefix continuation; it uses the same source-capacity accounting as CNet.

Bulk throughput uses verified peer bytes during the control interval, counted
once. RTT is a real fixture request/reply on a separate connection, not a local
send completion or a business ACK. Accounting is conservative per logical write
and can repeatedly count the shared source. CPU includes host, peers and byte
verification and retains platform accounting granularity. Global allocations,
kernel copies, path MTU, general scheduler QoS and production latency guarantees
remain unmeasured. The TinyTest summary includes drain/bookkeeping; explicit CSV
intervals are authoritative for the scoped metrics.
