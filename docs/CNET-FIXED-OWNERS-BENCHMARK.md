# One Owner versus two fixed SG Owners

This #189 cohort compares direct NativeIO, native CNet admission and an
additional admission callback within each topology. Bulk and control use two
independent TCP connections. One Owner advances both; two Owners place bulk on
SG shard 0 and control on shard 1. Connections never migrate. The existing
NativeIO sharded runtime supplies the fixed worker threads and host leases.

## Ownership and capacity protocol

Every socket, source, client, backend, counter and callback belongs exclusively
to its final Owner. That Owner creates, progresses, drains and destroys it, and
also services its unassociated native peer. Main submits bounded lifecycle/phase
tasks and reads results only after `native_io_sharded_wait`. It does no socket
I/O or NativeIO observation. Callback-scoped SG contexts are never retained.
Only compiled Platform atomic slots carry readiness, abort and stop signals
between Owners; they carry no data-path messages or pointers.

Both topologies reserve 4 endpoints, 8 requests and an aggregate completion batch
of 4. Each CNet Owner requires at least 2 endpoint slots, so the two-Owner case
uses 2/4/2 per shard and the one-Owner case uses 4/8/4. Two connections are active
in either topology. Client connection capacity is one, request capacity four,
completion capacity two, command capacity eight and receive buffers 256 bytes.
The same bounds apply to raw mode without creating CNet clients. This cohort
does not reuse the earlier 2-endpoint mixed timing results.

Bulk retains one immutable 32-KiB source, replenished at logical depth 1 or 8.
Depth 8 offers a ninth write and requires ENOBUFS without a lasting reference.
Raw mode is qualified only at depth 1: eight raw bulk requests exceed its shard's
four-request capacity. Control retains one byte, changed only after its prior
local send and actual sequence/reply both retire. All sockets use NODELAY.
Listeners retire before warm-up. No extra I/O observer or application FIFO.

Each two-Owner phase starts with a bounded atomic readiness rendezvous. Bulk
performs one real progress/peer-service round before publishing readiness for
control. It then continues replenishment independently. Control measures
sequential one-byte request/replies and publishes stop with release semantics
after the final reply and send completion. Bulk observes stop with acquire
semantics, seals admission and then drains every admitted write and peer byte.
Failure publishes abort; neither worker may wait indefinitely for its neighbor.

Bulk and control have separate start/end times. Record bulk start minus control
start and the delay from control completion to bulk observing stop. Bulk byte
count/rate covers bulk's own replenishment interval, including its initial round
and stop-observation delay. It is not an exact byte count for the control
interval. Control process CPU includes concurrent bulk/peer/coordination work;
it does not isolate per-thread or callback cost. A topology change changes the
amount of bulk work possible during a control interval.

Warm each fresh sample for eight exchanges and drain fully, then measure 4,096.
Five repetitions rotate mode order and alternate topology order. Depth 1 has
three modes, depth 8 two, producing 50 rows in the optional run. Existing TCP
formal tests run the five short paired scenarios. Timings use
`cnet_OWNERS_BENCHMARK=1` and the existing full build/CTest presets;
no target, workflow or external project is added.

```powershell
$env:cnet_OWNERS_BENCHMARK = '1'
ctest --preset native-release-user -R '^saltscore\.cnet_tcp_loopback$' -V
Remove-Item Env:cnet_OWNERS_BENCHMARK
```

`CNET_SINGLE_OWNER_CSV` has the mixed-workload columns, but belongs to this
4-endpoint comparison cohort. `CNET_FIXED_OWNERS_CSV` records control time/CPU
and RTT quantiles, bulk's own bytes/time/admissions, separate Owner round and
native submission counts, rejection/provider/policy counts, conservative sums
of per-Owner peak usage, physical send sources, bulk drain, connection-close
span, signed start skew and stop-observation delay. The peak sums are upper
bounds, not synchronized aggregate peaks. The close span is earliest connection
close start through both FINs/endpoints retiring, before SG runtime shutdown.
TinyTest's benchmark duration includes gates and drain; explicit CSV intervals
are authoritative for the scoped measurements.

Before close, both sources must return to one reference, logical usage and
native requests to zero, and every peer byte must match. Each Owner then closes
its connection, requires peer FIN and zero endpoints, destroys its clients and
sources, and releases its SG host lease. Main requires distinct live thread
tokens/backends throughout, complete SG task drain and successful runtime
shutdown/destruction before releasing fixtures. Failed cleanup retains live
storage. Raw request/endpoint generations and routing tokens remain authoritative.

No general speedup, QoS or scheduler guarantee follows from one uncontrolled
host. This cohort excludes TLS and kernel-stalled peers; global allocation/copy
instrumentation and broader platform timing evidence remain separate work.
