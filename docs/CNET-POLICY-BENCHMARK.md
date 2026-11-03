# Matched NativeIO and CNet retained TCP measurements

This is the first measurement slice of [#189](https://github.com/qigao/salts-core/issues/189).
It compares direct NativeIO, native CNet admission and an additional host
admission callback. Direct NativeIO is compared at window 1; window 8 compares
the two CNet modes. This is not a TLS benchmark, multi-Owner scheduler comparison
or a claim about production QoS.

## Matched protocol

Each sample uses one fixed caller Owner, an external CNet client and its one
NativeIO backend, plus an independent native TCP peer driven on the same thread.
All modes use the same backend capacities, completion batch, TCP_NODELAY setting, immutable
32-KiB source, payload order, send limits and peer read budget. One in eight
writes is one byte; the other seven are 32 KiB. No TLS is used. Connection setup,
source creation and warm-up precede measurement; close/drain follows it.

The CNet baseline uses its native hard send bounds. The composed mode adds a pure
per-connection callback checking the same operation and byte bounds; it never
owns payload or overrides hard admission. Both use the same storage provider.
One outstanding write is the paced workload. Eight outstanding writes plus
one rejected offer exercise admission saturation. This does not prove TCP
kernel backpressure: the receiver continues bounded reads on every host turn.

Direct NativeIO has one logical write and one native vector request in flight.
The caller retains the same immutable source until the entire logical write
completes, handles genuine terminal byte counts and resubmits a remaining prefix
on the same Owner. It validates the full native endpoint/request/tag identity
before retiring a borrow. NativeIO itself does not implement CNet's logical
write-all semantics. Comparing several outstanding logical writes would require
an explicit ordering/partial-write contract; this slice does not add an
application queue to manufacture that comparison.

Direct mode creates and accepts its TCP pair through native socket APIs, while
CNet mode uses its public listener. Setup is outside the measured region in
both. Each attaches one accepted nonblocking stream to the same kind/capacity
of backend and enables TCP_NODELAY before warm-up. Direct mode contains no
CNet client or CNet progress call in the transfer. Its local terminal is
published only after the full logical byte count, with the caller's retained
reference released, matching the CNet observer boundary. This comparison
includes the remaining CNet owner/accounting machinery, not just a callback.

Before enabling measurement, the existing TCP formal suite must run small
correctness cases for the CNet modes/windows and direct NativeIO. A second direct
case bounds each real native submission to 4 KiB to exercise continuation and
retention without fabricating a short completion or claiming kernel pressure.
The timed direct case uses the same full 32-KiB per-submit bound as CNet.
All cases verify FIFO completion sizes,
every peer byte, expected full rejection without retain, zero final usage,
source references, terminal/FIN, no hot-phase storage-provider allocation and
complete native endpoint/request/client/backend drain. No timing threshold is
a correctness assertion. The optional larger samples use the same path.

## Metrics and interpretation

- Throughput uses application payload bytes counted once, through completed
  local sends and actual peer reads. It includes host progress and byte checking.
- Per-write latency starts immediately before admission and ends at the local
  successful-send callback. p50/p95/p99 are nearest-rank sample quantiles, not
  peer response or business-ACK latency. TCP has no write/message boundary.
- CPU is process user plus kernel time, including the same-thread native peer
  and verification. Windows uses GetProcessTimes; POSIX uses getrusage.
  Accounting granularity may yield zero for short samples; do not interpret
  such a row as zero CPU cost.
- Allocation counts cover the configured CNet storage provider during the
  measured phase, not all libc, Core pool or kernel allocations.
  Direct mode does not instantiate that provider; its zero CNet-provider count
  is not NativeIO allocator instrumentation.
- Peak logical bytes and backing accounting come from CNet usage. Backing
  accounting is conservative per admitted operation, so it may count one shared
  source repeatedly; report its actual physical capacity separately.
- CNet's retained plaintext API does not copy payload into its write queue.
  That contract is not an instrumented count of kernel/TCP or verification
  copies. Such copies remain unmeasured.
- ENOBUFS counts are deliberate full offers; successful reference/drain checks
  distinguish bounded admission pressure from dropped or abandoned writes.
- Close/drain time is separate from steady transfer. A peer FIN and zero native
  usage are required regardless of the measured value.
- Native submit count is read from backend counters outside the timed interval.
  It distinguishes logical writes from real native submissions and continuations.

Use multiple warmed samples, interleave mode order and retain every raw row.
Record source SHA, compiler/build profile, backend, host/architecture, capacities,
operation counts and repetitions. Do not infer an optimization or add an API
from a single platform or a small, noisy difference.

The full #189 gate still includes concurrent NativeIO, mixed independent bulk/control
connections, matched TLS, multiple Owners, copy/allocation instrumentation and
broader platform measurements. This first slice does not close that issue.

## Run through the existing formal target

The existing `saltscore.cnet_tcp_loopback` CTest always runs four small CNet
cases and two direct NativeIO cases. No target, dependency or workflow is added. To opt in
to measurements, set `SALTSCORE_CNET_POLICY_BENCHMARK=1` in the parent process
and use the existing user build/test presets. Other nonempty values fail.

```powershell
# Use the normal project toolchain/VsDevCmd environment.
cmake --build --preset native-release-user
$env:SALTSCORE_CNET_POLICY_BENCHMARK = '1'
ctest --preset native-release-user -R '^saltscore\.cnet_tcp_loopback$' -V
Remove-Item Env:SALTSCORE_CNET_POLICY_BENCHMARK
```

```sh
cmake --build --preset native-release-user
SALTSCORE_CNET_POLICY_BENCHMARK=1 ctest --preset native-release-user \
  -R '^saltscore\.cnet_tcp_loopback$' -V
```

Five repetitions rotate the three window-1 modes and alternate the two window-8
modes, producing 25 rows. Each sample creates a fresh
connection, warms 64 writes, measures 2,048 writes and separately closes/drains.
The one-byte/32-KiB sequence repeats every eight operations. The existing test
timeout remains in force; no threshold compares the two modes.

Each `CNET_POLICY_CSV` row reports mode, repetition, window, operation/payload
counts, elapsed/CPU nanoseconds, local-send latency quantiles, full refusals,
peak logical/backing accounting, physical source bytes, hot-phase storage calls,
policy calls, close/drain nanoseconds and native submit count. The TinyTest `benchmark_io` summary
also includes the driver's measurement bookkeeping; use the explicit row fields
for the scoped metrics above. CTest retains the unabridged output in its normal
`Testing/Temporary/LastTest.log`.
