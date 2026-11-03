# Matched CNet admission measurements

This is the first measurement slice of [#189](https://github.com/qigao/salts-core/issues/189).
It compares native CNet admission with an additional host admission callback on
the same retained TCP send path. It is not a raw-socket/NativeIO baseline, TLS
benchmark, multi-Owner scheduler comparison or a claim about production QoS.

## Matched protocol

Each sample uses one fixed caller Owner, an external CNet client and its one
NativeIO backend, plus an independent native TCP peer driven on the same thread.
Both modes use the same backend, completion batch, TCP_NODELAY setting, immutable
32-KiB source, payload order, send limits and peer read budget. One in eight
writes is one byte; the other seven are 32 KiB. No TLS is used. Connection setup,
source creation and warm-up precede measurement; close/drain follows it.

The baseline uses the native hard send bounds. The composed mode adds a pure
per-connection callback checking the same operation and byte bounds; it never
owns payload or overrides hard admission. Both use the same storage provider.
One outstanding write is the paced workload. Eight outstanding writes plus
one rejected offer exercise admission saturation. This does not prove TCP
kernel backpressure: the receiver continues bounded reads on every host turn.

Before enabling measurement, the existing TCP formal suite must run small
correctness cases for both modes and windows. They verify FIFO completion sizes,
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

Use multiple warmed samples, interleave mode order and retain every raw row.
Record source SHA, compiler/build profile, backend, host/architecture, capacities,
operation counts and repetitions. Do not infer an optimization or add an API
from a single platform or a small, noisy difference.

The full #189 gate still includes direct NativeIO, mixed independent bulk/control
connections, matched TLS, multiple Owners, copy/allocation instrumentation and
broader platform measurements. This first slice does not close that issue.

## Run through the existing formal target

The existing `saltscore.cnet_tcp_loopback` CTest always runs the four small
retained-transfer cases. No target, dependency or workflow is added. To opt in
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

Five repetitions interleave native/callback order. Each sample creates a fresh
connection, warms 64 writes, measures 2,048 writes and separately closes/drains.
The one-byte/32-KiB sequence repeats every eight operations. The existing test
timeout remains in force; no threshold compares the two modes.

Each `CNET_POLICY_CSV` row reports mode, repetition, window, operation/payload
counts, elapsed/CPU nanoseconds, local-send latency quantiles, full refusals,
peak logical/backing accounting, physical source bytes, hot-phase storage calls,
policy calls and close/drain nanoseconds. The TinyTest `benchmark_io` summary
also includes the driver's measurement bookkeeping; use the explicit row fields
for the scoped metrics above. CTest retains the unabridged output in its normal
`Testing/Temporary/LastTest.log`.
