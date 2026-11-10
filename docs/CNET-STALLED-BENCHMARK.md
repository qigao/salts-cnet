# Control progress with a kernel-stalled bulk connection

This #189 workload extends the existing mixed TCP fixture with one fixed Owner,
two independent connections and one NativeIO backend (2 endpoints, 8 requests,
batch 4). Compare direct NativeIO, native CNet and an additional per-connection
admission callback. It adds no production policy, observer, queue or worker.

## Ownership and pressure protocol

Bulk depth is one retained immutable 8-MiB source; control has one retained byte
and a fixed 256-byte receive buffer. Sources stay immutable through their actual
native completions. Direct mode creates no CNet client. CNet uses its existing
retained write and receive paths. The host alone observes and routes the whole
batch; the same host services both peers.

Set the bulk peer receive buffer to 64 KiB before connect and connection send
buffers to 4 KiB, recording the effective bulk values after OS adjustment.
TCP_NODELAY is enabled on all sockets. Listeners retire before warm-up. Socket
buffer settings alone do not prove a kernel stall.

First pause all bulk peer reads. Offer one 8-MiB write and advance NativeIO.
If a whole write completes while the peer is paused, at most four completed
writes may prime the transport; admit the next using the same immutable source.
This is bounded pressure preparation, not a replay or a second send queue.
Record total admitted writes, native submissions and preparation time.

The pressure gate requires two real 25-ms NativeIO observation timeouts with
zero returned completions, one active bulk STREAM_SEND, the same native request
slot/generation across both timeouts, one retained logical write, and source
reference count two. Only one pending bulk request exists at this point. A full
admission queue or a completion held by the host cannot satisfy this gate.

Then measure sequential one-byte control requests/replies while bulk peer reads
remain paused and bulk replenishment is sealed. RTT starts at control send
admission and ends at validation of the actual reply. Source reuse additionally
waits for local send completion. The same logical bulk write must remain pending,
with source reference count two, one full logical/backing reservation and zero
bulk peer bytes read, checked after every progress round. Paused application
reads do not freeze TCP ACKs or kernel buffering: a real NativeIO prefix may
retire one native request and submit its continuation. Require a live bulk send
at the interval's end, validate every actual completion identity, and account
each additional submission against a successfully routed bulk prefix terminal.
The total interval submissions must equal two per control exchange plus those
bulk prefix terminals. Do not require the entry and exit native IDs to match.
Record control quantiles, elapsed/process CPU time, native submissions and scoped
resource/provider counts; no bulk-throughput claim belongs to this paused phase.

Finally resume bounded nonblocking bulk reads on the same host. Route real
prefix completions, verify every byte of every admitted write, and separately
measure drain bytes/time/native submissions. Both source references must return
to one and native requests to zero before connection close. Require both peer
FINs, zero backend endpoints, CNet clean terminals where applicable and complete
teardown. Error cleanup cancels/drains admitted requests before releasing their
backing. Failure to establish the real pressure gate fails the scenario.

Each fresh sample warms eight control exchanges with a complete pressure/drain
cycle, then repeats the cycle for measurement. Existing formal TCP tests run
eight measured exchanges for each mode. Larger local measurements opt in with
`cnet_STALLED_BENCHMARK=1`, using five rotated repetitions of 4,096
exchanges per mode. Other flag values fail. Use the full build and existing
`saltscore.cnet_tcp_loopback` CTest; no extra project, target or workflow.

```powershell
$env:cnet_STALLED_BENCHMARK = '1'
ctest --preset native-release-user -R '^saltscore\.cnet_tcp_loopback$' -V
Remove-Item Env:cnet_STALLED_BENCHMARK
```

`CNET_STALLED_CSV` records mode/repetition, exchange count, bulk write bytes,
preparation admitted writes/native submissions/time, the two empty observations,
effective socket buffer bytes, control elapsed/CPU time and RTT quantiles,
total interval native submissions, bulk peer bytes read during control, host rounds,
control-only policy calls and provider counts, peak logical/backing bytes,
physical send-source bytes, resumed bytes/time/native submissions, and close
time. Additional fields record actual bulk native prefix terminals/bytes during
control and whether the pending native ID changed. Kernel-accepted bytes are
not peer application reads. Preparation and resumed bulk work are excluded from control CPU/latency.
The TinyTest benchmark duration includes the full pressure/drain cycle; the
explicit CSV intervals define each scoped metric.

The pressure preparation, paused control interval, resumed bulk drain and final
connection close are separate measurement intervals. Record their scopes and
effective socket bounds. CNet provider counters exclude global/NativeIO allocator
traffic and kernel/user copies. One uncontrolled host cannot establish general
scheduler fairness, QoS, callback cost or production latency bounds. Multiple
TLS and broader instrumentation/platform timings remain open in #189.

## Native identity correction (#208)

The original gate also required unchanged native identity through control and
exactly two interval submissions per exchange. macOS ARM64 CI #250 captured a
valid counterexample: all eight exchanges completed, zero bulk peer bytes were
read, the one logical bulk write was still pending and its source had two
references, but native identity changed and interval submissions were 32 rather
than 16. An application-level read pause cannot prohibit native prefix progress.
The corrected protocol checks retained logical ownership on every round and
records/validates actual prefix progress instead of interpreting it as failure.
Existing byte, terminal, rejection, pressure-entry and final drain checks remain.
No timeout, capacity or production behavior changes.

The [historical Windows cohort](benchmarks/cnet-stalled-windows-x64-2026-11-04.md)
used the earlier stricter identity gate;
its observed unchanged identity and zero extra interval submissions remain facts
about those saved rows, not portable properties of a stalled logical write.
