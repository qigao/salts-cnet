# TLS CPU sampling protocol

Historical protocol: the `cnet_cpu_profile` workflow input and diagnostic CMake
switches described below have been retired. The collected report remains
evidence for its recorded revision. Current CI runs ordinary public presets
and their full CTest suite, without a separate profiling setup.

This #214 slice profiles the current provider before changing its scratch
allocation. Keep the production dependency, compiler flags and existing TLS
workload unchanged. Reuse the 25 formal CTests, five rotated repetitions of
direct/native/callback at depth 1 and native/callback at depth 8. Each process
still checks actual bytes, source references, bounded usage, native identities,
rejection, authenticated close and complete native drain. No new executable,
consumer, smoke project, validation script or benchmark-only job is added.
The [qualified report and raw rows](benchmarks/cnet-tls-cpu-2026-11-04.md)
record the observed CPU distribution, coverage limits and scratch decision.

## Protocol before collection

First preserve the ordinary full native suite and its 25 measurement cases on
Linux x64. Then reconfigure/build the same full graph with
`cnet_TLS_MIXED_PERF=ON` and run the existing measurement CTest label.
The option requires Linux, measurements and an unsanitized graph, and rejects
heaptrack or source-copy instrumentation. Missing tools or unsupported
sampling/permissions fail explicitly. The default remains off.

`perf record` launches each existing formal executable, selecting only user
space `cpu-clock` samples at a strict requested 4,000 Hz. Use DWARF callchains
with an 8,192-byte stack dump so optimized code does not require frame-pointer
or dependency/compiler changes. This is time-based sampling, not hardware
cycles, instruction counts, allocation counts or a stopwatch around malloc.
Record actual sample periods and loss/unwind diagnostics; do not treat zero
observed allocator samples as zero allocator CPU cost. Keep all repetitions.

The existing LLVM workflow accepts `cnet_cpu_profile=true`. Only Linux x64
adds the 25 native cases and their subsequent sampled run; other lanes retain
their ordinary formal suite. Install matching-kernel perf and libc debug
symbols as analysis tools. Temporarily permit user-mode perf on the ephemeral
runner and restore its original kernel setting when the step exits. The
workload itself runs as the normal runner user, with no system-wide recording.

Preserve native and sampled timing/work/adapter rows as separate cohorts.
Sampled timings include profiler overhead; do not infer an optimization or
stable profiling overhead from their difference. Capture source, host, project
compiler, perf/libc versions, dependency status and loaded-module build IDs.
Package/compiler versions are distinct from the project compiler identity.

Convert each recording on its original host into all captured symbolized stacks
with periods, flat and inclusive reports, build IDs and diagnostic output.
Publish these and the original recording SHA256; raw stack-memory dumps remain
local to that ephemeral runner. Keep unknown frames and lost-event messages.
This preserves the numerical sampling evidence without publishing stack bytes.

## Analysis and decision gate

Report whole-process and stacks containing `tls_mixed_phase` separately.
The latter contains warm/transfer and both drains, excluding handshake/close
when the captured callchain resolves that boundary. Report unresolved and
truncated chains rather than silently assigning them to an unrelated category.
Use recorded periods for CPU shares, retain sample counts and denominators,
and preserve each repetition's result rather than pooling unlike work amounts.

Classify allocator descendants under `tls13_gcm_encrypt` separately from
encryption, copies, other provider operations, polling/native calls and test
validation. Inclusive provider time is not allocator time. Sum mutually
exclusive self samples for overall cost; ancestor percentages overlap.
State coverage limits and sampling uncertainty before judging a small share.

Only pursue bounded scratch reuse if this evidence justifies its complexity
and retained-capacity cost. A candidate must define exact record capacity,
exclusive stream ownership, retries/profile behavior, wipe/reuse lifetime,
failure preservation and native drain, then measure allocation versus retained
capacity, CPU, throughput and latency with the same formal workloads. Otherwise
record the decision to retain the current provider. This sampling slice alone
does not implement reuse, remove copies or establish a performance gain.

Upstream contracts: [perf record](https://github.com/torvalds/linux/blob/v6.8/tools/perf/Documentation/perf-record.txt),
[perf script](https://github.com/torvalds/linux/blob/v6.8/tools/perf/Documentation/perf-script.txt),
[perf report](https://github.com/torvalds/linux/blob/v6.8/tools/perf/Documentation/perf-report.txt),
[perf access controls](https://www.kernel.org/doc/html/v6.12/admin-guide/perf-security.html).
