# Independent TLS bulk/control — Windows x64, 2026-11-04

Measured source: `3f4017298c27384bf9ca19aaffc6038d705d9d8c`.
[All 25 rows](cnet-tls-mixed-windows-x64-2026-11-04.csv) preserve rotated order.
The [protocol](../CNET-TLS-MIXED-BENCHMARK.md) defines ownership and scopes.

## Reproduction and topology

Windows 11 10.0.26200, AMD Ryzen 9 7940HX, 16 cores/32 threads; no affinity,
frequency or background-load control. LLVM-MinGW 20261020, Clang 23.1.4
(`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`), x86_64-w64-windows-gnu,
`native-release-user` Release. Canonical vcpkg-cache v0.1.5
(`f1caf997152e4830d7e1089fceaf77aa9127ec25`), GmSSL 3.2.0#18; its unchanged
port tree is `3b06c785649c2cd632c319375e9bc08e53296b39`. Collection was
2026-11-04 Asia/Shanghai after full-graph configuration/build.

One fixed caller Owner progresses two independent TLS connections and both
peer ends. Four backends each reserve 2 endpoints / 8 requests / batch 4,
aggregate 8/32/16. Four CNet clients each own one connection, or four direct
Crypto streams use NativeIO. There is no shared-single-backend claim. Match
p384 CA/certificate/key, localhost SAN, standard TLS, NODELAY, 17-KiB TLS I/O
and 32-KiB plaintext receive capacity. All four ends in every row negotiated
**TLSv1.3 / TLS_AES_128_GCM_SHA256**. Setup/handshakes precede measurement.

The same private workload header drives both existing formal executables:
offering, credit, byte/sequence validation, RTT, usage checks and phase drain.
Bulk uses one immutable 32-KiB source; control owns one-byte request/reply
sources and permits one exchange at a time. Callbacks validate/update state;
the ordinary host offers replies. No callback reenters CNet.

Warm eight exchanges and completely drain, then measure 512 per fresh process.
Five repetitions rotate all five scenarios so each occupies every order
position once. Use the existing TinyTest filters; each invocation must produce
exactly one selected long case and data row. For example:

```powershell
$env:SALTSCORE_NATIVE_TLS_MIXED_BENCHMARK = '1'
$env:cnet_TLS_MIXED_BENCHMARK = '1'
& build/native-release-user/bin/saltscore_gmssl_tls_io_abi_test.exe --filter `
  'measures direct mixed TLS control, repetition 0'
& build/native-release-user/bin/cnet_tls_ca_san_test.exe --filter `
  'measures mixed TLS control, repetition 0 scenario 0'
# CNet scenarios 1/2/3: callback depth 1, native depth 8, callback depth 8.
```

All 25 selected long formal cases passed. Raw runs intentionally FILTERED 24
other discovered cases; CNet runs FILTERED 31. Collection is not full-suite
qualification. Separate unfiltered local Crypto/CNet TLS/mTLS CTests passed
after the independent-peer correction (six CTests, 37.20 s). TLS 1.2 and 1.3
Python peer CTests each passed three consecutive repetitions (44.79 s total).
Default CI runs the unfiltered suites and six new short mixed scenarios.

## Observations and different amounts of work

Values are medians of five per-sample values; quantiles use nearest rank within
each sample and are not pooled. RTT starts before request admission and ends
at actual reply validation. Process CPU includes all four TLS ends, host
adapters/polling, usage checks and every-byte validation, with observed Windows
GetProcessTimes increments of 15.625 ms.

| Bulk depth | Mode | Bulk MiB/s median (range) | RTT p50 / p95 / p99 ms | CPU µs/exchange |
| --- | --- | ---: | ---: | ---: |
| 1 | Direct NativeIO | 5.35 (2.34–6.38) | 9.296 / 13.725 / 16.148 | 8666.99 |
| 1 | Native CNet | 5.50 (2.29–6.87) | 8.168 / 13.087 / 16.675 | 7873.54 |
| 1 | Callback | 3.09 (2.52–6.36) | 13.972 / 25.227 / 29.510 | 12054.44 |
| 8 | Native CNet | 3.10 (2.97–7.24) | 14.603 / 23.666 / 27.544 | 12939.45 |
| 8 | Callback | 3.92 (2.94–6.56) | 10.965 / 20.335 / 26.738 | 9979.25 |

There is substantial variation: intervals span 3.31–11.41 s; native depth-1
per-sample p99 spans 11.40–45.57 ms. Preserve every row. Throughput ranges
overlap and the apparent callback ordering reverses at depth 8. This does not
establish an isolated wrapper/callback cost, optimization, stable speedup or
general fairness/latency bound. No cause is assigned to the uncontrolled host
variation without profiling evidence.

The offered rule is closed-loop replenishment, not a fixed open-loop byte rate.
Direct rows execute 2,560 host rounds and validate 26.65625 MiB of bulk during
control, admitting 854 writes. CNet rows execute 1,536 rounds and validate
24 MiB, admitting 768 writes at depth 1 or 775 at depth 8. Wrappers have
different progress/event paths despite shared workload code and settings.
CPU/exchange therefore includes different bulk work and host rounds. Do not
infer fixed-work efficiency from the lower/higher medians or compare rates as
a TLS overhead factor against the earlier one-connection cohort.

Direct interval native submissions are 3,413 bulk / 2,048 control. CNet rows
record 3,072 bulk / 2,047 control. These are actual submitted-count differences
between phase snapshots, with existing native reads across boundaries, not a
portable per-exchange submission invariant. Subsequent rearming may belong to
drain/close. No completion, byte or read is fabricated to equalize counts.

Depth-8 rows require 1,536 ENOBUFS refusals with unchanged source references.
This is deliberate admission saturation, not measured kernel pressure. Callback
rows invoke the extra gate 1,792 times at depth 1 and 1,799 at depth 8: bulk
admissions plus 1,024 request/reply admissions. Hard-limit refusals do not invoke
that gate; native/direct rows invoke none.

## Retention, drain and qualification limits

All physical sources sum to 32,784 bytes: bulk 32,768 and two eight-byte backing
capacities holding one-byte control payloads. Depth-1 peak logical/accounted
backing is 32,769/32,776 bytes; depth-8 is 262,145/262,152. Repeated logical
references to the one bulk backing are conservatively accounted per operation;
these are not process RSS or distinct physical bytes.

After control, direct rows drain one further 32-KiB write (median 2.436 ms,
three additional native submissions). Native/callback depth 1 have no further
bulk bytes; their 100-ns median empty-drain timer is bookkeeping, not throughput.
Depth 8 drains seven more writes (229,376 bytes), with median native/callback
drain times 60.638/39.148 ms and 29 further combined native submissions. Every
row verifies interval bytes + drain bytes = all admitted bytes. Each phase
ends with zero logical usage, exact terminals and sole source ownership.

Close then requires reciprocal authenticated close_notify and zero native
requests/endpoints before complete teardown. The close field sums the two pair
close/drain sections, excluding object destruction between them; it is not a
continuous wall-clock interval or isolated API overhead measure. CNet storage
allocation/release balances are checked at destruction. Failure cleanup keeps
the whole parent/source/provider context if quiescence cannot be proved.

Measured CNet storage allocations and receive acquisitions were zero; those
receives were admitted before measurement. Raw has no CNet providers, so its
zeros do not instrument an allocator. Crypto/GmSSL, NativeIO/global allocation,
TLS transformation and OS copies remain unmeasured. No allocation-free or
zero-copy claim follows.

This supplies independent TLS bulk/control evidence under #189. Raw depth 8
is unclaimed; it would require a new application queue contract. Global
allocation/copy instrumentation and other-platform timings remain open.
