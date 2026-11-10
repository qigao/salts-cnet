# Direct NativeIO and CNet TLS — Windows x64, 2026-11-04

Measured source: `f1cf6e82f9416c1b0d6ff1d1adcbca558e4fae28`.
[All 15 final rows](cnet-native-tls-windows-x64-2026-11-04.csv) preserve sample
order. The [protocol](../CNET-NATIVE-TLS-BENCHMARK.md) defines ownership, native
continuation, authenticated close and metric scopes.

## Reproduction

Windows 11 10.0.26200, AMD Ryzen 9 7940HX, 16 cores/32 threads; no affinity,
frequency or background-load control. LLVM-MinGW 20261020, Clang 23.1.4
(`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`), x86_64-w64-windows-gnu,
`native-release-user` Release, GmSSL 3.2.0#18. Collection: 2026-11-04
Asia/Shanghai. Build the full graph with the existing preset.

The existing Crypto TLS ABI executable now also runs the direct NativeIO
fixture. Its production Crypto is linked statically; it imports Core/NativeIO
and **does not import CNet**. The CNet test continues to use production CNet's
private Crypto instance. Comparing separate processes avoids two physical TLS
implementations in one process. No new project, target, consumer or smoke test.

Each fresh sample warms 64 writes, then measures 2,048 at depth 1. Rotate
direct/native/callback by repetition index over five repetitions. Run the
existing formal executables with TinyTest's standard case filter; require
exactly one selected long case and one data row from each invocation:

```powershell
$env:SALTSCORE_NATIVE_TLS_BENCHMARK = '1'
$env:cnet_TLS_BENCHMARK = '1'
# Repetition 0; subsequent repetitions rotate this order and change the index.
& build/native-release-user/bin/saltscore_gmssl_tls_io_abi_test.exe --filter `
  'measures direct NativeIO TLS transfer repetition 0'
& build/native-release-user/bin/cnet_tls_ca_san_test.exe --filter `
  'measures verified TLS policy traffic, repetition 0 scenario 0'
& build/native-release-user/bin/cnet_tls_ca_san_test.exe --filter `
  'measures verified TLS policy traffic, repetition 0 scenario 1'
```

All 15 selected long cases passed. The other discovered cases are deliberately
FILTERED in these collection processes; this is not full-suite qualification.
The full Release build and two changed unfiltered CTests passed in 1.26 s.
All six existing Crypto/CNet TLS/mTLS CTests also passed during implementation
(9.72 s), including independent Python TLS 1.2/1.3 peers. Default CI executes
the complete short suites, including full-buffer and 4-KiB-bounded raw writes.
The bounded case requires actual native continuation and complete byte/close
validation; it does not manufacture natural short completions or OS pressure.

## Matched data path and observations

One caller Owner progresses both TLS ends with two native backends, each
2 endpoints / 8 requests / batch 4. Same p384 CA/certificate/key, verified
localhost SAN, standard security profile, NODELAY, 17-KiB TLS I/O buffers and
32-KiB plaintext receive capacity. Each repeating group has one one-byte and
seven 32-KiB writes from one immutable pooled source. All rows negotiated
**TLSv1.3 / TLS_AES_128_GCM_SHA256** at both ends. Raw has no application FIFO;
it retains one source through complete Crypto acceptance and actual ciphertext
completion. CNet uses its bounded retained-slice path.

Values are medians of five per-sample values. Quantiles use nearest rank within
each sample; this table does not pool individual latency observations.

| Mode | MiB/s median (range) | Send p50 / p95 / p99 ms | Process CPU µs/write | Close/drain ms |
| --- | ---: | ---: | ---: | ---: |
| Direct NativeIO | 19.93 (18.55–20.16) | 1.136 / 1.408 / 1.719 | 1365.66 | 0.279 |
| Native CNet | 20.14 (15.71–20.50) | 1.135 / 1.385 / 1.646 | 1358.03 | 0.360 |
| Callback | 19.83 (18.46–20.68) | 1.143 / 1.450 / 1.745 | 1380.92 | 0.406 |

Ranges overlap and the native CNet cohort includes a 15.71-MiB/s sample; every
row is retained. These observations do not establish an isolated CNet/callback
overhead, speedup, general latency bound or optimization. Process CPU includes
both TLS ends, host polling and every-byte verification, and uses Windows
GetProcessTimes with 15.625-ms increments. Different wrappers have different
instruction/control paths despite matched transport settings and offered load.

Transfer timing includes send admission and ends after all local terminals and
verified plaintext peer bytes. Send latency starts before the send-admission
call and ends at local completion, not a peer acknowledgment or RTT. Raw
handshake timing excludes TCP/context setup; CNet's handshake column includes
connect admission and client context creation. Do **not** compare handshake
columns as matched TLS overhead. Close/drain ends after authenticated reciprocal
close_notify and native/request/endpoint drain, before stream/client destruction.

Every row verified **58,720,512 plaintext bytes**, 2,048 local terminals and
7,680 combined native submissions. Callback rows invoked the extra gate 2,048
times; other rows invoked none. Paced depth 1 had zero deliberate refusals.
Logical/backing peaks and physical source capacity were all 32,768 bytes.
Every phase ended with sole source ownership, followed by clean authenticated
shutdown, zero native requests/endpoints and complete destruction.

Measured CNet storage allocations and receive acquisitions were zero; admission
precedes measurement. Raw has no CNet providers, so zeros in those columns are
trivial absence of provider calls. Neither mode instruments Crypto/GmSSL,
NativeIO/global allocation, TLS transformation copies or OS copies. No
allocation-free or zero-copy TLS claim follows.

A [15-row pilot](cnet-native-tls-windows-x64-2026-11-04-pilot.csv), measured at
`5d0bff4ca69710545a443670299a1d040a9f798e`, used the raw latency timestamp after
retain. Preserve it separately; final source moves the timestamp before
admission to match CNet. Do not pool the pilot with the final cohort or with
#207's separate depth-1/depth-8 cohort.

This supplies the depth-1 direct secure NativeIO comparison under #189.
Independent TLS bulk/control, global allocation/copy instrumentation and
other-platform timing evidence remain open. Raw depth 8 is not claimed.
