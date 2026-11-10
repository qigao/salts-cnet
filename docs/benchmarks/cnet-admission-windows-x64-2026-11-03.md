# Native versus callback admission: Windows x64, 2026-11-03

Historical two-mode run. The later [three-way NativeIO/CNet comparison](cnet-nativeio-windows-x64-2026-11-03.md)
uses one matched source revision and an aligned connection-drain interval. Do not
pool these cohorts or use the earlier callback difference as a stable penalty.

Measured source: `5397736dca92e13abd7589b9e1a75c545c29d784`, based on master
`c888705263dffbcb93a480e074d8e8d450635645`. Later commits add this evidence and
an explicit clean-close assertion outside the measured transfer. See the
[protocol at the measured revision](https://github.com/qigao/salts-core/blob/5397736dca92e13abd7589b9e1a75c545c29d784/docs/CNET-POLICY-BENCHMARK.md)
and [all 20 raw samples](cnet-admission-windows-x64-2026-11-03.csv).

## Configuration

- Windows 11, OS version 10.0.26200, x64; AMD Ryzen 9 7940HX, 16 cores/32 threads.
- LLVM-MinGW 20261020; Clang 23.1.4, LLVM source
  `7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`, target x86_64-w64-windows-gnu.
- `native-release-user`, Release, full graph build; existing TCP CTest with
  `cnet_POLICY_BENCHMARK=1`. Existing timeout unchanged.
- IOCP; one fixed caller Owner, one CNet client/connection, one backend with
  2 endpoint slots, 4 requests and completion batch 4. Native peer shares the
  caller thread; no affinity, CPU-frequency or system-background-load control.
- Plain TCP, sender TCP_NODELAY; no TLS. Command capacity 8, operation limit
  1 or 8, max write 32 KiB, byte limit derived identically in both modes.
- One immutable 32-KiB physical source. Each eight-write cycle has one byte
  followed by seven 32-KiB writes; 64 warm-up writes, then 2,048 measured writes
  totaling 58,720,512 application bytes per sample. Peer reads at most sixteen
  64-KiB chunks per host turn and verifies the exact expected byte sequence.
- Five fresh, warmed samples per mode/window, with native/callback order
  alternating by repetition. Measurements include common host/peer validation.
  Close/drain follows the transfer; no payload allocation/setup is timed.

## Observations

Entries are medians of five samples. Latency columns are medians of the five
per-sample quantiles, not quantiles pooled across all operations. Local-send
latencies combine both payload sizes and do not represent response/business ACK.

| Window | Mode | MiB/s median (min–max) | Process CPU µs/op | p50 µs | p95 µs | p99 µs | Close/drain µs |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1, paced | Native CNet | 640.17 (608.43–652.15) | 45.78 | 6.8 | 8.3 | 10.7 | 70.8 |
| 1, paced | Additional callback | 602.32 (593.85–613.56) | 45.78 | 7.1 | 9.1 | 11.5 | 63.8 |
| 8, admission saturated | Native CNet | 616.56 (584.04–634.54) | 45.78 | 305.9 | 389.9 | 446.3 | 78.4 |
| 8, admission saturated | Additional callback | 604.64 (585.66–637.46) | 45.78 | 305.9 | 395.7 | 461.4 | 72.3 |

Every measured phase made zero calls to the configured CNet storage allocator.
This is not a global allocation count. Every callback-mode sample evaluated the
policy 2,048 times; native mode evaluated none. Paced samples had no deliberate
full refusal; every window-8 sample had 2,040 ENOBUFS refusals with no lasting
retain. These are admission-capacity refusals, not proof of an OS-stalled send.

Peak CNet logical-byte usage was 32,768 at window 1 and 229,377 at window 8.
Peak conservative backing accounting was 32,768 and 262,144 respectively, while
the actual shared source remained 32,768 bytes in both. Every sample reached
zero CNet usage, sole host source reference, peer FIN, zero native requests and
endpoints, and complete provider allocation/release balance. The full formal
CTest run passed all 47 TinyTest cases, including four small transfer cases and
the optional measurement case, in 3.48 seconds.

GetProcessTimes advanced in coarse 15.625-ms increments in these samples, so the
identical median CPU/op cannot resolve callback CPU overhead. The paced callback
samples had lower measured throughput in this run, while the saturated ranges
overlapped substantially. Five samples on one uncontrolled host do not establish
a general policy penalty or justify a new fast path/API. No optimization follows
from this result alone.

## Remaining #189 evidence

Direct NativeIO versus CNet, independent bulk/control connections, multiple
Owners, TLS, real kernel-stalled workloads, global/copy instrumentation and
broader platform measurements remain open. CNet's retained-plaintext contract
does not instrument OS copies. The present output establishes a reproducible
matched admission slice with checked lifetimes; it does not close #189.
