# Retained TLS admission benchmark

This slice of #189 compares CNet's native hard send limits with an additional
per-connection admission callback, using the production CNet -> Crypto -> GmSSL
path. The existing `saltscore.cnet_tls_ca_san` formal test owns the workload.
No second Crypto linkage, provider, runtime or consumer project is introduced.

## Protocol

One caller thread owns both ends of one loopback TLS connection. Each end has
one external NativeIO backend, with 2 endpoints, 8 requests and batch 4. Each
CNet client has one connection, 16 commands/events, 8 requests, batch 4,
32-KiB maximum send/receive and the existing minimum TLS I/O buffer. Both ends
use NODELAY. The standard security profile verifies the fixture CA and
`localhost` SAN. The public profile negotiates TLS 1.2/1.3; each row records and
checks the actual version/cipher at both ends. This is not a version-pinned or
direct NativeIO TLS comparison. Context initialization precedes handshake timing;
connect admission through authenticated READY at both ends is timed separately.

One immutable pooled 32-KiB source belongs to the fixture. Repeating groups of
eight writes contain one byte followed by seven 32-KiB writes. Each admitted
slice retains one source reference until its FIFO local send terminal. A
callback validates every terminal's size; the receiver independently validates
every plaintext byte across arbitrary TLS record/callback boundaries. Receive
views are borrowed only during the callback. No callback reenters its Owner.
The host supplies bounded receive demand outside callbacks.

Depth 1 is paced; depth 8 fills the hard operation limit and deliberately offers
one more write before progress. ENOBUFS must retain nothing. This is admission
saturation, not an OS pressure or fairness claim. Callback mode adds the same
operation/logical/backing checks after the native hard limits. Its borrowed
fixture context lives through terminal notification and destruction. Rejections
at the hard limit do not invoke the extra gate. Both modes have identical
capacity, payload and closed-loop offering rules.

Fresh samples warm/drain 64 writes, then measure 2,048 writes. Five repetitions
rotate the four mode/depth scenarios. Default CI uses four short correctness
cases with eight warm and sixteen measured writes. Set
`SALTSCORE_CNET_TLS_BENCHMARK=1` for the long TinyTest `benchmark_io` samples.
Use the established full configure/build/test presets; no extra target is needed.

Transfer timing ends only after all local terminals and verified peer bytes.
Local-send p50/p95/p99 are enqueue-to-local-terminal latency, not peer RTT or
delivery acknowledgments. Process CPU includes both TLS ends, polling and byte
verification. Native submissions count both backends. Storage allocation and
receive acquisition counters cover CNet providers only, excluding Crypto/GmSSL,
NativeIO, global allocation, TLS transformations and OS copies. Retained logical
and accounted backing peaks count each operation; physical source capacity is
reported separately. No zero-copy claim is made for TLS.

After each phase require zero send usage and sole source ownership. After the
measured phase, close and progress both ends to exactly one clean terminal,
stop/drain clients and require zero native requests/endpoints before destruction.
Provider allocation/release totals must balance. Close/drain is timed separately.
All loops have deadlines. On error, attempt bounded drain; preserve any still-live
fixture, source and callback/provider storage rather than freeing borrowed memory.

This slice leaves direct secure NativeIO, independent TLS bulk/control traffic,
global allocation/copy instrumentation and other-platform timing evidence open.
