# TLS CPU sampling and scratch decision — 2026-11-04

The observed CPU distribution does not justify introducing retained GCM
scratch for this workload. AES/GHASH account for approximately 98% of sampled
traffic CPU. Allocator descendants under `tls13_gcm_encrypt` account for seven
of 98,700 traffic-phase samples, with unresolved and sampling limits described
below. Keep the current provider and policy API; no reuse implementation or
performance gain is claimed.

Measured source: `1eed97774becdfbc4c2ee237a13c9498295e1747`.
[LLVM CI #273](https://github.com/qigao/salts-core/actions/runs/41796177710)
passed all ten matrix jobs and aggregate SUCCESS. Linux passed the full native
180/180 CTests (40.21 s), then all 25 sampled formal measurement cases (28.03 s).
The [protocol](../CNET-TLS-CPU-PROFILE.md) was committed before collection.
Production source, dependencies, compiler flags and workload are unchanged.
The opt-in CMake/CTest launcher and existing full LLVM job perform collection;
there is no extra executable, consumer/smoke project or probe CI.

## Preserved evidence

- [50 timing/work rows](cnet-tls-cpu-timing-2026-11-04.csv), 25 native and 25
  separately labelled perf samples, including CPU, p50/p95/p99, capacities,
  refusal counts, actual traffic, partial native work and drain.
- [300 adapter-memory phase rows](cnet-tls-cpu-adapter-2026-11-04.csv).
- [50 sampling summaries](cnet-tls-cpu-summary-2026-11-04.csv), process and
  mixed-phase scopes for each fresh process.
- [420 mutually exclusive category rows](cnet-tls-cpu-categories-2026-11-04.csv)
  and [1,863 self-symbol rows](cnet-tls-cpu-leaf-2026-11-04.csv).
- [25 recording/export identities and diagnostics](cnet-tls-cpu-recordings-2026-11-04.csv),
  [loaded module build IDs](cnet-tls-cpu-modules-2026-11-04.csv) and
  [artifact/host/compiler/package provenance](cnet-tls-cpu-provenance-2026-11-04.csv).

Artifact `13306100096`, `cnet-cpu-measurements-linux-x64`, ZIP SHA256
`fa2911db8e8bc1dc0056ba1a7fb5b4c9db2d039437d89eb32e2c60f830715504`
matches GitHub's digest. It retains every symbolized captured stack and period,
flat/inclusive reports, diagnostics, recording hashes, CTest logs, host/compiler
and dependency status. Raw stack-memory dumps were not uploaded. Numeric rows
are committed here beyond the artifact's expiration.

Host: Ubuntu 24.04.5, image `20261025.353.1`, kernel `7.0.0-1017-azure`, AMD
EPYC 9V45, four logical CPUs. Project: Clang 18.1.3, Ninja Release, `ci-native`.
perf 7.0.14 has libdw/DWARF unwinding enabled; libc and libc debug symbols are
both `2.39-0ubuntu8.9`. libc did not change during tool installation. No affinity,
frequency or background-load control. Canonical vcpkg-cache v0.1.5 remains at
`f1caf997152e4830d7e1089fceaf77aa9127ec25`; GmSSL 3.2.0#18, x64-linux package
ABI `2befd56dd234aea326f59706c426dd219691ac934fb99085e18487363a327aef`.
This project compiler identity does not independently identify the package's
compiler/version/flags. Loaded build IDs preserve the actual sampled modules.
Compiler cache hit 461/467 (98.72%); content/input validation remained enabled.

## CPU distribution

One owner drives both ends of two TLS connections with the same bounded
NativeIO/CNet resources and verified TLSv1.3 / TLS_AES_128_GCM_SHA256 as the
earlier workload. Each fresh process warms/drains eight request/replies,
measures 512, drains bulk, then authenticates close and completes native drain.
All existing byte/sequence/reference/usage/native-identity and refusal checks
passed. Closed-loop modes perform different bulk work; inclusive or total
process cost must not be called isolated CNet overhead.

Sampling uses user-mode `cpu-clock` at a strict requested 4,000 Hz, DWARF stack
dump 8,192 bytes, without provider-copy instrumentation, heaptrack or sanitizers.
All 100,743 captured samples have a 250,000-ns period. The flat self histogram
and complete captured-stack export agree exactly on sample counts and period
sums for every recording. All 25 report zero lost samples; the stack exports
contain no lost-event records. Of these, 98,700 samples resolve a
`tls_mixed_phase` ancestor, covering warm/transfer and both drains. Process
scope also includes setup/handshake/close and remains separately available.
The full-process export also contains exactly seven GCM allocator-descendant
samples, plus four other allocator samples. The phase selection did not discard
an observed GCM allocator stack. All 48 unresolved process samples are already
included in the phase unknown count.

Percentages below are medians of five per-process weighted-period shares
within resolved mixed-phase stacks. Allocator columns preserve all five
repetitions, including zeros. Category shares use self samples; inclusive
ancestors overlap and are not added to these percentages.

| Mode / depth | Phase samples per repetition | AES self median | GHASH self median | GCM allocator samples, repetitions 0–4 | Allocator share range |
| --- | --- | ---: | ---: | --- | ---: |
| Direct / 1 | 4,210–4,347 | 46.498% | 52.036% | 0, 0, 0, 0, 0 | 0% observed |
| Native / 1 | 3,783–3,936 | 46.417% | 51.423% | 1, 0, 1, 1, 0 | 0–0.02644% |
| Callback / 1 | 3,749–3,926 | 45.894% | 52.450% | 0, 0, 2, 0, 0 | 0–0.05335% |
| Native / 8 | 3,721–3,986 | 46.627% | 51.357% | 0, 1, 0, 0, 0 | 0–0.02637% |
| Callback / 8 | 3,845–3,989 | 45.982% | 52.260% | 0, 1, 0, 0, 0 | 0–0.02601% |

AES self symbols start `aes_`; GHASH self symbols start `gf128_` or `ghash`.
Allocator classification requires a malloc/free-family frame below the GCM
encrypt ancestor, and precedes the other self categories. General allocator,
copy/clear, TLS adapter/provider, native/CNet, workload and unknown categories
are separate. A libc symbol such as `__memmove_avx512_unaligned_erms` denotes
the sampled machine copy routine; it does not change #215's source-level
memcpy/memmove classification.

Unresolved self/chain samples total 48/98,700; the largest individual phase
unknown share is 0.18206%. Captured phase chains reach the workload boundary
but not `main/_start`: the finite dump ends within the TinyTest caller frames.
Do not call these complete process backtraces or assign unresolved samples to
malloc. A zero/small sample count is not zero cost, an allocator-call count,
per-call latency or a statistical upper bound. Fixed-rate sampling can alias
periodic work; no independence or worst-case latency guarantee is asserted.

Every optional `perf report --header` print emitted
`Invalid HEADER_EVENT_DESC: nre=1 sz=144 (min 64)` and marked the extended
event description unavailable. These diagnostics are preserved in all 25
recording rows and original stderr files. Script/inclusive-report stderr is
empty; event names/periods decode and histogram/export totals match. Source,
command configuration, versions and modules are captured independently. This
is a limitation of the optional metadata report, not evidence of a fully
decoded header; its upstream cause has not been independently resolved.

## Bounded-scratch review and decision

The earlier heap/copy reports establish real per-record allocation and input
copies; this profile does not establish them as a CPU bottleneck. A possible
per-stream reservation would avoid repeated allocation, but requires the
following protocol before any provider change:

- Capacity: the observed send path clamps plaintext to 16,384 bytes and this
  pinned provider currently chooses zero padding. Its existing largest
  `inlen + 256` request is 16,640 bytes; a zero-padding-only scratch needs at
  least 16,385. These are current-path calculations, not general bounds on
  arbitrary public GCM inputs or TLS1.3 padding. Validate type/padding/capacity
  with checked arithmetic before mutation; do not silently grow or change
  public input semantics.
- Ownership: scratch belongs exclusively to a stream/provider operation,
  rather than a shared read-only context, CNet storage-provider binding or
  global allocator override. Reserve before traffic; failed reservation must
  unwind creation. Borrow input only through the synchronous encryption;
  preserve current retained caller source and cipher/native ownership.
- Retry/terminal: construct each record once. WANT_WRITE must continue the
  same ciphertext/sequence rather than re-encrypt or overwrite it. Scratch
  can be reused after synchronous encryption, while provider/native ciphertext
  keeps its own lifetime. Read/probe/pending plaintext must not alias scratch;
  current Crypto already prevents provider receive while a write is incomplete.
  Cancellation and authenticated close must retain native buffers until drain.
- Wipe/profile: clear used plaintext on success/failure before reuse/release;
  clearing adds work that must be measured. Keep TLS1.2/TLCP behavior and
  AES/SM4 GCM profile semantics, verification and failure ownership intact.
  Existing provider buffers are not automatically spare writable storage.

At a conservative 16,640 bytes per stream, four ends would retain 66,560 extra
bytes (65 KiB), and 10,000 streams 166,400,000 bytes (158.69 MiB), excluding
allocator metadata. These are capacity calculations for an unimplemented
candidate, not measured allocation savings, RSS or a new peak. Reusing an
existing provider buffer might avoid that reservation but requires its own
alias/retry/lifetime proof. A process/thread-global scratch would introduce
different sharing and reentrancy contracts.

The CPU gate therefore rejects adding scratch reuse in this iteration. Keep
production dependencies and the existing policy API. No candidate was built,
so there is no before/after gain, zero-allocation claim, new lifetime guarantee
or measured candidate capacity/latency tradeoff. Reconsider only with an explicit
allocation-budget requirement or representative evidence that justifies the
change. This is an evaluation decision, not an implemented optimization.
