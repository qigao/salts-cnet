# Direct NativeIO TLS comparison

This #189 slice adds the secure direct baseline to the existing production
TLS admission cohort. It reuses `saltscore.gmssl_tls_io_abi`: that executable
links production Crypto, Core and NativeIO, with no CNet linkage. The CNet
executable continues to link only CNet/TinyTest. Each process has one physical
Crypto/GmSSL implementation. No extra project, runtime, consumer or smoke test.

## Ownership and workload protocol

One caller Owner progresses a verified TLS client/server pair over loopback.
Both native backends reserve 2 endpoints / 8 requests / batch 4. Match CNet's
standard security profile, p384 CA/certificate/key, localhost SAN, NODELAY,
17-KiB TLS I/O buffers and 32-KiB plaintext receive capacity. Record and require
matching authenticated version/cipher at both ends and across compared rows.
Raw socket/connect/context setup precedes its TLS handshake timer. CNet's older
handshake timer also includes connection admission and client context setup;
these handshake columns are not a matched overhead comparison.

One immutable pooled 32-KiB source supplies repeating groups of one one-byte
write and seven 32-KiB writes. Direct depth 1 has no application FIFO. Successful
admission retains one source reference until Crypto accepts the whole identical
plaintext range AND every generated ciphertext byte completes locally. A second
offer while retained returns ENOBUFS without another reference. Never release
the plaintext merely because Crypto accepted it or a native prefix completed.
The sender records enqueue-to-local-terminal latency; every peer plaintext byte
is independently validated across TLS record/read boundaries. This is not RTT.

The host owns actual NativeIO request/endpoint generations and tokens. Each end
has at most one native read and one write. Stable Crypto I/O buffers remain
borrowed until matching completions are observed. Bound each read by current
cipher input capacity. Never overwrite/refill the encrypted write buffer while
NativeIO borrows it. Continue actual short sends with the unsent range and a new
request identity; do not fabricate completions. Route the entire observed batch
on error. The extra short correctness case bounds native write submissions to
4 KiB; it qualifies continuation, not kernel-pressure or natural short writes.

Fresh samples warm/drain 64 writes, then measure 2,048. Transfer ends after all
local terminals and all expected plaintext bytes. Setup, handshake and close
are separate. Record process CPU (both TLS ends, host polling and validation),
local-send quantiles, native submissions, logical/backing peaks and physical
source size. Direct mode has no CNet provider calls; zeros in those columns do
not instrument Crypto/NativeIO/global allocations or copies.

Normal formal tests use eight warm and sixteen measured writes. Opt in with
`SALTSCORE_NATIVE_TLS_BENCHMARK=1` for five long direct samples; CNet retains
`SALTSCORE_CNET_TLS_BENCHMARK=1`. Use each existing TinyTest executable's
`--filter` to select one long repetition/scenario, rotating direct/native/
callback order over five repetitions. Match depth 1 only; raw depth 8 would
need a different application queue contract. Retain all raw CSV rows, exact
measured source, environment and filtered test results. Use the established
full configure/build presets and existing formal test executables.

After each phase require sole source ownership and no outstanding logical send.
Close must exchange authenticated reciprocal close_notify, flush ciphertext,
then cancel/drain remaining native reads. Require zero native requests/endpoints
before destroying streams/contexts/backends and releasing backing. EOF alone
cannot qualify TLS close. Every loop has a deadline. Failure cleanup stops new
submissions, cancels and observes all native borrows; preserve live fixture,
stream and source storage if bounded drain fails.

This compares two formal executables using the same production primitives,
not identical application instruction sequences. Validate bytes/retention/close
before interpreting timing. Independent TLS bulk/control, global allocation/
copy instrumentation and other-platform timing cohorts remain open in #189.
