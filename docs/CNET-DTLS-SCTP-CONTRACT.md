# DTLS and SCTP channel admission and ownership contract

This is the first design slice of [#188](https://github.com/qigao/salts-core/issues/188).
It specifies a future production boundary. It adds no DTLS provider, public
channel API or supported URI. Production CNet continues to reject DTLS/SCTP
recipes until a real provider, bridge and qualification exist.

## Current implementation boundary

- `crypto/include/crypto/tls_stream.h` is an opaque TLS/TLCP byte-stream API.
  Its feed/take operations do not preserve UDP packet boundaries or provide
  DTLS flight, epoch, replay-window or retransmission semantics.
- `cnet_datagram` already supports one owned or borrowed NativeIO backend,
  copied UDP sends, real terminal callbacks and whole-batch external routing.
  Its receive views are borrowed through callback return. The lossless
  `cnet_datagram_received_endpoint()` query preserves IPv6 scope/flow identity.
- `cnet_packet_endpoint` owns its polling and supports UDP/KCP only. Its
  generation-checked session handles do not establish an external DTLS mode.
- `Salts::SCTP` exposes an experimental, synchronous, fixed-capacity C11 Session.
  It owns no socket, clock or DTLS authentication. Its `peer_binding` is a
  caller-supplied nonzero lifetime identity, not proof of authentication.
- `sctp/tests/independent/pion_dtls_transport.c` is a Linux test-only OpenSSL
  adapter. It uses a stream memory BIO, splits output records and calls
  `sendto()` directly. It is not a production datagram-preserving provider or
  a NativeIO bridge and must remain outside installed production targets.

No existing implementation meets the complete production contract below.
The provider/dependency choice remains explicit work; TLS must not silently
switch providers when DTLS is requested.

## Exact identity and admission

One channel has one fixed progress Owner. Its immutable identity consists of
the admitted provider and protocol version, role, security profile, local UDP
endpoint, complete remote endpoint, peer authentication policy and generation.
An endpoint includes family, address, port and applicable IPv6 scope/flow data;
normalizing a scoped peer to an unqualified address is not permitted.

Authentication policy must explicitly choose a qualified CA/name profile or an
out-of-band certificate fingerprint profile. Fingerprints must be exact-length
and compared without data-dependent timing. Missing trust or a failed peer
check cannot enable an insecure profile. Transport availability, handshake
completion and authenticated channel READY are separate states. No SCTP input,
SCTP Session creation or application plaintext publication precedes READY.

Admission validates all versions, identities, ownership and checked capacity
calculations before publishing a handle. Unsupported recipes return ENOTSUP;
invalid configuration returns EINVAL; exhausted fixed capacity returns ENOBUFS.
Rejection publishes no handle, owns no native request and leaves no lasting
provider/context reference. Initial server traffic must have a bounded
admission/anti-amplification policy before allocating per-peer handshake state.
No peer-address migration or DTLS Connection ID support is implied.

## Datagram and storage protocol

The topology is one Owner operating one channel and its provider state. A host
may cohost several channels on its existing NativeIO backend. It observes once
and routes the entire completion batch even when one channel fails. No provider
may call socket I/O, sleep, create a worker or independently observe that backend.

The provider must consume one complete encrypted UDP datagram at a time.
Several DTLS records may occupy that datagram. It must not concatenate separate
inputs into a byte stream, treat a truncated datagram as valid input or turn an
arbitrary stream-BIO chunk into an output packet. Output is likewise a complete
datagram with a known size and immutable bytes. Provider fragmentation/reassembly
and record packing follow its explicitly supported DTLS version.

| Storage | Owner and lifetime | Fixed bound and full behavior |
| --- | --- | --- |
| Receive datagram | NativeIO/CNet until receive callback return; provider must consume synchronously or copy into admitted storage | Configured UDP receive bytes; truncation rejects, no partial authentication |
| Handshake fragments and flights | Provider until protocol retirement or teardown | Explicit byte/count bounds, including reassembly and retained retransmission state; overflow fails the channel |
| Replay windows | Provider, scoped to authenticated association and record epoch | Version-specific fixed windows; duplicate/stale records never publish duplicate plaintext |
| Pending ciphertext | Provider until copied datagram admission succeeds | Fixed output byte/packet capacity; full preserves pending output without advancing it twice |
| Admitted UDP output | `cnet_datagram` owns its copy through the real native terminal | Existing send/request capacities; ENOBUFS means no native admission, not successful output |
| Plaintext | Borrowed through its callback, or explicitly copied into SCTP Session storage | Exact maximum authenticated message bytes; overflow rejects without truncating a message |
| Provider context | Retained by admitted channels until all channel work and native callbacks drain | Initialization failure returns its reference; context release cannot invalidate live channels |

The implementation must account for all these bounds together, rather than
adding an unbounded application send queue. Where the bridge copies output into
the existing datagram send slots, it records that copy and its lifetime; it must
not advertise zero-copy transmission. An implementation that later borrows
ciphertext instead must retain that exact backing through native completion.

MTU admission uses an explicit maximum UDP payload and the provider's supported
record overhead/fragmentation limits. SCTP's packet bound must fit the resulting
authenticated plaintext limit, with overflow-safe arithmetic. This does not
discover or certify path MTU. Oversized input/output fails before partial native
submission; no stream fallback, record slicing or DTLS+KCP stacking is allowed.

## Progress, timers and terminal authority

The Owner supplies a monotonic clock and bounds each progress turn. The provider
owns handshake flight retransmission, record epochs, replay checks and protocol
deadlines. The bridge integrates its next deadline with SCTP and NativeIO waits.
An ENOBUFS output refusal cannot consume a flight twice or cause the host to
resubmit output already accepted by NativeIO. Queued retry storage and retry
counts remain bounded. Fatal authentication errors terminate the exact channel;
they cannot trigger plaintext retry, provider fallback or application replay.

The channel lifecycle is:

`ADMITTED -> HANDSHAKING -> READY -> STOPPING -> CLOSED`

Handshake failure enters STOPPING without READY. Stop first seals application
admission and protocol timers, then retires unsubmitted output and drains actual
native operations. An optional close alert is bounded by the admitted shutdown
policy; an absent peer response cannot retain storage forever. The peer alert,
local close and native UDP completion remain distinct observations.

| Event | What it establishes |
| --- | --- |
| UDP send terminal | Local transmission result for one admitted encrypted datagram |
| DTLS authenticated plaintext | Record authentication/replay acceptance under this channel, not reliable remote application delivery |
| SCTP cumulative reliable receipt | Exactly the reliable receipt promised by the existing Session API, preserving stream/generation/ticket identity |
| SCTP abandonment/forward progress | The existing partial-reliability result, not reliable delivery or a generic success |
| Application ACK | Host protocol authority; never inferred from any event above |

Once a native request is admitted, cancellation returning ENOENT does not free
its storage. A completion already observed but not routed still owns its lease.
The bridge must match backend, endpoint, native request and channel generation;
a copied tag alone is insufficient. A closing generation cannot recycle its
slot until its real requests, callbacks and provider work retire. Duplicate or
late routing must not mutate a replacement or neighboring channel. Destroy
returns EBUSY until quiescent. Borrowed backend destruction remains host-owned.

## SCTP binding

Only an authenticated DTLS association can create its SCTP binding. The binding
is an Owner-managed, non-pointer generation identity, never a cryptographic key
or an unverified claim supplied by wire input. All entropy and cookie-MAC calls
remain with the admitted Crypto authority. Provider/context lifetime covers the
Session's retained callback context through Session destruction.

One authenticated DTLS plaintext packet carries one complete SCTP packet.
Session input/output, timers, stream identifiers, reliable tickets and partial
reliability stay with SCTP. CAPACITY must preserve its documented transaction
boundary: reserve space for a possible Session reply before invoking an API
that commits a wire/state transition. A later UDP refusal must not lose or
regenerate an already committed SCTP packet. Any retained output packet is a
bounded protocol obligation, not another application message queue.

DTLS loss, channel failure or generation change stops this association; it does
not implicitly replay DATA or carry a Session into a replacement association.
Stream reset/reuse keeps its existing generation fences. Stop/drain ordering
must preserve every existing Session receipt rather than invent a blanket
success/failure mapping. The current experimental ABI does not yet promise
generic cancellation terminals for all messages; a bridge must explicitly
resolve that gap before offering such an API.

## Implementation and qualification gates

1. Admit an explicit production provider/dependency profile and implement its
   datagram-preserving opaque Crypto boundary. Keep the current TLS profile's
   physical ownership and exact capabilities intact.
2. Qualify actual authenticated DTLS peers, including a different implementation,
   wrong trust/fingerprint/name, expired credentials, malformed/truncated input,
   replay, loss/reordering, retransmission and handshake timeout. Exercise both
   client and server roles and verify no pre-READY plaintext/SCTP publication.
3. Bind real UDP traffic to the existing owned/borrowed NativeIO path. Verify
   capacity refusal, delayed native terminals, cancellation, duplicate routing,
   generation reuse and neighboring-service survival with retained contexts.
4. Add the SCTP mapping only after DTLS readiness, then qualify actual message,
   stream/reset, ACK, partial-reliability and shutdown behavior over that bridge.
5. Run existing project formal tests through established presets/CTest on
   Linux/macOS/Windows x64/ARM64 and applicable sanitizers. Android build success
   remains separate from device execution. Add no consumer/smoke project or
   separate probe workflow.

The contract alone satisfies no production-support or interoperability claim.
