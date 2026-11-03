# CNet-native policy hierarchy: owner, connection lifetime and transfer workload

**Status:** M0/M1 and the M2 packet subset merged in PR #157; persistent TCP
and TLS retained-transfer slices merged in PRs #159 and #160 after their
exact-head LLVM CI passed. TCP pool READY/reuse merged in PR #161 after CI #160.
Bounded send-credit recovery and TLS pool READY/reuse merged in PRs #162/#163
after CI #163/#164. The external close/completion regression fix merged in
PR #164 after CI #167. Local IPC admission/transfer merged in PR #165 after
CI #169. Pipe policy admission and POSIX FIFO transfer merged in PR #166 after
CI #171. Fixed 1/2/4-Owner SG cohosting/isolation merged in PR #167 after CI #173.
Mixed SG-owned/CNet terminal routing merged in PR #168 after CI #175.
Large-vector POSIX kernel-pressure tests and the observed-vector-prefix close
regression fix merged in PRs #169/#170. Resource/policy separation merged in
PR #171. Authenticated TLS shutdown and native Windows pkg-config merged in
PR #172 after all ten LLVM qualification jobs passed.
Opaque production TLS ownership merged in #173; connection-phase send admission
merged in #175. The ten policy/ownership/rollback PRs #176 and #178–#186 merged
through #187, qualified together by [CI #210](https://github.com/qigao/salts-core/actions/runs/41584295038).
The sustained SG progress fix and TLS neighbor isolation merged through #192,
qualified together by [CI #216](https://github.com/qigao/salts-core/actions/runs/41591989053).
Packet generation drain and real KCP retransmission/stop merged in #193 after
[CI #218](https://github.com/qigao/salts-core/actions/runs/41593676226).
Baseline: SaltsCore master `8604d1978054fb8607d4edb4e353a9425a88a83d`.
[SaltsCore #156](https://github.com/qigao/salts-core/issues/156) records the final
Windows pressure/cancellation qualification and native policy acceptance.
Production DTLS/SCTP is tracked
separately in [#188](https://github.com/qigao/salts-core/issues/188), and matched
performance benchmarks in [#189](https://github.com/qigao/salts-core/issues/189).
The [DTLS/SCTP ownership contract](CNET-DTLS-SCTP-CONTRACT.md) defines the
future datagram/provider boundary and qualification gates; it adds no current
production support.
This RFC supersedes the earlier
ACE/Configurator-oriented draft in PR #157. **Core has no CMeta/ACE dependency,
second event loop, generic strategy registry, or new runtime.** Optional
reflection and lexical cleanup adapters belong to `qigao/cmeta`, above Core.

## Implemented resource and policy contracts

PR #171 introduced the following native
contracts. This is a source/ABI change: rebuild CNet and its consumers together.
Its exact-head ten-job LLVM qualification passed before merge. The historical
milestones above retain their own evidence.

| Concern | Configuration / API | Authority that cannot be overridden |
| --- | --- | --- |
| Control storage | `cnet_resources.storage`; separate `storage` bindings on Manager, Handoff, ManagedDial and Pool | Original provider receives every allocation back, including init rollback |
| Receive payloads | `cnet_resources.receive` returning canonical `mem_buffer_t` | Buffer owns its release authority through the last reference, even after client destruction |
| Send admission | `cnet_send_limits`, `cnet_send_admission_policy`, `cnet_client_set_send_admission`, `cnet_set_send_admission` | Aggregate and per-connection operation, logical-byte and backing-capacity limits; actual WriteQueue/NativeIO admission |
| Logical send completion | `cnet_send`, `cnet_operation`, `cnet_send_result`, `cnet_client_send_usage` | One terminal per accepted operation, no terminal or lasting retain on rejection |
| Destination / Owner choice | Existing built-ins or `CUSTOM` callback in the typed selection input | Snapshot freshness, eligibility and index validation; actual resource reservation follows selection |
| Connection reuse | `cnet_pool_selection_policy`, first / round-robin / least-used, `cnet_pool_set_selection` | Exact pool key, Manager BOUND, protocol READY, physical capacity and real protocol-token reservation |
| Recovery delay | `cnet_backoff_policy`, fixed / exponential jitter / custom delay | Attempt budget, maximum delay, absolute deadline, generation and security sealing |

Providers acquire resources. Policies make bounded decisions from borrowed
snapshots. The existing Owner performs state transitions, retains buffers and
routes NativeIO terminals. Policy callbacks must not block, retain snapshot
pointers, perform I/O, or mutate/reenter their owning objects. A custom choice
never grants permission to bypass a hard bound or security identity.

### Applying a policy by phase

Initialize storage providers, hard limits and progress ownership once. On the
Owner thread, outside poll/stop/callback execution, replace the send admission
binding with `cnet_client_set_send_admission` or the reuse selector with
`cnet_pool_set_selection`. Bindings are copied; callback user storage is
borrowed. An old policy user may be released once replacement returns. Existing
sends and pool leases keep their original completion/release obligations.

For example, an HTTP server can bind a connection gate with a small byte window
while reading/authenticating a request, then change that connection's gate for
streaming the response. An HTTP client can choose least-used READY connections for normal
traffic, then reject new acquisitions during explicit drain. MQTT/FlowMQ
handshake, READY, application ACK, QoS and replay authorization remain with
their protocol/session layer. A transport write terminal cannot establish
those facts. The host chooses the phase; CNet does not infer it from payload
size or install a second application queue.

```c
/* config is a fully populated cnet_client_config before init. */
config.send_limits.operations = 64u; /* must fit command_capacity */
config.send_limits.bytes = 4u * 1024u * 1024u;
config.send_limits.backing_bytes = 8u * 1024u * 1024u;
config.send_limits.connection_operations = 8u;
config.send_limits.connection_bytes = 256u * 1024u;
config.send_limits.connection_backing_bytes = 512u * 1024u;
config.send_admission = service_gate; /* applies to every connection */

/* After connect/adopt, outside callbacks, check each returned status. */
int status = cnet_set_send_admission(&client, connection, &handshake_gate);
/* Later, after returning from protocol callbacks to the Owner loop: */
status = cnet_set_send_admission(&client, connection, &streaming_gate);
/* Other connections keep their gates; resources and hard limits stay fixed. */
```

The gates in this example are application-supplied `cnet_send_admission_policy`
values. Resource provider replacement, live Owner migration and arbitrary
live trust/protocol mutation are not supported. A different resource lifetime
or hard budget requires a new owner/client and explicit drain of the old one.
Recovery backoff is bound at state initialization; destination and placement
inputs are supplied per decision.

#### Independent connection phases

`cnet_set_send_admission(client, connection, policy)` binds a copied extra gate
to one live connection generation. The Owner calls it outside progress and
callbacks, including after connect/adopt returns and before the first send.
Hard limits run first, then the client gate, then the connection gate; each
must accept. A zero binding removes only the connection gate. Replacing the
client gate never removes connection gates. Thus one HTTP connection can pause
new response writes while another connection on the same client keeps streaming.
The protocol host defines these phases and supplies the callback/user binding.

The gate borrows its user until successful replacement or the connection's
terminal notification. Replacement does not cancel, reprice or reorder accepted
writes: their FIFO completion, retained buffers and charged usage remain until
the original terminal. Rejection retains nothing and publishes no operation;
`CNET_LIMIT_POLICY` identifies client rejection and
`CNET_LIMIT_CONNECTION_POLICY` identifies connection rejection. Clearing a gate
does not bypass aggregate/per-connection hard budgets, transport readiness or
final-send/close sealing. Closed or stale handles cannot change a reused slot;
new generations start with no connection gate. Wrong-owner mutation is EPERM,
mutation during callbacks/progress is EBUSY, and a sealed connection is
ESHUTDOWN. The existing policy callback reentry prohibition also applies.

This adds one fixed-size binding to each existing connection record, with no
new queue, allocation during replacement, timer or progress owner. It does not
add per-connection mutable hard limits or change resource-provider lifetime.

### Memory and terminal accounting

Pool READY admission and each new lease also inspect the existing CNet session
through Manager. Manager BOUND alone does not prove the transport is OPEN:
connect/handshake may still be pending, or final-send/direct close may already
have sealed admission before the terminal observer retires the Manager record.
Opening/handshaking candidates are temporarily ineligible. Closing, directional
shutdown, stopped and stale connections are marked draining without closing
anything or fabricating terminal notification. A closing Manager likewise
cannot issue new pool leases; merely sealing new Manager reservations does not
stop an otherwise live pool connection.

The Owner performs these checks synchronously before selector/protocol-token
admission, without progress, callbacks, allocation or another lifecycle state
machine. Exact pool keys, host-declared protocol READY and actual protocol slot
reservations remain required. Existing leases keep their original release
authority and physical records stay charged until real terminal and final lease
release. This is an internal CNet/Manager/Pool check, with no new public API.

`storage` covers CNet client/Owner/session/dispatcher/command/event/write
records and the WebSocket transport bridge, plus explicitly configured
Manager/Handoff/ManagedDial/Pool objects. It does not replace dependency-owned
NativeIO, resolver, deadline queue, Disruptor, command/event payload-pool or
TLS allocations. Standalone listener/datagram/packet endpoint allocators are
unchanged. This contract is not a promise of process-wide heap-free operation.
No provider failure silently falls back to malloc or another buffer pool.

Receive providers return an owned reference with refcount one and sufficient
capacity. The backing's final-release authority must survive client shutdown
and permit release on the consumer thread. A stack arena or a pool destroyed
with the client cannot back a retained receive slice. Send backing still comes
from the caller's canonical buffers; CNet retains only after admission.

Send logical bytes and backing capacity remain charged until terminal,
including partial writes and pending cancellation. Distinct buffers within
one vector are charged once each; sharing one backing between operations
charges it once per operation. This conservative measure is not RSS. Zero
operation/byte limits derive from bounded write capacity and maximum send size;
zero backing-byte limits mean `SIZE_MAX`, so set explicit limits for isolation.

`cnet_send` requires a completion callback and returns a correlation identity,
not a cancel/ownership handle. Success completion means the logical write
completed locally. A failed write may have delivered a prefix to the peer.
Completion runs on the progress owner; failure completions precede connection
terminal notification. The existing successful `observer.on_send` notification
still runs after the operation completion. Convenience sends share the same
admission ledger. Release of caller references is independent of CNet's
retained operation references.

The existing formal policy/TCP tests cover each limit axis, phase replacement
with a live send, invalid custom selection, recovery caps/security sealing,
allocation failure at every injected init allocation, borrowed backend
survival, cross-DSO release after client destruction, and real NativeIO prefix
completion held across close. Pool reuse and protocol reservation are exercised
against real TCP connections. TLS and original Owner tests remain separate
regression gates. No new standalone test target or runtime is introduced.

### TLS policy and provider ownership

The production adapter in `cnet/src/cnet_tls.c` now calls the opaque
`crypto/tls_stream.h` interface. Crypto owns immutable security contexts,
handshake/record state, certificate inspection, platform trust and bounded TLS
buffers. CNet owns the progress thread, NativeIO requests, deadlines, write
admission and terminal/drain accounting. GmSSL headers and platform trust
libraries are private to Crypto; no backend context pointer crosses into CNet.

Security policy is fixed when the reusable context is created. A new connection
may select its standard TLS version range before the first handshake attempt.
An established connection cannot replace trust, identity or security profile.
Send admission and pool selection may still change at their documented Owner
control boundaries. Existing sessions retain their context even if the caller
releases the public CNet TLS handle, and native completions must drain before
the session and its I/O buffers are destroyed.

This cutover preserves the production TLS/TLCP/ShangMi implementation. It does
not substitute the narrower versioned Crypto qualification adapter or claim
DTLS support. The cutover passed its exact-head LLVM CI #189 and is included
in the combined CI #210 qualification.

### Sustained bulk and bounded control progress

The formal TCP suite includes a host progress contract on 1/2/4 fixed SG Owners.
Each Owner shares its existing backend and single host observer between two
external CNet clients. The host advances both clients once, observes one batch
of at most eight completions, routes the whole batch, then replenishes bulk to
the existing eight-write admission bound. Each write retains the same immutable
32-KiB source; ENOBUFS terminates replenishment. Peer reads are bounded per turn.

Both ends of the latency-sensitive control connection enable TCP_NODELAY so
TCP small-write coalescing does not consume an observation-round budget.
Eight sequential one-byte control request/reply exchanges must each finish
within 256 host progress rounds while bulk writes remain admitted. The bound is
part of this workload's formal acceptance, not an OS scheduling guarantee,
latency percentile, weighted scheduler or throughput claim. Once control finishes,
the host stops replenishing and verifies every bulk peer byte and logical send
terminal. Source storage reaches its sole host reference before teardown; both
clients, endpoints, requests, host leases and runtime must drain. Existing finite
bulk/isolation and mixed SG-owned completion cases remain separate tests.
Cross-platform qualification is recorded by this change's formal LLVM CI.

This workload exposed POSIX readiness starvation: immediate bulk completions
kept the local NativeIO terminal queue nonempty, and observe returned without
sampling the OS for an already-ready control receive. Readiness observe now
performs one nonblocking driver wait when queued terminals coexist with pending
requests, then drains completions in queue order. No pending request is settled
without its real syscall result; no second observer or queue is introduced.

### ManagedDial READY on a live transport

ManagedDial protocol READY also requires its Manager-owned transport to remain
OPEN at the call. A matching attempt ticket cannot reset recovery accounting
after direct close, retained FINAL admission, Manager request_close or directional
shutdown, even before the terminal callback retires the Manager record. These
paths return `ESHUTDOWN`; opening/handshaking returns `EBUSY`. The same private
transport-state check guards Pool reuse and Dial READY. Protocol authentication
and handshake authority remain with the host.

The formal TCP suite covers a real peer greeting followed by each of those four
close admissions, asserting rejection before terminal without changing the
attempt count, generation, deadline or READY state. Real terminal/FIN and Manager
recycle still drain normally. A live-transport control case admits READY, resets
the episode and completes a real request/reply. Cross-platform qualification
follows the exact-head formal CI result.

### Manager initialization Owner

Manager initialization must execute on its borrowed client's fixed Owner. A live
client wrapper alone is insufficient: a foreign thread receives `EPERM` before
the Manager storage provider runs or an implementation is published. Manager
progress and transport callbacks therefore share the same Owner from admission.
The formal real TCP phase case attempts foreign-thread initialization with a
counting allocator, requires zero allocations and an unpublished wrapper, then
continues real traffic and teardown on the original client Owner.

### Management allocation failure

Management storage initialization stops after its first allocator failure.
Handoff no longer attempts queue allocation after record allocation fails;
Pool no longer attempts later lease/candidate arrays after an earlier allocation
fails. Both return `ENOMEM`, free prior allocations through their original
providers and leave the wrapper unpublished.

The formal policy suite injects failure at each successive storage allocation
for Manager, Handoff, ManagedDial and Pool until initialization succeeds. It
requires no later allocation call after failure, zero remaining provider-owned
allocations and an unchanged borrowed Manager. Successful instances exercise
reserve/cancel/recycle, handoff credit release, idle Dial sealing or Pool
reservation abort before destruction. This qualifies initialization rollback
and bounded helper lifecycle, without dialing a peer or claiming transport drain.

### SG TLS handshake failure isolation

The formal TCP suite also hosts a TLS server connection and an independent
plain TCP client on the same SG backend/host lease, on 1/2/4 fixed Owners. The
public TLS server handle is released after admission; the handshaking session
retains its own context. Application send before TLS readiness rejects without
retaining the buffer. The native peer sends an invalid TLS record while the
plain neighbor exchanges real request/reply bytes.

Only the TLS connection fails, exactly once at the handshake stage rather than
by timeout, with no CONNECTED or application-data/send notification. Any fatal
handshake wire output drains before native peer EOF. Destroying that client
leaves the shared backend open and the neighbor able to admit a final send.
Both clients, endpoints, native requests, host leases and runtime then drain.
This qualifies malformed-record handshake isolation and retained TLS context
lifetime, not certificate-authentication coverage or scheduler fairness. Existing
trust/SAN negatives and the separate sustained-progress regression keep their
own acceptance. Qualification follows this change's formal LLVM CI result.

### Packet session close, reuse and retransmission stop

Packet endpoints currently own their NativeIO polling; they do not expose the
datagram API's borrowed-backend completion routing. Qualification must use that
actual boundary. One owner thread admits copied messages into fixed session,
datagram and tagged-send capacities. A closing session stays reserved until its
real UDP sends and terminal callbacks drain; only then may its slot be reused
with a new generation. Old handles must reject without changing the replacement
or a neighboring session. UDP local completion still does not prove peer receipt.

For KCP, a bound UDP peer withholds ACKs and observes the same logical segment
retransmitted on the wire. Local datagram completion must leave the logical tag
pending. Endpoint stop then disables admission/timers, cancels that logical tag
exactly once, drains native writes and publishes CLOSED before destruction.
These scenarios belong to the existing formal policy test, with no replacement
clock, injected native completion, new target or external-polling claim.

Session generations protect local handles and completion ownership. They are not
wire anti-replay identities: UDP has no generation field, and plain KCP's peer
and conversation identity does not authenticate packets. Applications must not
infer that reopening an identical wire identity rejects delayed old packets.
Authenticated-session security retains its separate handshake/identity contract.
This lifecycle qualification merged in #193 after its exact-head CI #218 passed.

### Multi-connection pool policy composition

Pool acquisition copies its protocol callback/user binding before entering
selection or reservation callbacks. The same binding applies across bounded
candidate retries and becomes the successful lease's release authority. A host
may prepare its next binding during reserve without redirecting the token just
admitted. The real TCP composition case rebinds the host's user from provider A
to provider B inside A's successful reservation, transmits that token to its
peer, then requires A to release it exactly once. Later acquisitions use B;
terminal/drain and final lease release leave both providers balanced.

The same formal TCP case checks selector errors, out-of-range and filtered
indices, and repeated selection of a candidate already excluded by protocol
ENOBUFS. Rejections leave empty output identities, unchanged lease/physical
counts, no protocol tokens and no release calls. A protocol hard error returns
unchanged after one reservation call, without trying the neighbor. A failed
reserve owns no protocol slot; only ENOBUFS permits a bounded alternative.
During a successful alternate-candidate acquire, the first full candidate
rebinds the host's future provider, but the second candidate and accepted lease
retain the provider captured at entry. The actual peer exchange and final
provider balances verify settlement after those rejected paths.

The existing real TCP loopback suite includes two physical connections with
the same exact pool key. Each completes a real peer protocol greeting before
READY binding. The host owns a bounded protocol token bank, independently of
the pool's advertised per-connection capacity; every accepted token is sent to
its native peer and receives a matching reply before the host releases it.

The case switches first, round-robin and least-used selection while leases are
live. It checks bounded candidate exclusion after protocol ENOBUFS, both
all-candidates-full rejection and successful selection of another connection,
aggregate lease saturation, paused acquisition, stale lease rejection and
callback reentry guards. Two protocol provider bindings share the token bank;
changing the caller's binding or the pool selector cannot change an existing
lease's copied release callback/user.

Draining one connection preserves its outstanding tokens through transport
terminal, reclaims its physical record only after the final lease release,
and allows the neighboring connection to complete another real exchange.
Final pool seal/transport close leaves tokens live until explicit release;
both providers then have exactly matched acquisitions/releases and both
Manager attachments recycle once. This qualifies the generic host token
contract, not HTTP multiplexing, MQTT QoS, a scheduler fairness or throughput
claim. Cross-platform qualification follows the exact-head formal CI result.

### ManagedDial client ownership and admission

ManagedDial checks both Manager connection credits and attachment records before
calling host admission or consuming an attempt. A cancelled/terminal record
returns its connection credit before its context hold and deferred recycle end.
If those records fill the table, `advance` returns `ENOBUFS` with zero wait and
leaves the recovery generation, attempt budget and seal state unchanged. Releasing
the hold alone is insufficient; the host must also advance Manager recycle.
The formal TCP case holds the sole cancelled record through both phases, then
recycles it and completes a real Dial connection and protocol exchange.

ManagedDial borrows the exact client wrapper used to initialize its Manager.
Both init variants reject a different wrapper with `EINVAL` before allocating
storage or invoking admission. A shared Owner thread or matching connection
slot/generation does not establish client identity: connect and close must
reach the same client. The host keeps both borrowed wrappers live until Dial
destruction and continues their existing progress/recycle loop.

The formal TCP loopback suite uses two clients with overlapping public handle
values and real native peers. It checks allocation-free mismatch rejection,
admission deferral without consuming an attempt, callback reentry rejection,
explicit protocol READY after transport connection and a real peer greeting,
and idempotent seal. Dial destruction remains busy through transport terminal
until Manager recycle; destroying that Dial and its client leaves the neighbor
able to complete another request/reply. Cross-platform qualification follows
the exact-head formal CI result.

### Real ManagedDial recovery lifecycle

The formal TCP loopback suite exercises three sequential physical connections
through one Manager record and one client slot. A native peer supplies a greeting
and closes each socket while CNet has a real receive pending. The host classifier
authorizes transient recovery for the first two losses, then selects SECURITY
for the last. This checks host classification handling, not a TLS authentication
failure or permission to replay application data.

The first loss occurs before protocol READY and preserves its consumed attempt
and original deadline. The second connection explicitly reaches READY and performs
a request/reply; its later loss starts a new bounded episode with reset attempts.
Each replacement waits for actual terminal and Manager recycle, receives fresh
transport and recovery generations, and rejects old connection handles and READY
tickets. Classifier callback mutation is rejected. The final security decision
seals recovery and admits no fourth connection. Zero-delay fixed backoff keeps
this case focused on lifecycle composition; delay and jitter bounds belong to
the existing recovery policy tests. Cross-platform qualification follows the
exact-head formal CI result.

### Custom backoff authority boundaries

The formal policy suite checks eleven deterministic custom-backoff cases:
bounded, zero and maximum delay; excessive delay and a provider error; exact
deadline equality and clock-addition overflow; exhausted attempts; security,
permanent and already-expired failures. Strategy selection never bypasses the
core attempt/deadline/identity checks. Invalid delay or a policy error seals
recovery; the original policy error is preserved. A delay reaching the deadline
or overflowing the clock cannot produce a wrapped, immediately eligible retry.

During evaluation, recursive begin/seal and snapshot access return `EBUSY`;
rejected begin outputs remain empty. Security, permanent and expired failures
do not invoke the strategy. Valid custom delays permit another attempt only at
their admitted time, and old tickets cannot settle that new generation. These
are pure policy contracts using explicit timestamps, without sleeping or claiming
transport/protocol execution. Cross-platform qualification follows the exact-head
formal CI result.

### CMeta integration above Core

`qigao/cmeta` supplies the optional `<cmeta/cnet_policy.h>` adapter. It exposes
read-only data descriptors for limits, usage, backoff input and pool snapshots,
and cleanup obligations for caller-owned buffers/slices. C uses
`cmeta_with_cleanups`; C++ uses `cmeta::cleanup_scope`, including exception
unwinding. Native CNet keeps its own admitted references. Fallible
`stop`/`drain`/`destroy` remain explicit; a lexical destructor cannot discard
their errors or destroy an owner with live I/O. Live clients, function pointers
and provider authority are not constructible from reflected data.

## Principle: independent axes, immutable admission

Long/short connection duration and small/large application writes are
**orthogonal**. The raw transport and the qualified Channel Stack are separate axes:

| Connection lifetime | Small/latency-sensitive writes | Large/throughput-sensitive writes |
| --- | --- | --- |
| One-shot / short-lived | Send retained small buffer; close **only after** true transport terminal and any required protocol response | Bounded retained slices/vector or chunks; drain all admitted bytes before terminal close |
| Persistent / long-lived | Optional compatible Pool; TCP_NODELAY only when latency warrants; explicit keepalive/idle management | Compatible Pool + scatter/gather + bounded backpressure and fair Owner progress; no implicit large-copy buffering |

The same TCP stream may alternate between small control traffic and large
payload transfers. Therefore: **never choose a single mutually exclusive
FAST/BULK/LONG enum**, never infer business lifetime solely from the last
write size, and never change a connection's Owner or trust identity based
on a later payload.

## Six policy scopes; L1.5 is the Channel Stack

L1.5 is a **CNet architecture label**, not an OSI "layer 1.5". L1 and L1.5
describe the data-plane substrate. L2 Owner is an **orthogonal control plane**
over the whole stack, not a byte-level wrapper between protocols. L3/L4 consume
the capabilities and terminal semantics admitted below them.

| Scope | Contract / examples | Authoritative implementation |
| --- | --- | --- |
| **L1 Raw Transport** | TCP / UDP / IPC / Pipe; exact OS endpoint, peer, native handle, raw stream/datagram capabilities | Existing CNet transports and NativeIO |
| **L1.5 Channel Stack** | Exact supported recipe: TLS over TCP, KCP over UDP, PSK secure KCP/FEC over UDP; prospective DTLS/SCTP only after qualification | Existing CNet TLS/KCP/packet endpoint, plus Crypto for cryptographic primitives |
| **L2 Owner control plane** | Hard capacities, retained memory, request/completion credits, progress and host timers | Existing Client/Datagram/NativeIO Owner; one observe path |
| **L3 Connection/session lifecycle** | One-shot, persistent, eligible pool reuse, explicit recovery, terminal drain | Existing Connection/Manager/Pool/ManagedDial; UDP packet sessions are not TCP sockets |
| **L4 Logical transfer** | Latency vs bulk, bounded retained vectors, FIFO, backpressure, channel-specific send terminals | Stream WriteQueue or the *existing* datagram/KCP endpoint protocol storage; not a second application queue |
| **L5 Application protocol** | Framing, READY, idempotency, business ACK and request replay authorization | CHttp/FlowMQ/Orbit/etc. |

### L1 and L1.5: select a validated recipe, not an arbitrary middleware chain

Channel recipes are **immutable admission-time identities**, not dynamically
composable plugin objects or a new public `cnet_*` ABI. The protocol order below
is top to bottom (toward the physical network). A recipe provides only the
capabilities proven by its actual implementation/configuration.

| Explicit recipe | Wire stack | Exposed semantics | Current CNet evidence |
| --- | --- | --- | --- |
| Plain stream | TCP | Reliable, ordered **bytes**, no message boundaries or encryption | Existing |
| Secure stream | TLS -> TCP | Authenticated/encrypted, ordered **bytes** *after* verified handshake; remote app receipt not implied | Existing stream TLS; exact Crypto/TLS profiles have separate gates |
| Plain datagram | UDP | Datagram boundaries; no reliability, ordering, or encryption promise | Existing `cnet_datagram` / packet endpoint |
| Reliable packet | KCP -> UDP | KCP sequencing/retransmission; logical message boundaries only in qualified **message mode**, not arbitrary KCP stream mode; no encryption/auth by default | Existing `cnet_kcp` and `cnet_packet_endpoint` |
| Secure reliable packet | Existing PSK v1 security + KCP + Reed-Solomon FEC -> UDP | Authenticated KCP session with bounded FEC and reliable ordered delivery according to its message-mode contract; **not DTLS** | Existing `cnet_secure_kcp` / packet endpoint security config; independent protocol qualification still applies |
| Secure datagram | DTLS -> UDP | Secure datagrams, **not** reliable/ordered delivery | **Not a production CNet channel yet**: no datagram-preserving DTLS session/lease contract |
| WebRTC DataChannel | SCTP -> DTLS -> UDP | Message/multistream SCTP over authenticated DTLS | **Not production-integrated**: SCTP/DTLS owner and generation/terminal bridge missing |
| QUIC | QUIC (integrated TLS 1.3) -> UDP | Secure streams/multiplexing, optional unreliable datagrams where implemented | **Not a current CNet channel**; do not model QUIC as generic DTLS + KCP |
| Local stream | IPC or Pipe | Only byte-stream/handle operations proved for that variant | Existing raw transport only; never infer TCP socket options or TLS support |

Existing stream TLS APIs (`cnet_tls_feed_cipher`, `cnet_tls_take_cipher`,
`cnet_tls_handshake`) must **not** be relabeled DTLS: they do not preserve
datagram record/peer ownership. Neither arbitrary `DTLS + KCP` nesting nor
TLS on IPC/Pipe is supported just because each name exists somewhere.
Standard TLS, TLCP and ShangMi profiles require independent explicit
qualification; no plaintext, trust, version or transport fallback.

The existing KCP protocol-only `cnet_kcp` is caller-driven; `cnet_secure_kcp`
adds its own PSK v1 security/FEC contract. `cnet_packet_endpoint` binds
UDP/KCP sessions to a single bounded datagram endpoint, with
generation-checked `cnet_packet_session` handles. One physical UDP socket can
serve multiple *logical* sessions: a KCP session's READY, lifetime, credits
and close are not equivalent to the UDP socket's bind/stop. Its internal
KCP retransmission/FEC storage is necessary bounded **protocol state**, not
authorization to add another application WriteQueue or NativeIO observer.

### Capability admission (host-owned today, not new CNet API)

A host may derive an immutable capability set for the **exact supported recipe,
version/configuration and backend**:

- `BYTE_STREAM`, `DATAGRAM_BOUNDARY`, `MESSAGE_BOUNDARY` (qualified mode only);
- `RELIABLE`, `ORDERED`, `SECURE_PEER_AUTHENTICATED` (only after handshake);
- `HALF_CLOSE`, `POOL_REUSABLE`, `MULTISTREAM` only where a concrete backend
  and channel contract really supports them.

These are **conceptual host descriptors**, not existing CNet flags or guarantees
that all combinations work. Require the necessary capabilities before acquiring
Owner credits/handles; reject the unsupported combination explicitly
(`ENOTSUP`/invalid policy as appropriate), with no fallback or partially
published connection. A declared requirement for security may not be satisfied
by plain KCP, plain UDP or a failed TLS/DTLS handshake. TLS trust/SNI/ALPN,
authenticated peer, protocol version, channel recipe, Owner and endpoint/session
generation participate in immutable identity and any eligible pool key.
Do not reuse physical sessions across a changed trust or channel identity.
For UDP/KCP, do not assume the TCP-only `cnet_client_pool` accepts such sessions.

Channel negotiation and completion require **three distinct gates**:

1. **Transport/base ready**: TCP connected or UDP endpoint bound/peer selected.
   This is not secure-channel READY.
2. **Channel ready**: TLS handshake/certificate checks complete; or a KCP/PSK
   session has satisfied its own session/handshake contract. Plain transport
   needs no extra cryptographic gate. Existing `CNET_CONNECTION_TLS_HANDSHAKING`
   and `cnet_secure_kcp_established()` are examples, **not a proposed universal
   state enum**.
3. **Application ready**: HTTP/RPC/FlowMQ/etc. have completed their own
   negotiation. Pool reuse/request replay may require this later gate.

No app payload may bypass a requested security gate. A channel error, timeout,
stale generation or rejected peer must fail closed and drain/cancel its **real
in-flight operations** before identity/credits are released. TLS shutdown/alert,
KCP retransmission/timer and DTLS future replay/handshake timers must advance
under the same Owner/host progress policy; no second Worker, timer wheel,
socket or NativeIO observe loop. Existing TLS timeouts are Owner config fields;
do not imply an invented per-connection/channel setter.

Channel-produced output must fit **both** L2 hard credits and protocol-specific
MTU/window/BIO/FEC limits, including encryption and framing expansion. A KCP
logical send may be larger than one UDP datagram but requires explicit bounded
fragmentation/retransmission; `max_datagram_bytes` is *not* path-MTU discovery.
Never derive capacity from a hypothetical unlimited protocol buffer.

### L4 terminal semantics depend on the admitted channel

| Completion source | What was actually proved | What was **not** proved |
| --- | --- | --- |
| TCP WriteQueue local terminal | Local native ordered write settled | Remote application receipt/ACK |
| TLS/TCP send terminal | Encrypted records passed through the qualified TLS/underlying native send path | Peer application processed plaintext |
| Raw UDP datagram send terminal | Local NativeIO datagram send settled | Remote peer received packet |
| KCP tagged logical-send terminal | Every segment in that KCP logical message was protocol-ACKed by the peer (existing `cnet_packet_send_terminal_fn` contract) | Remote application/business ACK |
| L5 application ACK | Application-specific delivery/processing evidence, if protocol defines it | Any universal exactly-once guarantee |

Stream channels continue to use the *existing* CNet WriteQueue and retained
send paths. Datagram/KCP channels use their *existing* packet-endpoint
admission/terminal and bounded retransmission storage; **do not route them
through a newly invented second stream WriteQueue**. Completion and channel
READY are orthogonal; do not infer application-ready status from a successful
transport write or auto-replay upon reconnect. Reconnect starts a **new**
generation, and only L5 can authorize replay.

**Priority of restrictions** (most authoritative first):

1. Mandatory security/trust, exact raw transport, channel recipe and capability
   admission. Reject all unqualified or silently downgraded stacks.
2. Owner/backend and channel hard quotas, native completion/borrow lifetimes,
   bounded protocol expansion, peer identity and generation.
3. Immutable session/connection identity, READY phase, lifetime and
   protocol-compatible reuse.
4. Per-write bounds and optional host batching within those limits.
5. Telemetry/adaptation for **future** admission, never rewriting an already
   admitted operation.

Do not use a monolithic mutable `cnet_connection_set_policy()` or add fields to
existing `cnet_connect_options` in M0/M1. The host may hold its own typed plan
indexed by a generation-checked CNet connection **or packet-session** identity
and must discard it after true terminal. No host plan pointer is retained by
CNet.

## L2: Owner budgets and scheduling, already implemented

Actual cnet_client_config contains:
- connection_capacity, command_capacity, request_capacity,
  completion_batch_capacity, event_capacity;
- max_send_bytes **per admitted logical write**, receive_buffer_bytes,
  optional aggregate command_buffer_bytes and event_buffer_bytes;
- connect_timeout_ms, read_timeout_ms, write_timeout_ms and optional
  TLS IO/handshake timeouts.

These are **client/Owner configuration**, not arbitrary per-connection timeout
overrides. A new write larger than max_send_bytes is rejected with EMSGSIZE.
The private cnet_write_queue bounds retained entries globally per Owner and
preserves FIFO **per connection**; it does not provide an automatic size-based
priority scheduler or a message coalescing/batching timer.

cnet_progress_strategy is also already implemented for an **ordinary owned**
CNet client. Its max_poll_passes caps callback-draining passes and
idle_wait_ms caps optional sleeping. The SPIN preset means zero idle blocking
**per invocation** and costs more CPU; it is not a new background busy loop.
These are **Owner-wide** progress controls, not per-connection QoS, and the
pass budget is not a byte/packet/callback-count priority budget. For
cnet_client_init_external()/NativeIO SG, use the embedding host's single
backend-observe policy instead of cnet_client_poll_strategy().

Do not create a second NativeIO poller, per-connection worker, queue or
timer wheel to implement profiles. Admit first, schedule the single Owner,
and route the full observed completion batch even if one earlier completion
returns an error.

### Concrete existing C11 configuration examples

```c
#include <cnet/cnet.h>

/* Owner has already been initialized, and must have zero live connections.
 * These options affect FUTURE TCP sockets of this CNet client. */
int configure_latency_tcp_owner(cnet_client *client) {
    cnet_stream_socket_options opt = CNET_STREAM_SOCKET_OPTIONS_INIT;
    opt.nodelay = 1;          /* latency-sensitive small writes */
    return cnet_client_set_stream_socket_options(client, &opt);
}

/* Only for an ordinary internally driven CNet client; NOT external SG. */
int drive_bounded_low_latency(cnet_client *client, size_t *out_events) {
    cnet_progress_strategy strategy = CNET_PROGRESS_STRATEGY_SPIN_INIT;
    return cnet_client_poll_strategy(client, &strategy, 0u, out_events);
}
```

The TCP options above do not apply to IPC/Pipe/UDP. CNet also provides
generation-checked per-live-TCP get/set for supported options (including
TCP_NODELAY), but not all initial socket options such as SO_LINGER have a
corresponding live API. Setting nodelay to zero in the initial config
preserves the platform default; it does not mandate an explicit live
TCP_NODELAY=0 transition. Keep platform-specific rejection and round-up.

## L3: connection lifetime, not a replacement transport

The application declares **intent** before admission:

- **One-shot:** no pool/reuse; connect, send, complete any required protocol
  response, then close and drain. For one-way traffic only, an already-owned
  immutable buffer can be the final write via cnet_send_buffer_and_close();
  it closes after the actual final send terminal, not immediately upon
  admission. For request/response, using *_and_close may prematurely close
  the receive path: instead use cnet_send_buffer(), wait for the protocol
  result, then cnet_close() (or supported TCP send-half-shutdown if the
  protocol specifically requires it).
- **Persistent:** keep the same Owner/authority/transport/policy identity,
  opt into cnet_client_pool only when the application protocol has proved
  READY and reuse eligibility; no new pool engine. TCP keepalive, if enabled,
  is a socket-level liveness mechanism, not application heartbeat or protocol
  readiness. Idle-age, max-lifetime and health rotation are **host timers**
  today, not first-class CNet per-connection policies.
- **Recovery:** cnet_managed_dial plus cnet_reconnect_* only on the
  Owner whose real Manager/CNet connection has reached a terminal. A new
  physical connection is not an application request retry.
  cnet_retry_evaluate authorizes replay only for owned replayable input and
  proven non-execution or explicitly idempotent operations, within budget.
  TLS/security failures seal recovery; no plaintext/destination downgrade.

The existing cnet_client_pool key includes Owner, endpoint, transport,
authority, TLS trust/SNI/identity, ALPN, protocol and session identifiers.
It is an **exact-key**, Owner-local physical/slot admission helper, not a
global pool. No pool reuse of UDP, IPC or Pipe is implied by current
cnet_pool_* interfaces.

## L4: small vs large **application writes** (not TCP packets)

TCP, IPC and Pipe are byte streams: one cnet_send_* write does NOT create a
remote application message boundary, nor does a CNet send terminal prove
remote business receipt. TCP segmentation/MTU and ACK behavior remain
OS/network-owned. Small/large here means the **application's logical write
size and latency requirements**; do not use a synthetic TCP packet size
classifier to alter routing or socket state on every callback.

**Small/latency-sensitive:**
- For TCP, explicitly choose TCP_NODELAY on suitable client/connection
  policy, not on each message; profile the tradeoff against packet overhead.
- Admit immutable small mem_buffer_t or mem_slice_t values with
  cnet_send_buffer()/cnet_send_slice(). CNet retains the backing only for
  the accepted operation; callers may release their own reference after
  successful admission but may not mutate backing bytes until settlement.
- An application may coalesce compatible writes **before** admission, with
  a strict byte count and time ceiling, but CNet currently has no implicit
  batching clock or coalescer. Do not delay protocol control/heartbeat behind
  a bulk queue without explicit authorization.

**Large/throughput-sensitive:**
- Use cnet_send_slicev() with 1..CNET_RETAINED_VECTOR_MAX canonical slices
  and total bytes <= the Owner max_send_bytes. CNet submits at most
  NATIVE_IO_VECTOR_MAX native spans per bounded submission and continues
  a partially settled logical write in order. This avoids a mandatory
  CNet-side plaintext flatten copy; it is **NOT kernel zero-copy**.
- For one contiguous immutable buffer, use cnet_send_buffer(); for a huge
  payload, the application must bound/chunk writes to the Owner limit and
  retain each required backing until its actual send terminal. Do not
  preallocate an unbounded giant command buffer.
- Observe ENOBUFS/EBUSY/EMSGSIZE and wait for true terminal/progress before
  admitting more. The existing FIFO is ordered within each connection;
  it is not a weighted-fair scheduler across connections. Any new priority
  or per-connection in-flight byte credit would require a separate narrow
  additive API and real starvation tests.

**UDP differs fundamentally:**
- cnet_datagram_config has send_capacity, request_capacity,
  completion_batch_capacity, max_datagram_bytes, receive_buffer_bytes and
  optional reuse_port; these are datagram-owner bounds.
- cnet_datagram_associate_endpoint can associate an exact peer, but an
  associated UDP socket does NOT become a reliable stream or a TCP-like
  persistent connection.
- Native UDP max payload 65507 is only an API/IPv4-sized bound and is NOT
  path-MTU safety. For a large message, the application must use a separately
  qualified fragmentation/reassembly protocol or explicitly select CNet KCP
  with its MTU/send/receive window/segment and optional Reed FEC policy.
  Never silently fragment or switch transport under the same UDP profile.

**IPC and Pipe:**
- Plain IPC is AF_UNIX on POSIX or Windows named pipe; Pipe is Windows
  named pipe or POSIX existing FIFO .rx/.tx pair, with transport-specific
  name/path validation and native handle lifetime. No TCP_NODELAY,
  SO_KEEPALIVE, socket linger or UDP hop-limit settings apply.
- They share the CNet byte-stream send/receive/terminal model where the
  current variant supports it, but do not assume every vector, half-close
  or reuse option is supported. Explicit ENOTSUP is correct.
- IPC listener's accept_capacity/child_capacity bound pending children;
  accepted descriptors must be move-owned and correctly drained. POSIX
  filesystem permissions/umask and Windows pipe ACL remain authoritative,
  not a built-in universal CNet peer-authentication policy.

## Host-owned profile selection (not a new public CNet ABI)

Optional small C11 host model:
```c
/* Illustrative host-only selectors; NONE of these are cnet_* API. */
typedef enum host_raw_transport {
    HOST_RAW_TCP = 1, HOST_RAW_UDP, HOST_RAW_IPC, HOST_RAW_PIPE
} host_raw_transport;

typedef enum host_channel_recipe {
    HOST_CHANNEL_PLAIN = 1,
    HOST_CHANNEL_TLS_TCP,
    HOST_CHANNEL_KCP_UDP,
    HOST_CHANNEL_SECURE_KCP_UDP
    /* DTLS/SCTP/QUIC intentionally absent until qualified. */
} host_channel_recipe;

typedef enum host_conn_lifetime {
    HOST_ONESHOT = 1,
    HOST_PERSISTENT = 2
} host_conn_lifetime;

typedef enum host_write_intent {
    HOST_LATENCY = 1,
    HOST_BALANCED = 2,
    HOST_BULK = 3
} host_write_intent;

typedef struct host_cnet_plan {
    uint32_t version;          /* HOST convention, not CNet ABI */
    host_raw_transport raw_transport;
    host_channel_recipe channel;
    host_conn_lifetime lifetime;
    host_write_intent write_intent;
    uint64_t service_identity; /* caller's authorized stable identity */
    uint64_t owner_identity;   /* final fixed Owner */
    size_t max_logical_write;  /* <= owning cnet_client_config.max_send_bytes */
    uint32_t idle_budget_ms;   /* host's timer, NOT a CNet setter */
} host_cnet_plan;
```

This struct is illustrative and **is not a new cnet_* API or compiled source
in PR #157**. Compile it into existing CNet init parameters and app-owned
admission decisions. Version/size/transport/channel mismatch, unsupported security requirements,
and unauthorized or unqualified channel combinations fail **before** any
socket/slot reservation. The host stores an immutable copy alongside its
generation-checked connection identity; old connections do not change when
future policy defaults are updated. A per-write hint may choose which
existing send_* API to call, but cannot weaken transport/security, reorder
admitted FIFO writes, exceed budget, migrate Owner or retroactively close
an active session.

Example selection for one TCP connection: choose endpoint and fixed Owner
with cnet_destination_choose / cnet_owner_placement_choose; then reserve
actual cnet_manager_* / optional pool_* or handoff_* credits on the **final
Owner**, initiate one cnet_connect/adopt, observe CONNECTED and protocol
READY distinctly, run sends with retained ownership, and settle all
real terminals before releasing credits. A failed advisory choice or FULL
credit cannot silently select an alternative under STRICT_KEY.

## What should NOT be added immediately

- A generic strategy registry, virtual per-socket chain, arbitrary DTLS/KCP nesting,
  or a second transport-independent channel runtime.
- A combined LONG_AND_SMALL / LONG_AND_BULK / SHORT_AND_SMALL enum or a
  strategy that flips TCP_NODELAY automatically for every write.
- A second send queue, automatic message coalescer, packet priority engine,
  per-connection worker, or duplicate NativeIO observe.
- A new per-connection timeout control pretending client-wide timeouts can
  currently be overridden.
- Implicit TCP/UDP/IPC/Pipe fallback, automatic replay, or a default
  one-way *_and_close when the application awaits a response.

**Real gaps that deserve additive API design only if a consumer proves need:**
per-connection or per-write *bounded* byte/priority credits; a genuinely
authoritative per-connection absolute deadline; explicit timer-backed
idle/lifetime expiry; fairness between bulk and control flows. Any such API
must preserve current cnet_connection ABI, terminal identity and ownership.

## Acceptance without new workflows or consumer/test projects

**M0:** approved design/mapping, no new runtime capability or performance
claim. **Implemented M1:** extend the existing `tests/test_cnet_policy.c`
with real CNet URI/TLS and UDP/KCP/secure-KCP admission checks, bounded FEC/
Owner/terminal version rejections, positive endpoint initialization and
pre-READY secure KCP send denial. Link the existing `saltscore.cnet_policy`
CTest target against production `Salts::CNet` instead of duplicating policy
sources into the test executable. PR #157's exact-head CI #153 passed all ten
LLVM matrix jobs; this does not introduce first-class host Channel Plan APIs.

**M1:** within existing tests/test_cnet_policy.c TinyTest, verify invalid
classification/version, raw transport/channel recipe mismatch (e.g. TLS/UDP,
DTLS pretending to be qualified, KCP/TCP), security downgrade denial,
capability/READY rejection, STRICT_KEY/FULL, host plan's bounded limits,
no hidden fallback and no partial outputs. Existing CNet options/snapshot
contracts stay unchanged.

**M2:** existing native CTest cases: real short TCP send+terminal/close;
TLS/TCP handshake and trust gate before plaintext delivery, persistent pool
reuse only after channel + protocol READY; small writes under TCP_NODELAY,
retained vector bulk/partial write, budget exhaustion and request/response
without premature close. Real UDP datagram MTU/rejection, explicit KCP and
secure KCP session READY/PSK/FEC, KCP logical protocol ACK vs native UDP
terminal vs L5 business ACK, POSIX/Windows IPC and Pipe supported/unsupported
APIs. A DTLS/SCTP runtime gate remains independent and is **not** claimed here.

**M3:** real 1/2/4 fixed-Owner SG cohosting and terminal-drain/fairness
cases, malformed/failed/partial cancellation, channel-handshake failure and
stop-vs-retransmission, close-vs-sends, retained slices and late completion,
wrong owner, stale connection **and packet-session** generation; existing LLVM
Linux/macOS/Windows x64/arm64 native tests and Linux ASan/UBSan/TSan.
Android builds are NOT device runtime. No new CMeta/ACE, Actor, install
consumer or probe CI. Compare same workload raw vs host-composed policy
in separate opt-in performance experiments with CPU/op, p95/p99,
write amplification, retained bytes and fair shutdown evidence.

### Qualified slices and remaining evidence

| Slice | Exact tested PR head | Qualification |
| --- | --- | --- |
| M1 admission and M2 UDP/KCP/secure-KCP loopback | #157 `a2cb4fe520845f73ba3abc8d08f90144c70dc2a8` | [CI #153](https://github.com/qigao/salts-core/actions/runs/41388112357), ten LLVM jobs passed |
| Persistent TCP small/bulk retained vector, FIFO, final send/FIN | #159 `859cd6975a95679954309e88eacbc75ce321d8d6` | [CI #156](https://github.com/qigao/salts-core/actions/runs/41392374952), ten LLVM jobs passed |
| Verified TLS small/bulk noncontiguous retained vector, FIFO, final send/close | #160 `9be95670a5588a8aed033a8597c342c2dd3db61a` | [CI #158](https://github.com/qigao/salts-core/actions/runs/41394653685), ten LLVM jobs passed |
| TCP protocol READY, exact-key pool reuse, lease/context drain and stale identities | #161 `df14a884033c951fb45bb24f11d420d541213f7f` | [CI #160](https://github.com/qigao/salts-core/actions/runs/41396782017), ten LLVM jobs passed |
| Bounded send-credit recovery, rejected final-send ownership and stale TCP handles | #162 `6f0183c66737c3a33257145528ddb10c836c45a4` | [CI #163](https://github.com/qigao/salts-core/actions/runs/41398654219), ten LLVM jobs passed |
| Verified TLS protocol READY, exact security-key reuse and lease/Manager drain | #163 `aeb12701a76c519e3185b4375541126cb7de3d37` | [CI #164](https://github.com/qigao/salts-core/actions/runs/41399822641), ten LLVM jobs passed |
| External close with observed send/pending receive terminals, retained obligations and stale replay | #164 `e1999a6ff3d5ee05f92a666cd1aa399306f3f4f6` | [CI #167](https://github.com/qigao/salts-core/actions/runs/41402483632), ten LLVM jobs passed |
| Detached local IPC ownership, capacity rejection, retained request/final reply and accept drain | #165 `2f80ccf2cb29f61d768218b7a194175ebcf1de71` | [CI #169](https://github.com/qigao/salts-core/actions/runs/41404951972), ten LLVM jobs passed |
| Pipe TCP-policy rejection and native FIFO/named-pipe retained transfer | #166 `1d26cd1439c77061abfca3242455089bae437539` | [CI #171](https://github.com/qigao/salts-core/actions/runs/41408786504), ten LLVM jobs passed |
| Fixed 1/2/4-Owner SG cohosting, bulk/control isolation and host-lease drain | #167 `74e405472109280ae621d0bc2bea350aec18c6d2` | [CI #173](https://github.com/qigao/salts-core/actions/runs/41415636265), ten LLVM jobs passed |
| Mixed SG-owned/CNet terminals, owned receive cancellation and error-batch drain | #168 `0b4d781d14c3e2deb185537842be7ab4543e2025` | [CI #175](https://github.com/qigao/salts-core/actions/runs/41419975647), ten LLVM jobs passed |
| Large retained vectors, POSIX pressure and bounded vector-prefix close | #169/#170, included in merged #187 | [CI #210](https://github.com/qigao/salts-core/actions/runs/41584295038), combined native/sanitizer qualification |
| Opaque production TLS and per-connection phase admission | #173/#175, included in merged #187 | [CI #210](https://github.com/qigao/salts-core/actions/runs/41584295038), combined native/sanitizer qualification |
| Integrated Pool/Dial admission, recovery, Owner identity, provider authority and allocation rollback | #187 `e263ccf364ace9fa561fca91b3df75427e43b879` | [CI #210](https://github.com/qigao/salts-core/actions/runs/41584295038), ten LLVM jobs plus aggregate passed |
| Sustained bounded SG control progress and shared-backend TLS handshake isolation | #192 `193ca97d5a0371a4b7ed83f3aa20523e769baa32` | [CI #216](https://github.com/qigao/salts-core/actions/runs/41591989053), ten LLVM jobs plus aggregate passed |
| Packet generation close/drain/reuse and plain-KCP stop after real retransmission | #193 `51f145e5ec22e992a00c1961c87c3af58f3e3d96` | [CI #218](https://github.com/qigao/salts-core/actions/runs/41593676226), ten LLVM jobs plus aggregate passed |

PR #161 extends the existing `saltscore.cnet_tcp_loopback`
TinyTest/CTest against production `Salts::CNet`: one Manager/Pool connection
is unleaseable before a real peer's protocol READY greeting, then carries two
leased request/reply exchanges on the same TCP generation. Every pool-key
identity participates in reuse rejection. A local send terminal does not
release the request lease; transport terminal does not release an outstanding
lease or the Manager context hold. Pool/lease generations reject stale handles.
The host chooses when to call `bind_ready`; the Pool does not parse or infer
application READY.

PR #162 saturates the production Owner's two retained write
slots before polling. Ordinary and final-send admission both return ENOBUFS
without retaining the rejected buffer or sealing receive admission. Real FIFO
terminals return credits, after which the same final buffer is admitted and
delivered before remote FIN. A second cycle reuses the sole connection slot
and checks that its previous public generation cannot send on the new stream.
These checks qualify bounded admission backpressure, not forced partial writes
or kernel send-buffer pressure. PR #163 separately checks application READY and
two request/reply leases over one verified TLS connection, with stable peer
fingerprint, exact security-key rejection and clean terminal/recycle.

PR #164 holds a real NativeIO send completion across CNet close,
then cancels a pending receive and holds that real cancellation completion.
One host thread observes; CNet must retain each request/backing and reject
stop/destroy until the matching completion is routed. Replayed completions
cannot settle a reused connection/request, and CNet must leave the borrowed
backend open after its own destroy. NativeIO cancellation ENOENT on a borrowed
backend can mean the host already observed the terminal; it must not turn a
clean close into FAILED or release storage before routing. This fix and its
production-loopback regression passed the exact-head matrix recorded above.

PR #165 exercises a real local IPC listener with detached
adoption into production CNet: AF_UNIX sockets on POSIX and overlapped named
pipes on Windows. A full final Owner must consume/close a rejected detached
child while its established neighbor still transfers a retained request and
final reply. TCP-only options and half-shutdown are rejected on IPC. POSIX
retained vectors are exercised; Windows pipe vectors reject without a retain,
and its supported buffer-send API is tested separately. Both clients and
pending listener accepts drain before destruction and caller-owned path cleanup.
These checks passed the exact-head matrix above and do not cover POSIX FIFO pipes.

PR #166 applies the same TCP-only policy rejection to `pipe://`
as to `ipc://`: enabled NODELAY, keepalive, linger and socket buffer overrides
must fail admission without a partial handle rather than be silently ignored.
The Windows test dials the real named-pipe endpoint with the Pipe URI; the
POSIX test owns two actual `.rx`/`.tx` FIFOs and checks a noncontiguous retained
vector, native peer reply, retained final send, EOF and caller-owned path cleanup.
Live TCP properties and half-shutdown remain unsupported. The exact-head matrix
above includes POSIX FIFO and Windows named-pipe runtime evidence; Android jobs
remain build-only.

PR #167 uses the existing NativeIO SG runtime with 1, 2 and 4
fixed Owners. Each Owner registers one host lease and hosts two independent
external CNet clients on its backend: a 32-KiB bulk send and a small control
exchange. Short routed tasks advance clients, observe once through the host
lease, and route the whole native batch. Wrong/stale lease and unleased observe
are refused. Thread affinity stays fixed across startup/progress/teardown.

After native peers verify all initial bytes, the bulk client is closed and
destroyed. The control client retains its pending native receive, receives a
real peer reply, then admits a final send. SG shutdown and host release remain
busy until all borrowed clients are gone. Each backend reaches zero requests
and endpoints before host release and SG shutdown. Main accesses Owner state
only between submit/wait boundaries; borrowed callback storage outlives runtime
destruction. These tests passed the exact-head matrix above. They prove
composition and teardown isolation; latency fairness, saturation behavior and
mixed SG-owned completion routing require separate evidence.

PR #168 adds mixed-ownership variants to those same 1/2/4-Owner
cases. Each Owner attaches one real UDP endpoint to its SG backend and admits
an owned receive while its two external CNet clients transfer TCP data. The
native peer supplies the exact byte. A second owned receive is cancelled while
the remaining CNet client still has a pending receive. Cancellation alone must
not settle the token: terminal and finalizer run once, on the fixed Owner, only
during host observation. Recursive observation from that terminal is EBUSY.
The host counts the SG-settled events without routing them again to CNet. No
particular OS batching or cross-endpoint completion order is assumed.

For the error path, the test prepends one deliberately unknown request identity
to an actual observed batch containing a CNet completion. EPROTO must be returned
after every remaining real event is routed exactly once; normal CNet sends,
receives and final close must still drain. The unknown event is an injected
negative, not a completion claimed to come from the kernel. All real completions
are observed once through the host lease. SG-owned storage remains live until
finalization, the endpoint is closed/released after both terminals, and clients
are destroyed before host release and runtime destruction. This slice passed
the exact-head matrix above and does not qualify scheduler fairness or kernel pressure.

The next source slice sends an 8-MiB logical vector using four nonadjacent ranges
from one immutable retained backing, followed by a one-byte FIFO tail. The peer
pauses reading with a configured finite receive buffer; the sender has a small
SO_SNDBUF. On POSIX the test requires at least one real short NativeIO write and
then a pending send with no logical send/close callback. Resuming nonblocking
peer reads on the same host must deliver every byte exactly once, followed by
the final tail and FIN. A POSIX cancellation variant queues an ordinary tail
(final admission seals public close), explicitly closes during the pending
write, and checks EBUSY stop/destroy and retained backing until the actual native
terminal is routed. Stale replay cannot settle it twice.

Windows loopback may buffer the entire overlapped write despite small configured
socket buffers. Its large-vector case therefore holds that real full terminal
before routing and checks retained backing, exact bytes, FIFO callbacks and FIN;
it does not require or claim short writes or kernel-pressure cancellation on
IOCP. No synthetic short completion, private descriptor mutation or alternate
backend is used. These cases merged in #169 after CI #177 and are also exercised
by the combined CI #210. POSIX pressure/cancellation does not qualify IOCP pressure.

The Windows cancellation variant now replenishes the same immutable 8-MiB
source after each fully completed write, for at most four replenishments. Peer
reads stay paused. It must reach two consecutive 25-ms observation timeouts
with one real NativeIO STREAM_SEND still active; a held full completion cannot
satisfy this gate. The fixed two-write FIFO then admits an ordinary one-byte
tail. Explicit close must produce a real CANCELLED/ECANCELED IOCP terminal,
with bulk backing retained and stop/destroy busy until that terminal is routed.
Routing publishes one connection terminal without reporting the cancelled bulk
or tail as successful, releases both retained sources and submits no remainder.
Replaying the observed terminal is unconsumed. Backend cancellation count is
exactly one; requests, endpoints and borrowed backend then drain. This qualifies
actual pending-send cancellation on IOCP, without requiring Winsock to report a
POSIX-style short successful send. Its exact-head matrix is recorded in #156.

The next close-ordering regression holds a real NativeIO vector prefix terminal
before requesting CNet close. Seventeen nonadjacent retained ranges exceed the
existing sixteen-span NativeIO submission bound, so the observed native terminal
is a strict prefix of the logical write even on IOCP. This is bounded vector
submission, not a synthetic short completion or a Windows kernel-pressure claim.

Previously, routing that held success after close resubmitted the logical
remainder and left the connection open. A closed plain-stream logical write now
settles its unsent remainder as cancelled after accounting for the real prefix;
it admits no more native work and emits no successful logical send. A fully
completed logical write still reports its send before close. TLS ciphertext
retains its separate record/shutdown drain behavior. The regression checks the
unchanged native submission count, retained backing and EBUSY stop/destroy before
routing, one clean terminal, exact peer prefix followed immediately by FIN,
released backing and rejected replay. It failed before the fix and passed locally
on Windows afterward. It merged in #170 after its exact-head CI #178 passed,
and is also exercised by the combined CI #210.

**Nonclaim:** each successful matrix qualifies only its tested slice. Android
x64/ARM64 jobs build the SDK without device runtime tests. IOCP pending-send
cancellation does not promise short successful native writes. SG control progress
is bounded for the specified workload, not general scheduler QoS. Production
DTLS/SCTP (#188), matched performance (#189), adaptive batching and new independent
per-connection stream deadlines remain separate work. Existing host-owned timers
and protocol READY/replay authority do not move into CNet.
