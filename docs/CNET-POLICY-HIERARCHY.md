# CNet-native policy hierarchy: owner, connection lifetime and transfer workload

**Status:** M0/M1 and the M2 packet subset merged in PR #157; persistent TCP
and TLS retained-transfer slices merged in PRs #159 and #160 after their
exact-head LLVM CI passed. TCP pool READY/reuse merged in PR #161 after CI #160.
Bounded send-credit recovery and TLS pool READY/reuse merged in PRs #162/#163
after CI #163/#164. The external close/completion regression fix merged in
PR #164 after CI #167. Local IPC admission/transfer merged in PR #165 after
CI #169. Pipe policy admission and POSIX FIFO transfer merged in PR #166 after
CI #171. Fixed 1/2/4-Owner SG cohosting/isolation merged in PR #167 after CI #173.
Mixed SG-owned/CNet terminal routing tests are pending their own exact-head CI.
The rest of M2 and M3 remain open in
[SaltsCore #156](https://github.com/qigao/salts-core/issues/156).
Baseline: SaltsCore master bc070affca0afbc5cad6e060b9c60a7a22abad10,
reconciled with the native-testing merge. This RFC supersedes the earlier
ACE/Configurator-oriented draft in PR #157. **No CMeta, ACE, reflection,
plugin, Actor, second event loop, generic strategy registry, or new runtime.**

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

The next source slice adds mixed-ownership variants to those same 1/2/4-Owner
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
are destroyed before host release and runtime destruction. This slice is pending
its own exact-head CI and does not qualify scheduler fairness or kernel pressure.

**Nonclaim:** each successful matrix qualifies only its tested slice. Android
x64/ARM64 jobs build the SDK without device runtime tests. Forced partial writes,
kernel backpressure, other cancellation orderings,
fixed SG multi-Owner fairness, DTLS/SCTP, adaptive batching and per-connection
stream deadlines retain separate gates. Keep M2/M3 independent. Track exact HEAD.
