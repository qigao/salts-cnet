# CNet-native policy hierarchy: owner, connection lifetime and transfer workload

**Status:** Design/RFC only; tracked in [SaltsCore #156](https://github.com/qigao/salts-core/issues/156).
Baseline: SaltsCore master bc070affca0afbc5cad6e060b9c60a7a22abad10,
reconciled with the native-testing merge. This RFC supersedes the earlier
ACE/Configurator-oriented draft in PR #157. **No CMeta, ACE, reflection,
plugin, Actor, second event loop, generic strategy registry, or new runtime.**

## Principle: independent axes, immutable admission

Long/short connection duration and small/large application writes are
**orthogonal**. The transport is a separate axis:

| Connection lifetime | Small/latency-sensitive writes | Large/throughput-sensitive writes |
| --- | --- | --- |
| One-shot / short-lived | Send retained small buffer; close **only after** true transport terminal and any required protocol response | Bounded retained slices/vector or chunks; drain all admitted bytes before terminal close |
| Persistent / long-lived | Optional compatible Pool; TCP_NODELAY only when latency warrants; explicit keepalive/idle management | Compatible Pool + scatter/gather + bounded backpressure and fair Owner progress; no implicit large-copy buffering |

The same TCP stream may alternate between small control traffic and large
payload transfers. Therefore: **never choose a single mutually exclusive
FAST/BULK/LONG enum**, never infer business lifetime solely from the last
write size, and never change a connection's Owner or trust identity based
on a later payload.

## Five layers; each has one authoritative owner

| Layer | Policy examples | Configuration time / current authority |
| --- | --- | --- |
| L1 Transport capabilities | TCP/UDP/IPC/Pipe, TLS/KCP only when explicitly chosen; compatible options | Parse/admission; existing CNet transport/NativeIO |
| L2 Owner hard budgets and progress | connection/command/request/completion/event capacity, max_send_bytes, buffer ceilings; max_poll_passes, idle_wait_ms | cnet_client_init/cnet_datagram_init or native SG host; existing CNet Owner |
| L3 Connection lifetime | one-shot, persistent, compatible pool, explicit reconnect, terminal/idle policy, pinned destination/Owner | Host-owned immutable admission plan; existing Manager, Pool, ManagedDial and CNet state |
| L4 Transfer/write characteristics | small urgent vs bulk; retained buffer/slice/slicev, bounds, queue pressure, partial writes and completion | Each admitted write; CNet FIFO and existing NativeIO |
| L5 Application/protocol | request/response, framing, ACK, idempotency, retransmission/replay, protocol READY | Application/HTTP/FlowMQ/etc., not CNet transport |

**Priority of restrictions** (most authoritative first):

1. Security, exact transport and capability admission. Unsupported options
   fail explicitly, never translate IPC or Pipe into TCP or a new path.
2. Owner/backend hard quotas and native completion/borrow lifetime. Neither a
   connection plan nor a transfer hint may increase a hard owner limit.
3. Immutable connection identity, lifetime intent and protocol compatibility.
4. Per-write bounds and optional host batching within those limits.
5. Telemetry/adaptation for **future** admission, never silent rewriting of
   an already admitted operation.

Do not use a monolithic mutable cnet_connection_set_policy() or add fields to
existing cnet_connect_options in M0/M1. The host may hold its own typed plan
indexed by a generation-checked CNet connection identity and must discard it
after true terminal. No host plan pointer is retained by CNet.

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
admission decisions. Version/size/transport mismatch fails **before** any
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

- A generic strategy registry or virtual strategy chain per socket.
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

**M0 (this PR):** design/mapping only; no new runtime capability or
performance claim.

**M1:** within existing tests/test_cnet_policy.c TinyTest, verify invalid
classification/version, capability rejection, STRICT_KEY/FULL, host plan's
bounded limits, no hidden fallback and no partial outputs. Existing
CNet options/snapshot contracts stay unchanged.

**M2:** existing native CTest cases: real short TCP send+terminal/close;
persistent pool reuse only after protocol READY; small writes under
TCP_NODELAY, retained vector bulk/partial write, budget exhaustion and
request/response without premature close. Real UDP datagram MTU/rejection
and explicit KCP, POSIX/Windows IPC and Pipe supported/unsupported APIs.

**M3:** real 1/2/4 fixed-Owner SG cohosting and terminal-drain/fairness
cases, malformed/failed/partial cancellation, close-vs-sends, retained
slices and late completion, wrong owner, stale generation; existing LLVM
Linux/macOS/Windows x64/arm64 native tests and Linux ASan/UBSan/TSan.
Android builds are NOT device runtime. No new CMeta/ACE, Actor, install
consumer or probe CI. Compare same workload raw vs host-composed policy
in separate opt-in performance experiments with CPU/op, p95/p99,
write amplification, retained bytes and fair shutdown evidence.

**Nonclaim:** the existing successful default CNet/TinyTest CI proves
its established API/test coverage; it does not already prove this
new cross-profile composition or automatically supply transport-level
adaptive batching and stream deadlines. Track only exact HEAD results.
