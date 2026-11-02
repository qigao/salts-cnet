# CNet plain-transport policy composition with optional CMeta/ACE

**Status:** RFC / design only. Tracking [SaltsCore #156](https://github.com/qigao/salts-core/issues/156).

**Grounded source baselines:** SaltsCore master \`bc070affca0afbc5cad6e060b9c60a7a22abad10\`;
CMeta master \`5d1845373f4aa7df721882324a11e93365356be0\`. This RFC
does not modify either installed ABI, network runtime, Plugin lifecycle,
native backend, or SDK release.

**Normative previous decision:** [CMeta #1050](https://github.com/qigao/cmeta/issues/1050)
already defined Managed as existing CNet Strategy + owner-local state,
not a new ClientManager/ServerManager/PoolManager. The final CNet Owner is
fixed; CNet has no Actor, Configurator, Plugin, second Reactor or Proactor,
and no per-message registry lookup. This design **extends usage of that
decision**, not a new CNet policy engine.

## Decision: two layers, one execution owner

The application MAY use CMeta and ACE on the **configuration/control plane**
to assemble policy providers and validate immutable typed configuration.
It MUST use the existing CNet and NativeIO as the **only** connection,
resource-credit, send/receive, completion and terminal authorities.

~~~text
Application / CHttp / FlowMQ / Orbit
  optional CMeta DataDesc + Component descriptors
   -> CMeta::Configurator: explicit choice and dependency/lifecycle graph
   -> CMeta::ServiceHost: optional published generation + Plugin Scope/lease
   -> typed host-owned IMMUTABLE plan (copy or lifetime-pinned borrow)
                         |
                         v
      host on fixed NativeIO/CNet Owner
      validation + admission-only typed interceptors (optional)
         cnet_destination_choose()  [remote endpoint, pure]
         cnet_owner_placement_choose() [local final Owner, pure]
                         |
           authoritative reserve / commit / rollback
            Manager  Handoff  Pool  ManagedDial
                         |
      CNet TCP / UDP / IPC / Pipe authoritative I/O
      NativeIO single-observe, bounded completions and terminal
                         |
        settle real credits, Context and Plugin leases

NO CMeta/ACE call or reflection in per-packet dispatch.
NO new threads, queue, retry engine, Actor or resource owner.
~~~

CMeta's Interceptor header defines a native typed borrowed before/after/error
chain, but **does not** itself supply a CNet policy runtime, guarantee a
Plugin lease, or map its generic short-circuit error to a specific transport
error. Only bind it to bounded admission/control-plane operations; do not
route each packet or CNet callback through it.

## Design pattern mapping

| Pattern | Reuse / role | Ownership and forbidden shortcut |
| --- | --- | --- |
| GoF Strategy | Existing cnet_destination_choose, cnet_owner_placement_choose, cnet_retry_evaluate | Select only; no implicit dial/reserve/retry |
| Component Configurator / Factory | Existing CMeta::Configurator creates an explicitly selected dependency graph | Static providers; no hidden rankings/fallback |
| Service Configurator / Epoch publication | Existing CMeta::ServiceHost publishes generation N+1, holds Scopes and Plugin leases | At most TWO attached generations; no live socket mutation or premature DSO unload |
| Chain of Responsibility / Interceptor | Optional typed CMETA_INTERCEPTOR_TYPE at pre-admission; validation, audit, admission/error hooks | Borrowed hook context and metadata; no hot-path dynamic dispatch or longjmp |
| Acceptor-Connector | Existing CNet listener/client, cnet_manager_adopt/connect, cnet_handoff | Real transport owner only; no parallel socket lifecycle manager |
| State | Existing CNet session/Manager, ManagedDial and cnet_reconnect state machines | CONNECTED is not application/protocol READY; recovery is not request replay |
| Resource lease / transaction | Existing manager/handoff/pool credits, NativeIO request generation, ServiceHost Scope | Reserve -> commit OR release, terminal and real in-flight quiescence |
| Observer / Proactor / Reactor | Existing cnet_observer and sole NativeIO backend observe/dispatch | Never subscribe a second observer to the same completion or invent an Actor hop |

The control plane may additionally supply service-discovery snapshots,
health scoring, tenant quotas and tracing. Those **providers are NOT**
implemented as first-class automatic CNet routing, breaker, rate-limiter
or hedging services today; any such host decision must be explicit and
separately tested.

## Transport capability and policy scope

Key: \`D\` = direct existing transport/config API; \`H\` = only external
host composition of existing decision APIs; \`-\` = invalid/not provided.

| Surface | TCP | UDP | IPC | Pipe |
| --- | :---: | :---: | :---: | :---: |
| Endpoint selection / Owner placement at new admission | H | H | H* | H* |
| CNet Owner quotas, bounded requests, events and callback lifetime | D | D | D | D |
| Connect/read/write budgets | D** | D** | D** | D** |
| TCP keepalive, TCP_NODELAY, linger | D | - | - | - |
| TCP directional shutdown / preserve send on EOF | D | - | - | - |
| Live socket buffer / hop-limit controls | D (TCP properties) | D (datagram properties) | - | - |
| UDP peer association / receive demand / reuse_port | - | D | - | - |
| Local names, listener accept credit and move-owned child | - | - | D | H* |
| Owner-local physical pool and protocol-capacity lease | D (host opt-in) | - | - | - |
| Reconnect/retry | H (client ManagedDial/recovery) | H (application protocol) | H (host must implement transport mapping) | H (host must implement transport mapping) |

*IPC/Pipe names are exact local resource identities. Selecting among
different names is only valid if the application explicitly supplies a
trusted, authorized candidate set. NEVER turn a failed \`ipc://\` or
\`pipe://\` attempt into a fallback TCP connection or another path.

**The existing \`cnet_client_config\` budgets/deadlines are **Owner/client
configuration**, not independently settable on every \`cnet_connect()\`.
The dedicated \`cnet_datagram_config\` and \`cnet_ipc_listener_config\`
own their own budgets. Pipe open on a native handle may complete/fail
immediately: an Owner connect timeout does not create a portable asynchronous
open-time deadline. Do not advertise per-connection deadline override or
per-socket deadline changes where the current ABI cannot provide them.

### Immutable versus mutable scope

**Initialization scope:** allocate the CNet client's command, connection,
request/completion and event budgets; configure a dedicated datagram or
IPC listener; initialize Manager/Pool/Handoff where the host uses them.

**New admission scope:** validate trusted endpoint/Owner topology, choose
remote endpoint and fixed final Owner, reserve actual credits, apply copied
TCP socket options, open/adopt/associate one resource and record its identity.
The selected transport and trust authority are immutable for that admission.

**Live connection scope:** only explicitly supported TCP option get/set,
UDP datagram option get/set, send/receive demand and bounded progress may
change. TCP half-close is TCP-only; no Owner relocation, implicit DNS/IPC
fallback, transparent credential update or reinterpreting a live session's
\`STRICT_KEY\` placement.

**Application logical request scope:** \`cnet_retry_evaluate\` is just the
authorization decision. The caller proves body ownership, idempotency or
non-execution, bytes, budget and deadline, and performs any actual replay.
A reconnect does not prove prior request non-execution.

## Reference C11 usage: existing APIs, no new CNet facade

The following is **existing real API** policy selection code. It deliberately
does not call a fictitious \`cnet_connection_set_policy()\` or claim that
selection reserves transport capacity.

~~~c
#include <cnet/destination_policy.h>
#include <cnet/owner_placement.h>
#include <error_codes.h>
#include <stdint.h>
#include <stddef.h>

int choose_new_tcp_admission(
    const cnet_destination_hint *endpoints, size_t count,
    uint64_t generation, uint64_t endpoint_key,
    const cnet_owner_placement_hint *owners, size_t owner_count,
    uint64_t owner_key,
    cnet_destination_result *out_remote, size_t *out_owner)
{
    cnet_destination_selection remote = {0};
    cnet_owner_placement_input local = {0};
    int rc;
    if (!out_remote || !out_owner) return SALTS_EINVAL;
    *out_remote = (cnet_destination_result){0, 0, SIZE_MAX};
    *out_owner = SIZE_MAX;

    remote.size = sizeof(remote);
    remote.version = CNET_DESTINATION_POLICY_VERSION;
    remote.kind = CNET_DESTINATION_STRICT_KEY;
    remote.endpoints = endpoints;
    remote.endpoint_count = count;
    remote.snapshot_generation = generation;
    remote.expires_at_ms = UINT64_MAX;
    remote.key_hash = endpoint_key;
    remote.key_known = true;
    rc = cnet_destination_choose(&remote, out_remote);
    if (rc != SALTS_OK) return rc;

    local.size = sizeof(local);
    local.version = CNET_OWNER_PLACEMENT_VERSION;
    local.kind = CNET_OWNER_PLACE_STRICT_KEY;
    local.owners = owners;
    local.owner_count = owner_count;
    local.key_hash = owner_key;
    local.key_known = true;
    rc = cnet_owner_placement_choose(&local, out_owner);
    if (rc != SALTS_OK)
        *out_remote = (cnet_destination_result){0, 0, SIZE_MAX};
    return rc;
}
~~~

**Host's next step, not performed by that function:**
check that selected remote is still authorized, reserve final-Owner
credits through \`cnet_manager_reserve\` / optional
\`cnet_handoff_reserve\`, or owner-local \`cnet_pool_reserve_connecting\`
for client dial. Only after actual reservation should it call existing
\`cnet_connect\` / \`cnet_manager_connect\` or its transport-specific
equivalent. Rejection/failure settles every accepted credit according
to its own authoritative contract. \`STRICT_KEY\` FULL fails rather than
silently selecting another endpoint/Owner. Note destination STRICT_KEY uses
stable-ID **rendezvous hashing** while Owner STRICT_KEY uses
\`key_hash % owner_count\`; changing Owner count may change placement
for *new* connections, never migrate existing ones.

## Optional ACE usage — control plane only

These are **existing API names**; the exact component/provider type for a
host's network-policy contract is application-owned and not yet declared in
Core or CMeta. Do not mistake this sketch for a compiled drop-in example.

~~~c
#include <cmeta/configurator.h>
#include <cmeta/service_host.h>

/* Static-only deployment:
 *   salts_configurator_context_init(...)
 *   salts_configurator_context_resolve(...)
 *   salts_configurator_context_start(...)
 *   salts_configurator_context_find_service_from(...)
 *   [admit exact cmeta_interface_desc + FunctionAbi]
 *   [compile/copy typed CNet policy inputs]
 *   salts_configurator_context_stop(...) after all borrows settle.
 *
 * Optional dynamic generation deployment:
 *   salts_service_host_generation_build(...)      // N+1 built off-line
 *   salts_service_host_runtime_publish(...)       // new Scopes -> N+1
 */
static int bind_policy_from_published_host(
    salts_service_host_runtime *runtime,
    const cmeta_interface_desc *required_interface)
{
    salts_service_host_scope scope = SALTS_SERVICE_HOST_SCOPE_INIT;
    salts_configurator_service view = {0};
    if (salts_service_host_scope_acquire(runtime, &scope)
        != SALTS_SERVICE_HOST_OK) return -1;
    const salts_service_host_status result =
        salts_service_host_scope_find_service_from(
            &scope, "app.network.policy", required_interface, &view);
    if (result == SALTS_SERVICE_HOST_OK) {
        /* Application must admit the actual typed Interface/FunctionAbi,
         * then build a self-contained immutable CNet plan from view.
         * NEVER pass view.object, provider vtable or Plugin pointers to CNet.
         * NEVER interpret returned service as a native socket owner.
         */
    }
    if (salts_service_host_scope_release(&scope)
        != SALTS_SERVICE_HOST_OK) return -1;
    return result == SALTS_SERVICE_HOST_OK ? 0 : -1;
}
~~~

**Critical lifetime rule:** the above immediate Scope release is allowed
ONLY if the actual host policy has been fully copied with no provider-owned
borrowed pointers/callbacks retained after release. Otherwise hold the
Scope/Plugin lease until the last in-flight connection callback or policy
hook terminates. The current ServiceHost permits at most **two attached
generations**; old generations may remain BUSY while scopes live. Config
publication affects new admission; it cannot mutate or relocate old CNet
Owner connections. ServiceHost does not load a Plugin itself.

For ordinary fixed configurations, **do not require CMeta at all**:
construct typed CNet policy inputs statically and call its functions.
CMeta/ACE is an opt-in service-host composition dependency.

~~~cmake
find_package(SaltsCore CONFIG REQUIRED)
find_package(CMeta CONFIG REQUIRED)  # No version in CMeta find_package.
target_link_libraries(my_service PRIVATE Salts::CNet CMeta::ServiceHost)
~~~

This is the application/host dependency graph. The Salts::CNet library
must NOT link to CMeta::ServiceHost or CMeta::Configurator.

## Admission transaction and failure semantics

~~~text
validate schema/version/transport + identity/security snapshot
 -> optional admission interceptors BEFORE side effects
 -> choose remote endpoint (if explicitly configured)
 -> choose final Owner (for new admission only)
 -> reserve real Handoff/Manager/Pool/NativeIO credits on the correct Owner
 -> invoke existing CNet transport-specific create/connect/adopt/associate
 -> CONNECTED terminal (transport, not necessarily protocol READY)
 -> optional protocol validates identity/auth/handshake
 -> protocol READY authorizes pool bind / request admission
 -> real CNet terminal + CNet Manager recycle / Pool lease release
 -> ServiceHost Scope release / Plugin lease drain if any
~~~

Each \`reserve\` succeeds exactly once or leaves no credit, and each
successful reserve is eventually committed or released. A callback error,
capacity FULL, wrong/stale generation, cancel, partial I/O or wake failure
must not trigger a fresh allocation or second application replay.
An accepted cross-Owner Handoff publish transfers descriptor ownership even
if the subsequent wake fails; producers MUST NOT republish the same ticket.

Accepted send completion proves local transport settlement, not application
exactly-once delivery. TLS or HTTP2/WS/FM Q protocol readiness and replay
classification remain the higher layer's responsibility.

## Optional policies NOT yet first-class in CNet

Service discovery, active health/outlier selection, adaptive circuit breaker,
per-tenant rate limiter, request hedging, general traffic mirror, endpoint
fallback chains and universal per-connection config hot-update are **not**
implemented as automatic CNet policies. A host MAY supply their results as
immutable eligibility/pressure inputs but must separately prove those
results and ownership. Do not publish a named policy kind in Salts::CNet
until a real consumer, exact ABI and negative acceptance exist.

## Rollout and acceptance (without new CI or consumer projects)

| Gate | Evidence |
| --- | --- |
| M0: design | This RFC and [#156](https://github.com/qigao/salts-core/issues/156); existing policy/API behavior remains unchanged |
| M1: static typed plan | Existing \`tests/test_cnet_policy.c\` TinyTest plus new focused cases within existing native test target: wrong kind/version, TCP-only option on UDP/IPC/Pipe, outdated endpoint snapshot, STRICT_KEY/FULL and zeroed outputs |
| M2: real owner integration | Existing native CNet/Manager/Handoff/Pool/ManagedDial/NativeIO tests for 1/2/4 Owners; actual TCP, UDP peer, IPC accepted-child and Pipe path negative cases |
| M3: optional CMeta/ACE | Existing ACE Configurator/ServiceHost TinyTest for explicit policy selection, exact Interface/FunctionAbi, two generations, Scope/Plugin lease and DSO quiescence; CNet raw users still work with no CMeta |
| M4: platform and performance | Existing Linux/macOS/Windows LLVM CTest x64+ARM64 and ASan/UBSan/TSan, Android build-only, no new installer/consumer/probe CI; opt-in paired raw-vs-policy throughput/latency and retained-credit measurements |

A documentation-only passing check does NOT qualify any runtime gate,
new public CNet API or release. Preserve real terminal, cancellation,
TSan and security negative tests. If multiple genuine application
consumers later require a shared per-connection admission facade, propose
a **separate narrow additive C ABI**; do not silently mutate
\`cnet_connect_options\`, \`cnet_client_config\`, or the existing SDK ABI.
