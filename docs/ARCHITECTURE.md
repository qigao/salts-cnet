# Standalone SaltsCore architecture

Canonical decision: [qigao/salts-core#1](https://github.com/qigao/salts-core/issues/1).

## Directional dependency graph

```text
Salts (CMeta / CFlow / CSTL / Component / ACE)  ─┐
SaltsUtils (Jinja / DataBind / Parsers)           ─┼─> SaltsCore SDK
TurboScript / TurboAgent / TurboMedia            ─┘

Salts::Core [C11 base byte views / future buffer/error]
  ├── Platform (clock/thread/CSPRNG) ──> Concurrency ──> Coroutine ──> NativeIO ──> CNet
  ├── FS, Process [native OS; independent bounded queues / native pipes]
  ├── Unicode 17 ──> IDNA UTS #46
  ├── Serial [POSIX / Win32, SPSC]
  ├── ASN1 ──> Crypto [locked local native objects, one static archive] ──> CNet
  └── optional USB / Capture / Playback
```

**No arrow points from SaltsCore to a Salts or SaltsUtils package.**
CMeta reflection, CFlow scheduler/actor/publisher, and CSTL remain in Salts;
none is part of SaltsCore's mandatory dependency closure. Historical
`cmeta_fs_*`, `cmeta_process_*` symbol spellings are distinct from runtime
reflection. Source/API renaming is not itself a reason to discard ABI tests.

## Extraction inventory

- `qigao/salts/utils` + select `platform`: minimum Core, sync FS/Process,
  byte views, clock, log/error and crypto algorithms (split into targets).
- `qigao/salts/utils/src/cmeta_buffer.c`: move mem_pool/mem_buffer/mem_slice
  ownership and public C11 headers to Core, replacing only the old aggregate
  `cmeta_thread.h` include with `<thread.h>`. Consumers of CNet
  must not need CMeta Reflection for buffer storage.
- `qigao/salts/concurrency`: all six direct C11 primitives; names `cmeta_*`
  remain only for existing binary/API shape, with no Reflection dependency.
- `qigao/salts/coroutine` and `native-io`: independent native executors and
  OS completion/readiness mechanisms (future qualification).
- `qigao/salts/cnet` plus `cnet/uri` and WebSocket parser: native transport stack
  moves to Core after NativeIO; CMeta/ACE interface tests stay in Salts.
- `qigao/salts/unicode` and `idna`: all generated Unicode 17.0.0 source tables,
  re2c tool/data hash gates, NFC, Bidi, casefold and IDNA tests. Existing
  `vstr` is `CMETA_STRUCT`-defined: replace reflection-based declaration with
  plain C11 view **while proving byte-exact field layout and call ABI**.
- `qigao/salts-utils/crypto`: Ed448 with private libecc and native CSPRNG.
- `qigao/salts-utils/cflow-fs`: native watch backends and the bounded metadata
  service now live in `fs/`, using Core Concurrency instead of the CFlow worker
  executor. The `fs_watch_publisher` remains
  an optional **downstream Salts/CFlow adapter**, not a Core dependency.
- `qigao/salts-utils/cflow-process`: native process pipes and the bounded Shell
  facade now live in `process/`; NativeIO drives their IOCP/epoll/io_uring/kqueue
  admission and completion independently of CFlow IO Actor. The existing Core
  process owner remains the single process lifecycle authority.
- `qigao/salts-utils/cflow-usb`: current libusb event-thread and callback
  queue are already independent of CFlow's Actor; remove unnecessary CFlow
  linkage and remap thread/error dependencies to Core.
- `qigao/salts-utils/salts_serial`: migrate POSIX/Win32 backends, SPSC ring,
  pump, and events. Replace CSTL `vec_t` with private counted port snapshot,
  preserving deep copy, ownership and allocation-failure semantics.
- `qigao/salts-utils/capture` and `playback`: platform-optional modules.
  Never compile multiple miniaudio implementations into one binary image.

## Native FS / Process asynchronous extraction

The metadata service, native watchers, asynchronous process pipes and Shell
come from `salts-utils-release-rc9` commit
`234c4a73bcefc455d48b3550ec2142d7ff1c3f5a` (`cflow-fs/`, `cflow-process/`).
Regular-file ownership follows `salts` commit
`9df83cfc6885071f00b60d5c61cdb16e67857d86`, `cflow/src/io_file.c` and its native
file backends. These are source references, not runtime/build dependencies.
The extraction retains native code and behavioral tests and replaces the
CFlow executor, Actor, lease and acknowledgment plumbing with Core ownership.

| Capability / public header | State owner and execution |
|---|---|
| Sync filesystem / `fs.h` | Existing descriptor/root capability owner; API preserved |
| Metadata and paths / `fs_async.h` | FS fixed slots and copied paths; bounded Concurrency thread pool |
| Directory events / `fs_watch.h` | FS bounded queue; native Windows/inotify/FSEvents publication |
| Regular-file data / `fs_file.h` | FS handle and private/injected shared runtime; NativeIO completion owner |
| Async standard streams / `process_async.h` | Process owns three pipes; NativeIO driver owns request slots |
| Command execution / `shell.h` | Process owns copied input, bounded output and chunk buffers |

The same `native_io_driver` serves files and process pipes. A mutex protects
MPSC admission/cancellation; one owner submits to the selected native backend,
observes terminals and invokes callbacks. Fixed slot and completion capacities
are allocated at initialization. Successful admission commits one nonzero ID
and a buffer borrow; rejection clears the ID and retains nothing. An accepted
native submission failure is delivered as `FAILED`. Request IDs never wrap.
Callbacks release their borrow only after returning. A delivering slot remains
occupied, and driver reentry or premature destruction returns `EBUSY`.
Concurrent reads must not share writable storage; write storage must remain
immutable until callback return. These APIs do not schedule CFlow tasks or
acquire an Executor implicitly.

| Target | File data backend | Process pipe backend | Directory watch |
|---|---|---|---|
| Windows | IOCP offset read/write | IOCP | Overlapped `ReadDirectoryChangesW` |
| Linux | io_uring offset read/write/fsync | Explicit epoll or io_uring | inotify |
| macOS | Darwin AIO offset read/write/fsync | kqueue | FSEvents |
| Android | io_uring, subject to kernel/policy admission | epoll or io_uring | Explicit `ENOTSUP` |
| iOS / supported BSD | Explicit `ENOTSUP` for file data | kqueue | Explicit `ENOTSUP` |

Backend availability is checked against the target build. Initialization and
native I/O errors propagate; no worker/backend fallback is selected. IOCP
`FILE_FLUSH` returns `ENOTSUP`: blocking `FlushFileBuffers` is not presented as
native asynchronous I/O. On Linux/macOS, wait for writes to complete before
requesting flush when durability is required; flush is not a fence across
concurrent producers. Metadata operations remain explicit worker operations
because their syscall contracts differ from regular-file data. File open and
final handle close are synchronous boundaries. Darwin AIO observation uses
native `aio_suspend` in at most 10 ms slices to bound control-wake delay;
`aio_return` is the sole reclamation point, including after cancellation.

Stop/join producers before lifecycle calls. Call `close`, continue `run_ready`
until `is_quiescent`, then `destroy`. Cancellation is a request: a completed
operation may win and retain its original terminal. Never recycle a buffer or
close its endpoint merely because cancel returned success. Shared file runtimes
outlive every attached file; file close cancels only that file's requests.
Runtime close stops all admission and cancels all requests; runtime destruction
also requires every file to be destroyed. Process close additionally terminates
its Core-owned process tree and waits for the original owner to publish the
terminal result. No second process state machine is introduced. Shell pumps
partial I/O and EOF, reports the shared stdout/stderr output limit explicitly,
and retains the bounded captured prefix on overflow.

This composition reuses NativeIO completion ownership instead of copying a
second IOCP/io_uring engine into FS/Process. Keeping CFlow Actor/Publisher in
Core would introduce a reverse dependency; replacing every metadata operation
with OS-specific async APIs would broaden the semantic change. A short mutex
and fixed-array scans favor an auditable owner over another queue framework.
The driver polls only when called; no scheduler/waker integration or performance
improvement is claimed. Watch threads and the existing process monitor retain
their native roles. `Salts::FS` publicly depends on Platform/NativeIO and
privately on Concurrency; `Salts::Process` publicly depends on Platform/NativeIO
and privately on Core for Shell's existing bounded `tstr` storage.

Migration is additive to the synchronous FS/Process API. New headers use flat
Core includes and `salts_*` symbols; CFlow request/lease types and Publisher/Actor
wrappers remain downstream. Adding `offset` to `native_io_operation` changes
its layout, so all NativeIO consumers must rebuild against this candidate SDK
and zero-initialize descriptors. No published binary compatibility is claimed.
Rollback requires a matched SDK and consumer rebuild, or use of the preserved
synchronous APIs. Do not mix old/new NativeIO structures or link historical
and Core module owners together.

Formal tests stay in `fs/tests` and `process/tests`. Windows llvm-mingw qualifies
this checkout locally; Linux/macOS execution and Android/iOS cross-builds remain
separate release requirements. See [NATIVE-TESTING.md](NATIVE-TESTING.md) for
commands, coverage and limitations.

## Nonnegotiable gates

1. **No dependency cycle**: fresh install/build without Salts or SaltsUtils
   present, no imports of `cmeta/struct.h`, `cflow/*`, `cstl.h`, or any
   `Salts::` target. CI rejects regressions. `cmeta_`-prefixed native function
   names are allowed solely as historical compatibility while implementing
   their functionality without reflection/actor runtime.
2. **Lifetime correctness**: FS sandbox paths and watch event ownership;
   Process cancellation, pipe drain, forced child-tree reaping; USB device
   removal and terminal acknowledgment; Serial background pump join and SPSC
   producer/consumer contract; Capture/Playback stop/unload.
3. **Crypto**: remove incompatible GmSSL/libecc `sha256_*` global symbols and
   duplicate `get_random`; unique include guards; test real final-image
   linkage and RFC vectors, with no hidden provider fallback.
4. **Unicode/IDNA**: re2c >=4.6 is a host **build** requirement only; data
   remains Unicode 17.0.0 SHA-pinned; run official normalization and UTS #46
   conformance; DNS/TLS/SNI A-label parity is tested in the default Core CNet target.
5. **ABI and release**: no published `Salts::Core` replacement before
   source/protocol tests, installed C11/C++17 consumers, Linux/Windows/macOS
   execution, Android/iOS SDK cross-build, symbol audit and exact-head CI.
   Keep legacy implementations until coordinated migration passes.

## Current status

**Draft migration candidate under qualification:** the default graph includes
Core, Platform, Concurrency, Coroutine, NativeIO, ASN1, local static Crypto,
URI and production CNet. Optional module builds retain their independent
source, platform and installed-consumer gates. The native TLS implementation
is compiled from locked local sources and retains its GmSSL provenance;
CNet resolves those functions through the sole Crypto archive. The migration
branch is not a published binary replacement. The strict original source/API
gate, exact-current-source platform CI, physical owner audits and release
blockers remain authoritative for completion.

