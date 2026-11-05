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
  └── optional Media (Capture / Playback)
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
- `qigao/salts/cnet` plus `uri` and WebSocket parser: native transport stack
  moves to Core after NativeIO; CMeta/ACE interface tests stay in Salts.
- `qigao/salts/unicode` and `idna`: all generated Unicode 17.0.0 source tables,
  re2c tool/data hash gates, NFC, Bidi, casefold and IDNA tests. Existing
  `vstr` is `CMETA_STRUCT`-defined: replace reflection-based declaration with
  plain C11 view **while proving byte-exact field layout and call ABI**.
- `qigao/salts-utils/crypto`: Ed448 with private libecc and native CSPRNG.
- `qigao/salts-utils/cflow-fs`: copy native watch backends; replace CFlow worker
  executor with a native Core bounded worker. The `fs_watch_publisher` remains
  an optional **downstream Salts/CFlow adapter**, not a Core dependency.
- `qigao/salts-utils/cflow-process`: keep native process owner and pipes;
  reimplement IOCP/epoll/kqueue admission/completion independent of CFlow
  IO Actor before retiring its old wrapper.
- `qigao/salts-utils/salts_serial`: migrate POSIX/Win32 backends, SPSC ring,
  pump, and events. Replace CSTL `vec_t` with private counted port snapshot,
  preserving deep copy, ownership and allocation-failure semantics.
- `qigao/salts-utils/capture` and `playback`: platform-optional modules.
  Never compile multiple miniaudio implementations into one binary image.

## Nonnegotiable gates

1. **No dependency cycle**: fresh install/build without Salts or SaltsUtils
   present, no imports of `cmeta/struct.h`, `cflow/*`, `cstl.h`, or any
   `Salts::` target. CI rejects regressions. `cmeta_`-prefixed native function
   names are allowed solely as historical compatibility while implementing
   their functionality without reflection/actor runtime.
2. **Lifetime correctness**: FS sandbox paths and watch event ownership;
   Process cancellation, pipe drain, forced child-tree reaping;
   Serial background pump join and SPSC
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

The USB module and libusb dependency were removed on 2026-11-05.
The SDK no longer exports `Salts::USB` or installs `cflow/usb.h`.

**Draft migration candidate under qualification:** the default graph includes
Core, Platform, Concurrency, Coroutine, NativeIO, ASN1, local static Crypto,
URI and production CNet. Optional module builds retain their independent
source, platform and installed-consumer gates. The native TLS implementation
is compiled from locked local sources and retains its GmSSL provenance;
CNet resolves those functions through the sole Crypto archive. The migration
branch is not a published binary replacement. The strict original source/API
gate, exact-current-source platform CI, physical owner audits and release
blockers remain authoritative for completion.

