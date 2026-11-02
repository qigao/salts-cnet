# CNet source closure and local Crypto qualification

**Draft only. No existing Salts binary, provider, or consumer switches.**

## Immutable provenance

CNet sources taken from `qigao/salts`, head
`36889896e7e79fb9842accd9a35ac6e59f0ddab4` of
`refactor/cnet-ipc-name-native`, which stacks:
- Salts #1290: fixed-capacity IPC accepted-child FIFO instead of CSTL deque;
- Salts #1291: private indexed peer map instead of CMeta/CSTL HashMap;
- Salts #1293: caller-owned native IPC path instead of tstr/SDS.

All 51 private CNet source/header files and 13 public CNet headers are
migrated into the existing `cnet/src` / `cnet/include/cnet` module structure. Private Monocypher namespace sources live under `vendor/monocypher`; Reed–Solomon GF(256) source and attribution live under `vendor/reed`.
Only *documentation* in headers is changed to reflect the new target owner.
The RFC 6455 parser is consumed from separate M4.1 (PR #14) and compiled
as one private object; URI comes from the re2c-based PR #11.

## Default target and dependency closure

The current Core candidate always builds production CNet, URI, ASN1 and
Crypto. This supersedes the original opt-in extraction profile; the old
CNet build switch and external GmSSL prefix are rejected. The graph requires:

- `c-ares::cares`: asynchronous DNS; exact private provider package;
- `kcp::kcp`: KCP transport;
- `Salts::Crypto`: the one source-built static archive containing the locked
  local native TLS/algorithm implementation and private libecc objects;
- SIMDe includes for Reed private implementation;
- host re2c (build-time URI lexer only);
- platform socket/security frameworks (Win32 Crypt32/Winsock; Apple Security
  and CoreFoundation where appropriate).

No fallback to system OpenSSL, libuv, plaintext, old Salts libraries, a
fake CMeta/CFlow provider or unversioned vendored CNet is accepted. CMake
uses REQUIRED dependency lookups. Missing exact dependency packages fail
configuration; they do not disable production CNet.

One SHARED `Salts::CNet` owns the production CNet Client/Manager/
Handoff/Listener/UDP/KCP/TLS/WebSocket/Resolver implementations. It links
publicly to new Core/Concurrency/NativeIO and privately to URI, Platform,
KCP, c-ares, the local Crypto archive and one namespaced Monocypher/Reed implementation.
All lower static libraries use PIC when linked into this DSO. The binary
is a new ABI identity; original Salts::CNet symbols cannot be linked as a
second owner in the same process.

## What the provider-free policy test actually validates

`saltscore.cnet_policy` compiles *actual* original C11 source for CNet
destination selection, owner placement and retry/recovery decisions without
GmSSL/KCP/c-ares. It exercises no-retry-on-security failure, expiry, strict
pinning versus eligibility, weighted RR and failure-output semantics.

Standard SaltsCore CI keeps this test within the full default graph on
Linux/Windows/macOS, alongside installed C11/C++17 consumers and the no-Salts
dependency scanner. It remains a policy test and cannot replace production
transport or TLS execution. The WebSocket parser retains its own 3-platform
RFC 6455 CI.

## Full CNet qualification required before switching anyone

1. **Implementation closure**: configure/compile/link the locked local Crypto
   source and exact KCP + c-ares + SIMDe dependencies on Linux/Windows/macOS; include
   installed SDK C11/C++17 link and runtime test. Verify Windows runtime DLL
   closure and relocation. Fail closed when any provider is missing.
2. **DNS/TLS**: real CA/SAN/trust rejection, ALPN, fatal-alert drain, TLS1.2/
   TLS1.3 and GmSSL ShangMi suites; independent OpenSSL/libwebrtc peer
   interop where applicable. No self-loop-only proof.
3. **Transport**: real TCP, UDP, KCP, WebSocket RFC6455 over live sockets,
   IPC/pipe/VSOCK platform limits, retained sends and exact terminal callback
   matching under cancellation.
4. **Concurrency**: NativeIO sharded host leases and cross-shard transfers,
   ownership races, TSan/ASan/UBSan, unload/quiescent drain on real systems.
5. **API/ABI**: C11/C++17 exported headers, public layout, symbol list,
   provider visibility and one binary owner. Only then switch Salts CMeta/ACE
   downstream integration tests; no accidental duplicate target definitions.
6. **Packaging**: exact source SHA + test run/attempt + RID + locked native
   source and dependency artifact identities; Android/iOS cross build is separate from device runtime
   acceptance.

**Source ownership and a successful partial profile do not qualify production
TLS or full CNet.** Current-source native, installed, sanitizer and physical
owner evidence is required independently of source presence.

## Reproducible local implementation CI candidate

`vcpkg.json` requires c-ares, KCP and SIMDe in the base graph, with host
pkgconf on Linux. The historical **cnet** feature is empty compatibility
metadata, not an implementation switch. The repository's fixed registries
and baseline remain the dependency authority. GmSSL is no longer restored
as a package: `crypto/native/gmssl/source-lock.json` records the local native
source and reviewed patches, and `crypto/tools/check_local_native_source.py`
checks the raw Git blob bytes without newline normalization.

The unified LLVM workflow `.github/workflows/ci.yml` restores that manifest
through the pinned curl-only vcpkg-cache action and selects the checked-in
`ci-native` preset. It compiles the complete graph once and runs the formal
CTest suite on Linux, macOS and Windows x64/ARM64. It does not create a second
installed-consumer project. Exact-head success is still required before CNet
can be called provider-qualified.

The additional M2/M5/M6 graph is enabled only by
`SALTSCORE_TEST_CNET_CRYPTO_QUALIFICATION`. It uses the same local Crypto
source and retains Python peer, SAN/mTLS, NativeIO and two-plugin tests. That
option does not alter production CNet and cannot replace its actual owner
audit or production protocol tests.

## Local native ABI and ShangMi implementation test gate

The default CNet build includes two independent C11 tests linked against the
actual local `Salts::Crypto` implementation; their historical names are kept:

- `saltscore.gmssl_tls_io_abi`: ensures the runtime and public header agree
  on `TLS_CTX` and `TLS_CONNECT` sizes, and that external I/O callbacks
  propagate retry signals rather than inventing a synchronous completion.
- `saltscore.gmssl_shangmi_provider`: migrates Salts' existing standalone
  RFC 8998/TLCP provider-side SM2/SM3/SM4 KAT, AEAD, HKDF/HMAC and strict
  cipher/protocol profile test.

The Linux CNet workflow asserts **both named tests are present and actually
run**, beyond the generic CTest. These tests do *not* exercise an actual TLS
handshake or certificate chain, and do not establish Windows/macOS provider
ABI, runtime conformance, or independent network interoperability. The
separate source-byte gate verifies the exact reviewed patch result but is
not itself a protocol test.
