# Handoff

## 2026-11-01 public header path flattening

- Public headers no longer use `include/salts/`, `include/salts_core/`, or
  `salts_*.h` filenames. Include them from their module include root directly;
  functional directories that already own a namespace, such as `cnet/`,
  `crypto/`, `cserde/`, and `tinytest/`, remain unchanged.
- This is a source-path migration only. Existing C ABI symbol prefixes and
  CMake target names remain stable. Do not restore forwarding headers or
  compatibility directory trees for the retired paths.
- Frozen donor inventories and `serial/original/` retain historical upstream
  names as provenance evidence; they are not current public include paths.

## 2026-11-01 Windows LLVM release identity

- CMake's MinGW platform defaults add a `lib` prefix to Windows DLLs. Keep
  `CMAKE_SHARED_LIBRARY_PREFIX` empty on Windows so MSVC and llvm-mingw publish
  the same versioned `saltscore_<module>-0.1.dll` ABI identity. Do not loosen
  the installed-owner auditor to accept compiler-dependent DLL names.

## 2026-11-01 LLVM preset and CI convergence

- `vcpkg-cache` compiler actions reject protected Release setup when
  `build-type: Release` is combined with `obfuscator: false`. SaltsCore does
  not enable obfuscation, so CI requests `build-type: toolchain-only`; the
  checked-in CMake preset independently selects the Release configuration.
- The outer CMake toolchain is the vcpkg manifest toolchain. Native LLVM or
  the Android NDK is supplied only through `VCPKG_CHAINLOAD_TOOLCHAIN_FILE`.
  Reversing these two toolchains bypasses manifest-mode dependency ownership.
- Existing product CI path filters include production sources and public
  headers, plus native test sources, root CMake settings and the workflow
  itself. These test-only changes qualify the actual native owner graph;
  documentation/packaging-only edits do not trigger new product jobs.
  No separate probe or synthetic installer/consumer workflow is introduced.
- Do not restore installed-consumer/smoke CMake projects. Configure owns the
  complete graph, build runs it without `--target`, and formal tests run only
  through CTest.
- When removing an installer/consumer source tree, remove its native-graph
  registration in the same change. A stale `add_executable` is detected only
  at CMake generation, even when configure has otherwise found all packages.
- Use the shared `qigao/vcpkg-cache` Actions for compiler, host tools and vcpkg
  setup. As in cmeta PR #1351, normal product builds set `restore-packages: "false"`
  and restore the repository's Actions-backed local files cache before CMake.
  Missing ABI packages are built from the pinned manifest and saved to that
  cache after configure. A cold cache is supported; dependency build errors
  still fail the job. Do not impose `--only-binarycaching` on these presets.
  Actions caches are repository-scoped, not a cross-repository package feed.
  Publishing GitHub Packages remains a separate operation.
- Keep ccache restoration independent of the complete registry/port revision.
  ccache checks compiler contents, flags and headers; keep OS/architecture
  and preset namespaces separate.

## 2026-11-01 CNet numeric-host endpoint

- A c-ares numeric-host result cannot be trusted to preserve the service port
  byte order on every platform. `cnet_resolver_submit()` retains the caller's
  host-order port and the callback writes `htons(requested_port)` into the
  validated IPv4/IPv6 sockaddr before transport admission. Do not add retry,
  provider fallback, or timeout relaxation for this failure.
- Local configure/build/test requires the tracked root
  `CMakeUserPresets.json`; do not qualify an older checkout that lacks the
  versioned root presets.

## 2026-11-01 Windows LLVM-MinGW qualification

- Windows CI uses the pinned `vcpkg-cache/setup-llvm-mingw` action for both
  x64 and ARM64. Its `QIGAO_COMPILER_TOOLCHAIN_FILE`, overlay triplets and
  `qigao-*-windows-llvm-mingw` identities are the contract; a local clang-cl
  build is useful for diagnosis but is not equivalent CI evidence.
- LLVM-MinGW 20261020 with CMake 4 exposed a zstd overlay bug: a C-only
  project must guard C++ flag probes with `CMAKE_CXX_COMPILER_LOADED`, not the
  mere presence of `CMAKE_CXX_COMPILER`. This is fixed in vcpkg-cache PR 262,
  merge commit `529019437597fa71f7d8dcc561d26fc7b0603ae6`.
- MinGW DLL import libraries require explicit public API export annotations.
  Do not rely on `WINDOWS_EXPORT_ALL_SYMBOLS` to recover legacy Platform
  functions.
- LLVM-MinGW LLD map files use `Address Size Align Out In Symbol`, unlike
  MSVC maps. Native-Crypto ownership auditing must combine the LLD input
  member with `llvm-nm` archive-member definitions and use `llvm-readobj` for
  PE imports; unsupported linker diagnostics are not a substitute.
- Use `SALTS_THREAD_LOCAL` for shared Core TLS declarations. Selecting
  `__declspec(thread)` from `_WIN32` alone makes LLVM-MinGW ignore the
  attribute and silently turns logger caches into process globals.
- After adding source checkout rules to `.gitattributes`, rematerialize the
  locked source tree with `core.autocrlf=false`; otherwise the index contract
  and the working bytes can disagree.
- The TLS close fix from PR 129 depends on the reciprocal shutdown machinery;
  do not cherry-pick the close-only change onto an older owner state machine.
- The exact LLVM-MinGW TLS 1.3 `send_buffer_and_close` scenario from PR 129
  passes when invoked directly. Do not globally enable
  `SALTSCORE_CNET_PRODUCTION_REQUIRED_MTLS_TEST` yet: its pre-existing TLS 1.2
  invalid-EKU negative case leaves the Python peer waiting for alert/EOF until
  its socket timeout, while the native server waits for the peer to close
  before its IOCP receive becomes terminal. CancelIoEx, graceful shutdown and
  abortive-close experiments did not establish a safe fix and were reverted;
  keep this as a separate fail-closed handshake-termination issue.
- `setup-re2c-tools` uses `actions/setup-python`, which narrows
  `PKG_CONFIG_PATH` to the hosted Python prefix. On Linux this hides native
  multiarch `.pc` files from vcpkg's `pkgconf`, even after the SDK packages
  are installed. Append `/usr/lib/$(dpkg-architecture
  -qDEB_HOST_MULTIARCH)/pkgconfig`, `/usr/lib/pkgconfig` and
  `/usr/share/pkgconfig` after the action, and probe the required PipeWire
  module before configure.
- The full Android preset must use `ANDROID_PLATFORM=android-26`. Capture's
  retained MediaProjection ABI calls `ANativeWindow_toSurface`, and its
  compiler guard intentionally rejects API 24; do not weaken that guard or
  add a lower-API fallback.
- `SaltsCore.Native` publication stays inside the existing eight-RID LLVM CI.
  The tag run installs the already-qualified graph and packages those install
  trees; do not restore the removed standalone consumer/installer workflow or
  publish from a locally assembled SDK.

## 2026-11-01 downstream physical-owner audit

- `tools/audit_runtime_owner.py` is the Core-owned cross-platform parser used
  by CMeta's installed physical-owner audit and is referenced by
  `docs/M4-RUNTIME-ONE-OWNER.md`. Do not remove it as migration-only tooling;
  keep `tests/test_audit_runtime_owner.py` registered in the formal CTest graph
  so downstream source pins cannot lose the auditor silently.

## 2026-11-01 SIMD owner migration

- `Salts::SIMD` moved to SaltsUtils following qigao/salts-utils#732. SaltsCore
  0.1.1 must not build, install or export a second SIMD target. SIMDe remains a
  private base dependency because CNet Reed still uses its SSE2 facade.
- The next immutable package/tag is `SaltsCore.Native 0.1.2` / `v0.1.002`.
  Downstreams that own `Salts::SIMD` must reject the previous 0.1.0 package,
  which still exports that target.

## 2026-11-01 Serial module directory

- The active native Serial owner lives at `serial/`; `salts_serial/` is only
  the historical donor path recorded in frozen migration inventories and must
  not return as a root source directory. Public `salts_serial_*` ABI names and
  `<serial.h>` remain unchanged.

## 2026-11-05 USB removal

- The user requested removal of the entire USB module. The SDK no longer
  builds or installs `Salts::USB`, `cflow/usb.h`, or the libusb provider.
  Native and Android presets omit the `usb` manifest feature; CI no longer
  installs the Autotools bundle needed only by libusb.
- Historical migration inventories remain provenance snapshots, not the
  current SDK surface. Serial USB metadata uses native OS APIs and remains
  part of Serial.

## 2026-11-05 SNI identity selection qualification

- The independent pollux-go non-mTLS handshaker's `ServerName` verifies the
  certificate but does not send SNI. Use the existing independent mTLS client
  with an explicit SNI extension when qualifying ShangMi certificate selection;
  never count a default-certificate handshake as SNI coverage.
- Default Python key shares exposed a TLS 1.3 HRR failure: ClientHello2 added
  padding after a larger ClientHello1 omitted it. RFC 8446 permits padding
  addition/removal/length changes. GmSSL #28 handles that exception while
  retaining duplicate-extension and other ClientHello consistency checks.
- Rejecting ClientHello2 also exposed an uninitialized-key dereference in
  `tls13_send_alert`: `TLS_state_client_hello_again` must use a plaintext alert,
  because HRR has not established handshake traffic keys. Keep the negative
  HRR cases; successful negotiation alone misses this failure path.
- The Python SNI suite now includes default-group handshakes and observes the
  wire HRR and padding lengths without modifying the independent TLS engine.
  The native formal suite forces HRR deterministically, independent of Python's
  platform-specific default groups, and checks valid and rejected mutations.

## 2026-11-05 client certificate selection

- TLS 1.2 must distinguish receipt of CertificateRequest from having a selected
  signing identity. No match still sends the empty Certificate message and skips
  CertificateVerify; a zero key index must never reach key lookup.
- Independent Go TLS peers wait for the native client's close_notify before
  closing TCP. Closing immediately after response data races native close/send
  completion on Windows and does not test identity selection.
- Distinct CA hints require distinct root subjects, not only distinct keys.
  Keep generated CommonName values within the X.509 length bound (64 characters).
- A TLS1.3-capable client negotiating TLS1.2 must add its retained ClientHello
  to the raw CertificateVerify transcript. The range context also advertises
  PSS for TLS1.3; TLS1.2's local signing selector must not label PKCS1 as PSS.
  Keep independent range-to-TLS1.2 mTLS cases as regression coverage.

## 2026-11-05 certificate signature policy

- GmSSL's TLS1.3 context has an extension-50 switch, but tls13_init previously
  did not copy it into the connection. A populated certificate policy alone
  therefore neither advertised the list nor selected it for verification.
  Keep mixed handshake/issuer-signature tests; identical lists miss this bug.
- Certificate lists do not require a handshake-capable algorithm. PKCS1-only
  certificates are valid with RSA-PSS TLS1.3 CertificateVerify. Do not reuse
  handshake-list version validation for certificate policy.

## 2026-11-05 TLS AES-protected PKCS8

- GmSSL #30 already parses explicit HMAC-SHA256 and AES256-CBC envelope
  parameters. Reuse its ASN1/PBKDF2/AES implementations; no provider patch or
  second BER/DER parser is needed for this credential-input addition.
- Select only the documented PRF/cipher pairs before derivation. Key length
  must equal that cipher's key size; reject absent PRF and unsupported pairs.
  Preserve all work/output bounds and erase both AES/SM4 schedules on exit.
- Keep separate independent .aes and .encrypted fixture files so AES tests
  cannot silently replace SM3/SM4 coverage in subsequent subtests.

## 2026-11-05 PKCS8 AES key sizes

- GmSSL's common X509 algorithm parser knew AES128/192 CBC, but the later
  pbes2_enc_algor_from_der whitelist admitted only AES256 and SM4. Update that
  owning whitelist; no new OID decoder or ASN1 parser belongs in Crypto.
- Derive exactly the cipher-OID key size (16/24/32), never infer it from an
  optional PBKDF2 keyLength. Preserve the negative mismatched-length cases.
- The maximum-iteration check is shared by all AES key sizes. Keep its full
  boundary case with AES256 while exercising each size's other acceptance and
  failure cases, so the formal suite does not repeat the same expensive KDF.

## 2026-11-06 TLS validity diagnostics

- A date rescan after a generic certificate error can mislabel the first failure
  or use a different clock sample. Capture expiry/not-yet-valid where GmSSL's
  actual x509_cert_check fails, preserving verification order and status.
- Propagate the specific result through CA-purpose, normal-chain and TLCP
  verification; their generic certificate assignments must not overwrite it.
  Successful checks must leave verify_result unchanged.
- Invalid intervals and clock failure remain generic. Certificate positions are
  unknown unless reported explicitly; do not label every validity error index 0.

## 2026-11-06 TLS validity certificate positions

- GmSSL #33 records the peer-chain cursor at the actual failing validity check
  and propagates it through all five TLS verifier call sites. Crypto copies it
  only for expired/not-yet-valid failures. No certificate rescan or new clock
  sample is involved; local-only anchors and generic errors remain unknown.
- Independent RSA/P256 TLS1.2/1.3 fixtures exercise indices 0, 1 and 2 with
  file/PEM/DER trust, plus unknown local-anchor/malformed-interval positions.
  SM2 mTLS covers both endpoints; TLCP distinguishes signing/encryption leaves.
  The native runner checks the owned diagnostic again after owner teardown.

## 2026-11-06 immutable certificate verification time

- Copy the optional Unix-second value once, before allocation, callbacks or
  trust-file access. NULL selects the system clock; zero is a valid explicit
  epoch, not a sentinel. Reject invalid values, unavailable provider ranges
  and unsupported platform-trust enforcement at context admission.
- GmSSL #34 routes context-owned time to all five protocol verifier calls and
  leaf/CA/anchor checks. Do not override the process clock or scan certificate
  dates after verification. Peer-policy/revocation clocks remain independent.
- Independent fixtures must keep unaffected certificates valid at the chosen
  time. For exact leaf validity endpoints, give its local issuer a wider window
  to avoid an unrelated anchor failure caused by fixture creation timestamps.
- Full native-release-user graph and ten selected formal CTests passed across
  the initial and affected follow-up runs. New scenarios cover 252 handshakes;
  the registry-pinned configure/build also succeeds without an overlay.

## 2026-11-06 certificate purpose diagnostics

- KU/EKU checks already derive their required purpose from the handshake role.
  Capture decoded role mismatches at those checks, including CA EKU restrictions;
  do not infer purpose errors from every rejected extension or rescan a chain.
- Record indices at the actual peer-chain cursor. Local-only anchors remain
  unknown. Preserve generic malformed/other-constraint results, missing-extension
  acceptance, CA anyExtendedKeyUsage behavior and the earlier validity failure.
- Formal provider tests distinguish successful/wrapper calls, truncated KU/EKU
  and unrelated BasicConstraints failures; native/independent fixtures check
  leaf/issuer/anchor positions and retained diagnostics after owner teardown.
- Full native-release-user graph and ten selected formal CTests passed, covering
  248 purpose/control handshake scenarios and five provider extension cases.

## 2026-11-06 Windows ARM64 startup observation (#260)

- CI #370 failed the one-owner SG TLS-isolation case at sharded runtime creation,
  before TLS setup; the original assertion discarded the constructor status.
  Preserve owner count, backend kind and the returned status at this test boundary.
  Keep the failing assertion and cleanup unchanged; do not retry construction.
- The same job passed its purpose suites and later 2/4-owner cases; the other
  nine matrix jobs passed. The root cause remains unknown under #260. Local x64
  formal loopback repetition (`ctest --preset native-release-user -R
  "^saltscore.cnet_tcp_loopback$" --repeat until-fail:64 --output-on-failure`)
  passed all 64 runs. This does not qualify ARM64 or close the issue.

- Follow-up formal NativeIO coverage uses 768 same-process runtime generations
  (512 single-shard, 128 each for two/four shards), checking owner-local execution,
  exact command settlement, closed admission and quiescent destruction. Four
  invalid backend configurations exercise bootstrap error propagation and cleared
  output ownership. Local native-release-user full graph and NativeIO/coroutine/
  concurrency/CNet-loopback CTests passed; ARM64 reproduction remains required.

- Confirmed diagnostic gap: an accepted bootstrap had no cancellation callback,
  so executor cancellation left bootstrap_done false and create returned generic
  EIO. Record the original cancellation status and done flag before the executor
  terminal is joined; leave backend_initialized false for a cancelled bootstrap.
  Existing first-shard error selection and owner-local cleanup remain unchanged.
- Temporary branch `verify/bootstrap-cancel-260` injected executor ENOMEM on
  shard 1 and changed only the existing NativeIO formal test. Full user-preset
  graph built; `ctest --preset native-release-user -R "^saltscore.native_io$"
  --output-on-failure` failed before the fix (two EIO results instead of ENOMEM),
  then passed all four cases with the same injection: 2/4-owner partial startup,
  earlier backend EINVAL, and normal single-owner creation after cleanup.
  Temporary injection/worktree/branch were removed. Main full graph and five
  related formal CTests passed. This proves cancellation propagation, not that
  cancellation caused the original Windows ARM64 observation; #260 stays open.

- CI #374 reproduced the startup failure in the new formal NativeIO lifecycle
  test: Windows ARM64, generation 112 with two IOCP owners, create returned
  SALTS_ENOMEM (-4030). One/four-owner cases and CNet loopback passed in the same
  job. Executor startup reserves singleton broadcast consumer slots using
  Disruptor try-register; its one-shot weak CAS may reject a vacant slot.
  Use strong CAS for that bounded slot attempt, retaining memory orders and
  full-capacity rejection. Formal Disruptor tests exercise 4096 registrations
  each with one/four slots, last-slot reuse, full rejection and publication.
  Local full native-release-user graph and six related formal CTests passed.
  Temporary diagnostic PR #262 / CI #375 confirmed the owning failure path on
  Windows ARM64: the singleton weak CAS returned false with expected still
  VACANT, immediately followed by executor startup failure and NativeIO ENOMEM.
  It failed at generations 1125/29/1 for 1/2/4 owners respectively. The other nine
  matrix jobs passed. Keep the same amplified formal suite for the strong-CAS
  comparison, then remove the temporary diagnostics, worktree and branch.
  The historical #370 assertion discarded its status; its exact cause remains
  an inference from the now-reproduced startup failure, not a captured fact.

## 2026-11-06 TSan audio runtime package indexes

- The private PulseAudio runtime is installed before the Linux capture SDK
  step refreshes apt metadata. A hosted image's stale package lists can name
  removed libsoup builds and fail with HTTP 404 before configure. Refresh the
  index at the audio install boundary; retain fail-fast package installation.

## 2026-11-06 certificate signature failure positions

- GmSSL's existing cert_chain result lost the checked certificate's position.
  Capture it only where the actual presented-certificate signature check fails:
  standard chain cursor minus one; TLCP signing leaf zero, encryption leaf one,
  then the current intermediate. Retain original check order and error category.
- Failed root discovery still returns TRUST_ANCHOR with unknown position. A
  signature failure does not justify rescanning a chain or guessing leaf zero.
  Crypto copies the provider index into its existing first-failure diagnostic;
  CNet keeps the owned value through TLS/owner teardown.
- GmSSL 3.2.0#36 is pinned in manifest registry, CI cache action and source lock.
  The existing formal standard-TLS CTest failed against #35 with CHAIN_SIGNATURE
  and SIZE_MAX instead of the checked index, then passed with #36. Full local
  native-release-user graph and eight related formal CTests passed (67.55s).
- Independent fixtures exercise 160 signature/control handshake scenarios:
  RSA/P256 TLS1.2/1.3, both native mTLS roles, two intermediate levels, ShangMi,
  TLCP signing/encryption leaves, file/PEM/DER and unknown root-selection errors.
  No new test project, feature switch, verification rescan or retry is needed.

## 2026-11-06 local KeyUpdate byte budgets and formal-test admission

- `key_update_byte_limit` is a copied SHANGMI_TLS13 client/server scalar; zero
  disables this budget and 1..2^34 bounds encrypted application plaintext per
  local sending key. Records split at remaining capacity. Charge only after
  successful encryption, not on every retry of pending ciphertext or on control
  records. Reset on local sending-key updates, including mandatory responses;
  receiving a peer's new key must not refill this independent budget.
- GmSSL #37 uses the existing bounded record/KeyUpdate state machine and one
  owner-local uint64 counter. Byte-only policy does not enable the record-count
  trigger; either configured limit can trigger one update. Reject impossible
  usage greater than the budget before subtraction. No new timer/queue/buffer.
- Formal provider cases verify exact 2-byte prefixes from 5-byte input under
  byte-at-a-time writes, original-key KeyUpdate/new-key application ordering,
  simultaneous limits, mandatory responses, disabled/maximum/rejected limits
  and failure-before-output for invalid counter state. Independent SM2 peers
  check 3-byte logical sends across quota boundaries on both native roles and
  mTLS server, limits 1/2/maximum and byte/record precedence. Configuration is
  erased after synchronous context admission to verify copied ownership.
- Corrected a previous qualification report: 72 certificate-signature mTLS
  scenarios from #263 were not selected by CTest's anchored Go test filter.
  Route the helper through registered TestShangMiMutual; its native mode must
  expect CHAIN_SIGNATURE plus the explicit index, rather than depth/unknown.
  Keep send callbacks checking the exact configured logical length (3 bytes for
  quota tests), not an obsolete one-byte-only fixture assumption.
- Use the existing user preset and formal CTests. Initial eight related tests
  passed; cnet_shangmi_key_update passed after correcting fixture lengths, and
  cnet_shangmi_required_mtls passed all newly admitted position cases (13.42s).
  Three affected adjacent parser CTests also passed (56.03s); ten distinct
  relevant formal CTests pass across the initial/affected runs. Final full CI
  qualifies the delivered API, provider package and test-entrypoint correction.
- Send-side KeyUpdate previously ignored secret/key derivation returns. Four
  formal absent-digest cases (both roles and AEAD suites) reproduced SEND_AGAIN
  instead of the fatal error. Check both derivation results before budget reset
  or transport output; reject the failed transition with zero consumed bytes,
  no emitted control ciphertext and the old budget unchanged. Crypto latches
  the fatal stream error; no recovery/rollback to application traffic is allowed.
  With the same formal failure fixture, GmSSL IO, required-mTLS and KeyUpdate
  CTests passed after the fix (17.98s). Counter-invariant tests use valid AEAD
  keys and an available transport, so a missing guard cannot pass merely because
  unrelated cipher setup or backpressure also rejects the operation.

## TLS 1.3 key age and duplex record ownership (2026-11-06)

- SHANGMI_TLS13 client/server `key_update_interval_ms` is immutable at admission.
  Zero disables; uint32 milliseconds uses a stateless Crypto OS monotonic clock.
  Start once at provider handshake completion; sample before new application
  records. Any enabled time/record/byte budget can trigger one KeyUpdate.
  Pending application/control ciphertext finishes unchanged. Successful local
  key changes reset age; receiving peer keys must not reset the sending key.
  Clock failure/regression, missing initialization and failed derivation remain
  fatal. Compare before subtraction; no deadline-addition overflow or timer task.
- Formal isolated-KeyUpdate/then-send regression exposed an existing HIGH issue:
  tls13_recv waited for another header with shared recordlen=5. tls13_send treated
  this as pending output, bypassed admission and returned success with sent=0.
  Four role/AEAD cases reproduced the error. A coalesced application record hid
  the defect by clearing the shared receive cursor; do not substitute that
  fixture for the isolated-control regression.
- GmSSL #38 isolates established TLS1.3 incoming ciphertext/cursors in one fixed
  record buffer. Received plaintext reuses databuf, so outgoing plain_record
  cannot overwrite retained input tails. All profiles share the TLS_CONNECT ABI
  and its larger fixed allocation; there is no progress-time allocation or
  growth. Existing ticket parsing follows the received-plaintext buffer without
  claiming restoration/0-RTT qualification.
- New formal provider cases cover exact expiry, combined budgets, startup and
  later clock failures/regression, epoch zero, maximum interval/clock values,
  mandatory response reset, peer-update non-reset, partial writes, derivation
  failure, partial RX header/body versus TX, partial TX versus RX and retained
  plaintext tails. Real-clock independent CNet cases run through the existing
  TestShangMiKeyUpdate entry (both native roles and mTLS server), with exact
  authenticated record/update order and final-key close. Configuration scalars
  are erased after init. Four unsupported-profile endpoint configurations fail
  before absent trust-file access or peer-policy retain/callback.
- Registry-pinned native-release-user configure/full graph passed. Nine related
  formal CTests passed after duplex correction (82.34s); the final affected
  provider boundary CTest passed again after additions. No extra validation
  project, alternate provider or CMake feature switch was added.

## Bounded TLS 1.3 post-handshake framing (2026-11-06)

- TLS1.3 records do not equal handshake messages. Thirty-two formal endpoint /
  AEAD / request-kind / split-position cases reproduced premature fatal rejection
  against GmSSL #38. GmSSL #39 assembles complete supported messages using the
  consumed initial-handshake fragment array and one new length scalar. The
  initial Finished boundary consumes that array before established I/O starts.
  Sending and received plaintext remain independent; no progress allocation.
- Reject empty handshake fragments, unknown types, tickets received by servers,
  oversized headers, interleaved application/alert records and KeyUpdate suffix
  bytes. Apply peer-update admission and derivation only once after a complete
  update ending at the record boundary. A partial message cannot authenticate
  close_notify or release application data. Retain the existing fatal latch.
- Existing ticket serialization accepted network-sized tickets into a 512-byte
  local array with no capacity preflight. Compute the exact encoded size before
  derivation/output (53 fixed bytes + ticket, maximum 459 ticket bytes), reject
  count overflow, check derivation/file completion and clear temporary key and
  session material on every admitted exit. The empty-ticket check incorrectly
  tested its length pointer rather than the value; reject zero-length tickets.
  This reception work does not qualify session restore/cache or 0-RTT.
- Formal provider coverage adds 118 cases, including partial assembly across
  independent writes, malformed/interrupted frames, ticket/update coalescing,
  maximum/excess ticket sizes, empty values, count overflow, expansion failure
  and failing file output. Test wrong ticket roles with correctly matched peer
  traffic keys; flipping only the receiver role would fail AEAD before testing
  message admission. Test reuse stays in the existing ABI CTest.
- Independent peers add 26 scenarios inside registered TestShangMiKeyUpdate:
  five update-fragment layouts across native client/server/mTLS server, three
  ticket/fragment/coalescing/native-client paths, and four malformed layouts
  across server authentication and mTLS. Do not add an unselected standalone
  Go Test function. Native checks preserve FAILED/EPROTO/read for interruptions.
- Pinned native-release-user configure/full graph passed. Nine related CTests
  passed (87.26s); after the final empty-ticket/type corrections the two affected
  CTests passed again (10.57s). The provider test now executes 376 internal cases.

- Enforce the Finished phase before reusing initial handshake storage. Four
  negative role/AEAD cases retain the original buffer on pre-Finished input.
  Existing synthetic established-peer fixtures now explicitly mark handshake
  completion, preserving their exact admission/key assertions.
  The final pinned full graph and all three affected CTests passed (24.78s),
  including all 376 provider cases with zero skipped.

## Peer KeyUpdate time/byte spacing (2026-11-06)

- The existing consecutive-update limit resets on any nonempty authenticated
  application record. Add immutable SHANGMI_TLS13 client/server minimum time and
  byte intervals rather than changing that existing burst contract. Zero disables
  each minimum; the first valid update is free, later updates must satisfy all
  enabled minima. Count both request kinds, including replies. A violation is a
  permanently latched EPROTO before another receiving-key derivation.
- One owner holds a seen flag, peer timestamp and capped uint32 byte credit.
  Credit is explicitly bounded at the minimum, not a cumulative counter. Charge
  authenticated plaintext once per decrypted record, never padding, empty/control
  records, repeated reads or outgoing data. Discard surplus on update commit;
  pre-first-update data cannot be banked. Local responses cannot refill peer credit.
  No array/allocation/queue/thread is added. Quiescent destruction stays unchanged.
- Share the existing monotonic clock for peer spacing/local age. Initialize once
  at Finished if either policy needs time. Reject different callback/user clock
  domains before configuration mutation; disabling one policy retains the other's
  borrowed clock. Byte-only spacing retains no unused callback. Clock failure or
  regression is fatal; compare before subtraction, never add a deadline.
- This is strict minimum spacing, with one initial allowance, not a configurable
  token bucket/window burst. It can reject spec-conforming crossed/requested
  updates. Applications must choose compatible send/receive policies and accept
  disconnect on violation. Admission still preserves mandatory replies. No
  request_update=0 exemption, automatic recovery or retry is introduced.
- Formal provider spacing coverage adds 87 cases: exact/max/short bounds,
  fragment completion, shared-clock lifetimes/conflicts, burst precedence,
  nonbanked credit, partial reads, epoch zero, failed clock/peer derivation and
  exclusion of padding/unauthenticated data. Existing TestShangMiKeyUpdate adds
  30 independent native-client/server/mTLS-server cases, including immutable
  input erasure, real-clock spacing and retained terminal errors. Time failures
  use UINT32_MAX, not a scheduler-dependent short "early" exchange; success and
  byte-only combined failures use an intentional 400ms wait for a 250ms minimum.
  Server failure injection still waits for the native SEND completion marker.
- Twelve unsupported-profile endpoint configurations fail before absent trust
  files or policy references/callbacks.
- CI #391 exposed a pre-existing independent mTLS negative-fixture race:
  reject_malformed_ca_no_signature_match legitimately rejected CertificateRequest
  before the peer finished its later authentication messages. A broken pipe then
  hit an incorrectly late authFlightSent gate. As for the other malformed request
  cases, mark the exact rejection stimulus only after emitting that request.
  Keep native handshake-failure/no-CONNECTED/no-application assertions intact.
- Two formal early-reject scenarios withhold the certificate tail and keep TCP
  open. A received alert must authenticate as fatal decode_error; clean abrupt
  transport termination is also permitted by the existing failure contract.
  Bad MAC, malformed/truncated record, unexpected data or timeout cannot satisfy
  the gate. Native retained handshake-failure assertions stay intact.

## TLS 1.3 fatal alert sending direction (2026-11-07)

- HIGH: the early-reject probe exposed tls13_send_alert using server traffic
  keys/IV/sequence for both roles. Client alerts failed independent AEAD
  authentication and advanced the receiving sequence. Select the active local
  sending direction by role; preserve pre-key plaintext alerts. Pending partial
  output reuses the already encrypted record and advances its sequence only once.
- Sixteen formal provider cases cover both roles, both ShangMi AEAD suites,
  handshake/established encrypted alerts with one-byte writes, and all four
  pre-key states. Before the fix, four client-direction cases failed receiving
  sequence preservation and both independent early-reject cases failed MAC.
- With provider f856a0a1a468a80b6376528618cda926a666f479 (port tree
  5bfc4769b17a01f8063d067ef9417cfb6031a8b0), native-release-user configure/full
  build and all nine related CTests passed (88.89s). The provider suite executes
  479 cases with zero skipped; independent mTLS early-reject records authenticate.

## Explicit SHA384/SHA512 encrypted TLS memory credentials (2026-11-07)

- The memory PKCS8 loader admitted only SM3/SM4 or SHA256/AES. GmSSL already
  supplies generic PBKDF2-HMAC and SHA384/SHA512 digests; extend its bounded PRF
  decoder and Crypto's explicit AES-only dispatch instead of adding a provider,
  general ASN1 parser, digest inference or trial-decryption path. PRF omission
  still means unsupported SHA1; malformed/unknown PRFs and SHA384/512 with SM4
  fail before derivation. Work, salt, IV, key-size and output limits are unchanged.
- All state remains owned by synchronous initialization. Borrow password/input
  only during the call, erase derived keys/cipher/output on failure, and publish
  only after exact PKCS8 parsing and certificate/private-key binding. No public
  struct, configuration switch, allocation, thread or production dependency added.
- Registered Go entries add 184 RSA/P256 PEM/DER admission scenarios (each checks
  client/server contexts), 48 standard TLS1.2/1.3 client identity handshakes,
  36 ShangMi native/native and independent mTLS paths, and 12 TLCP dual-key paths.
  Both PRFs use every AES size; binary/empty passwords, exact PRF selection,
  malformed parameters, work bounds and identity mismatch remain formal checks.
  New identity scenarios require their generated fixture rather than selecting
  an existing SHA256 input if its map entry is absent.
- Before the implementation, the formal client-identities CTest failed all 96
  newly valid admission cases. Pinned GmSSL #41 uses 99156c278e9f10fe72376573a2fc8b5340a40183
  / port tree 789a8e17c3d0206a8434169134af3526c39bb62c. native-release-user
  configure/full build and all five related CTests passed (83.83s). Existing
  client-identities coverage passed again after its final fixture-map guard
  (56.72s).
  SHA256 and SM3/SM4 cases remain in those entries. Additional PRFs, PKCS12/PFX,
  file-password loaders and standalone key-export formats are separate work.

## TLS1.2/range independent certificate signatures (2026-11-07)

- The existing certificate_signature_algorithms list was TLS1.3-only. Extend
  STANDARD admission to exact TLS1.2 and ranges, using the same immutable context
  array and no public layout change. TLCP still fails ENOTSUP before trust I/O.
  Initialize the existing per-connection extension flag in the TLS1.2 path.
- ClientHello extension 50 carries certificate policy separately from handshake
  extension 13. Server selection intersects local certificate policy with the
  peer's certificate list, or its handshake list if extension 50 is absent.
  Both received chain roles and their top signature against a local issuer use
  the certificate policy, preserving trust, fatal latching and owner teardown.
- TLS1.2 CertificateRequest has one shared list. Do not union certificate-only
  schemes into handshake offers: that would advertise unauthorized handshake
  algorithms. Intersect its shared list separately with local handshake and
  certificate policies, then select a CA/type-compatible identity. Empty
  intersections preserve empty-Certificate/REQUIRED-rejection semantics. The
  new intersection is a bounded 32-int handshake-stack array, without dynamic
  storage, retained inputs or a new progress owner.
- Formal coverage adds six byte-exact TLS1.2 ClientHello cases (485 provider
  cases total), 22 new CNet exact/range/forced-TLS1.2 server-auth cases, 45 native
  mTLS cases using independent P256/P384 certificates across file/PEM/DER, and
  nine independent exact/range client-identity handshakes. Include the omitted
  extension 50 fallback constraint and the TLS1.2 shared-request rejection with
  matching TLS1.3 success controls. Caller arrays are erased before progress.
- The new TLS1.2 formal case reproduced configuration rejection before the
  implementation. Pinned GmSSL #42 uses 8cf1c6e282f958fed44e2c2c889824bdd6b8e330
  / port tree 31ddf7a06fad9b7391f6e40c0a4bc0e3ff2a19b6. native-release-user
  configure/full build and six related CTests passed (84.39s), then the two
  affected CTests passed after final peer-constraint additions (22.62s).
  No new dependency, configuration switch, retry, test skip or versioned API.

## Complete explicit SHA-2 PKCS8 memory-import PRFs (2026-11-07)

- Add HMAC-SHA224, SHA512/224 and SHA512/256 to the bounded provider PRF decoder
  and Crypto's AES-only digest dispatch. Together with SHA256/384/512, this
  completes RFC 8018's six explicit SHA-2 PRFs for AES128/192/256-CBC memory
  credentials. Reuse GmSSL primitives; do not truncate SHA512 output or alias
  the truncated variants to SHA224/SHA256. AES256 with either 28-byte PRF needs
  two PBKDF2 output blocks, covered by independent Go encryption.
- Keep the synchronous initialization owner, existing input/work/output bounds,
  failure-atomic context publication and private-key/certificate binding. Derived
  keys, cipher state and decoded keys retain their erasure paths. No new public
  field, dependency, allocation, thread, default PRF or trial decryption path.
  SHA1, other KDF/cipher schemes, PKCS12 and standalone exports remain separate.
- Reuse one hash/OID fixture table for standard TLS admission and identity
  scenarios. Named selectors use a separator rather than prefix matching, so
  SHA512/224 and SHA512/256 cannot accidentally select SHA512. Unknown names fail.
  The new PRFs run all AES sizes and PEM/DER with empty/binary passwords, exact
  label selection, malformed parameters, work bounds and mismatched identities.
- Existing registered entries add 276 RSA/P256 admission scenarios checking
  both context roles, 72 standard TLS1.2/1.3 client identity handshakes, 54
  native/native and independent ShangMi mTLS paths, and 18 TLCP dual-key paths.
  Before implementation all 144 newly valid admission cases failed. Existing
  SHA256/384/512 and SM3/SM4 cases remain selected.
- Pinned GmSSL #43 uses 5c4eb708fe29752f43da9b4464ed00e11bcb30c8 / port tree
  af32f1b14ccce16861245d2452225745bdd48902. native-release-user configure/full
  build and all five related CTests passed (107.31s); client-identities completed
  in 73.04s under the unchanged formal timeout. No extra verification project,
  CMake feature flag, test skip, retry or relaxed assertion.


## Local #219 completion branch (2026-11-07, not yet pushed)

- User requires completing the remaining authorized software locally in one pass,
  then pushing after completion. Work only in feat/crypto-219-completion at the
  existing salts-core-cnet-policies worktree; preserve the unrelated dirty main
  checkout. No remote Git/PR/issue closure or push has occurred. Provider stays
  pinned to GmSSL 3.2.0#43; no new production dependency or provider changes yet.
- Implemented bounded, atomically retained immutable decrypted credential objects
  and explicit profile-specific group lists. Contexts import separate provider key
  state. Formal tests erase/release all source material before actual TLS/TLCP/
  ShangMi handshakes and cover concurrent context construction and input rejection.
- Added authenticated DER PKCS12/PFX import into those objects: integrity before
  decryption, finite SHA2/SM3 MACs, existing PBES2 AES/SM4 policy, bounded cumulative
  KDF work, strict BMP password encoding, complete bag/certificate/key matching,
  and TLCP dual-key roles. Independent Python fixtures plus actual CNet standard,
  ShangMi and TLCP handshakes pass. Legacy SHA1/PBE and general exports remain out
  of this finite import profile. The configured Python executable is passed into
  the existing formal peers, with no interpreter fallback search.
- Added finite SM2/SM3 CMS SignedData: explicit RFC/national content OIDs, canonical
  signed attributes, exact embedded certificate set, separate signature/issuer IDs,
  pinned path/time/purpose/revocation checks before output. Native GmSSL CMS is not
  wrapped as a generic trust API. Independent gmsm/PKCS7 tests cover attached/
  detached, four-level paths, maximum messages/IDs and signed malformed attributes.
- Added finite RFC5083 AuthEnvelopedData composition using existing SM2 key
  transport and SM4-GCM: one recipient, fresh key/nonce, separate full tag, no CBC
  padding oracle, and private plaintext until complete authentication. Recipient
  trust reuses the existing path owner with EMAIL_ENCRYPTION (emailProtection EKU
  and keyEncipherment KU); SignedData rejects encryption-only trust. A shared
  private CMS schema helper owns bounded ASN1 composition only, not cryptography.
  Independent Go ASN1/SM2/SM4 tests cover both directions through maximum signed
  payload size, fresh key/nonce, long issuer Names, independent certificate IDs,
  corruption, recipient trust, callback gates and exact output erasure. Inner
  signed payload composition is tested; GCM does not authenticate sender identity.
- Added direct-issuer SM2 OCSP primitives and copied immutable TLS/CNet snapshots:
  SHA1(identifier-only)/SHA256/SM3 CertIDs, responder Name/key hashes, explicit SM2
  IDs and time/age/skew/rollback/nonce policy, all-entry validation and distinct
  snapshot-authentication vs actual-target-good decisions. Real ShangMi mTLS in
  both roles and TLCP dual-leaf tests cover status, issuer substitution, lifetime,
  data/close and unsupported role/profile gates. A separate pollux OCSP producer/
  verified parser qualifies independent wire composition. Delegation, wire
  stapling and distribution/cache workflows are still separate work.
- Fixed new OCSP factory alias admission order: an unrelated invalid field must
  never trigger output clearing over borrowed input. Formal regression covers
  each aliased span and ordinary failure clearing. OCSP skew fixture initially
  encoded local timezone: DER requires UTC; fix the independent fixture, not the
  production validator. New CMS negative mutation fixtures clone encoded input so
  one corruption cannot make later negative cases pass for the wrong reason.
- Validation uses saved native-release-user LLVM-MinGW environment and full graph
  builds, then formal CTest only. The LLVM-MinGW bin directory must precede PATH
  so C++ tests load libc++/libunwind; the earlier launch failure was rerun passing.
  Crypto/CNet/provider selection (54 formal CTests) passed in 160.96s before the
  envelope addition. Full build plus CMS envelope/signing/trust/admission and C++
  header tests passed (five tests, 2.70s); final long-name/max-content additions
  passed all three CMS tests in 2.05s. Latest OCSP primitive/snapshot/actual-transport
  group passed four tests in 3.59s. Logs are under TEMP/salts-219-*.log. No new
  verification project, feature flag, skip, retry or relaxed authentication.
- #219 is NOT complete: general PKIX/path discovery/constraints, remaining trust/
  diagnostic configuration, delegated/distributed revocation, separate TLCP
  issuers/IDs and client auth, session restore/cache/0RTT/PHA, production DTLS and
  CNet/SCTP integration, and actual private-arithmetic side-channel qualification
  remain. SDF/SKF remains user-deferred; hot update remains excluded. Session
  research found native file-based tickets and an unfinished age calculation;
  do not expose those helpers as a production memory-session API without binding
  peer/profile/hostname/ALPN/policy and qualification. No constant-time or full
  platform/production-DTLS claim follows from functional local tests.

- Continued OCSP completion adds explicit same-issuer delegated responder
  primitives and immutable snapshot inputs. Reuses pinned path validation for
  responder digitalSignature/OCSPSigning, explicit issuer ID and validity at now
  and producedAt. Requires issuer-signed noncritical exact NULL ocsp-nocheck;
  no missing-status fallback or recursive revocation. Direct functions never infer
  delegation. Optional embedded certificates match the configured responder and
  optional exact issuer. Signer-ID and CertID-issuer binding remain separate.
  Independent Crypto delegation tests and actual ShangMi mTLS/TLCP dual-leaf
  tests pass; TLCP encrypted-leaf revoked/unknown/missing status still rejects.
  Snapshot bound is now <100 KiB, checks remain allocation-free and references
  retain every copied public input. Full build plus six OCSP/CRL tests passed in
  6.64s; affected TLCP tests passed after delegation additions (1.95s). Delegated
  responder discovery, non-no-check revocation and wire stapling are still open.

- TLCP independent certificate-signature work now changes the local provider port:
  feat/gmssl-219-completion has port-version 44, a new
  tlcp-certificate-signatures.patch and its portfile registration, uncommitted and
  unpushed. Core admits TLCP CLIENT SM2/SM3 or RSA-PKCS1-SHA256 certificate lists;
  handshake remains SM2. Server lists still ENOTSUP while client auth is absent.
  Provider enforces both sibling leaves with the actual common issuer, presented
  issuer signatures and the selected local anchor signature after full native
  authentication. Initial ordinary-chain matching falsely used the encryption
  leaf as issuer and rejected valid RSA leaves; the dedicated sibling matcher
  fixes the ownership/schema boundary instead of weakening mapping checks.
- Latest full configure/build uses explicit
  -DVCPKG_OVERLAY_PORTS=C:/projects/cpp/turbonet/.worktrees/vcpkg-cache-signature-position/ports/gmssl
  with native-release-user. This is the local dependency fact source; Core's
  committed manifest/registry still select #43. Final publication must register
  #44 tree/version/baseline and update Core's pin together before removing the
  override. Shared binary cache restore/build/upload remains active (first local
  #44 build took 13s); there was no remote Git push/PR/issue mutation.
- The new CNet TLCP certificate-policy CTest reproduced ENOTSUP on old Core/#43.
  Full graph build + native ABI/admission and independent TLCP policy tests pass
  with #44 (2 tests, 2.77s). Expanded default/mixed/optional-issuer tests are next.
  Task-only source snapshots for patch generation are under ignored
  build/provider-tlcp-policy (no CMake project); remove only those task files
  when the complete local pass is finished. Do not modify the dirty main tree.

- Expanded TLCP certificate-policy tests now pass default/exact/mixed allowlists,
  SM2/RSA issuers, CA file/PEM/DER and optional transmitted issuer (48 scenarios).
  Source arrays are erased before progress; ClientHello rejects any accidental
  TLS extension 50. Full graph and all 57 selected Crypto/CNet/provider CTests
  passed on the local #44 overlay (167.61s), before the depth-position addition.
- Added x509-depth-positions.patch to the same unpublished #44 port. The native
  verifier records the first presented issuer beyond its existing bound (TLS
  depth+1, TLCP depth+2) only when that peer position actually exists. Crypto
  retains the existing DEPTH reason with that index; authentication/error ordering
  is unchanged and local anchors stay unknown. Existing mTLS tests reproduced
  old missing positions; full build plus ABI/TLCP-policy/mTLS tests passed (3,
  29.05s). Actual independent TLCP chains with one/two/three issuers qualify the
  valid boundary and index 3 for both final and earlier traversal failures;
  the full TLCP suite passed (10.78s). Generic malformed/constraint diagnostics
  and other positions are not claimed complete by this slice.
- Review found constructor output aliases could clear borrowed raw/PFX/key/
  password/descriptor storage before rejection. Both identity constructors now
  reject alias before clearing, preserve aliased storage, and document that out
  owns no reference on entry. Formal ABI/admission and independent PFX tests pass
  after the fix (2, 4.94s). This is separate from the earlier OCSP alias boundary.
- CodeGraph sync completed: 75 changed files / 1219 nodes, 30.3s, before the final
  alias test additions; .codegraph stays ignored. No commit or push performed.
  Current #44 source extraction under vcpkg/buildtrees includes local patches;
  do not mistake it for an unmodified #43 source when generating later patches.
  The task-only build/provider-tlcp-policy snapshot is #43 for tls_vrf.c/tlcp.c;
  its role is patch generation only, not a separate verification project.

- Final local regression after depth and credential-alias fixes: full configured
  graph already built; `ctest --preset native-release-user -R
  'crypto\.|saltscore\.(cnet_|crypto_tls_|gmssl_)' --output-on-failure` passed
  57/57 tests in 167.99s (TEMP/salts-219-local-regression-depth.log). Native Release
  only: no new Linux sanitizer/device/macOS/platform CI claim. No push, commit or
  issue closure. Keep user request to finish the authorized software pass before
  pushing; #219 remains incomplete despite these local capability additions.

- Read-only refreshed #188 and its original #195 contract at exact commit
  e7895b5961258ee8f7d900eb0f6fc1e51766b533. It specifies a bounded datagram owner,
  replay/flight timers, pre-auth anti-amplification and SCTP transaction/output
  reservation, but no chosen DTLS version/cipher profile. The historical contract
  path is absent from this checkout; it was read via GitHub, not restored.
  RFC6347/5288 research is started for a first-party DTLS1.2 record layer over
  existing GmSSL primitives; NO DTLS code/public API or supported recipe added.
  Do not treat TLS byte-stream feed/take or existing SCTP peer_binding as DTLS.
  Next software work includes selecting/documenting an actual DTLS profile,
  handshake/trust/fragment/replay/retransmission state and real NativeIO/SCTP
  bridge before any production or interoperability claim. Session restoration
  also needs authenticated peer/profile/hostname/ALPN/policy binding and a
  bounded owned cache; native file-session helpers remain unqualified.

- 2026-11-08 local completion pass: added context-owned client TLS1.3 session
  cache and actual accepted-restoration queries through Crypto/CNet. Capacity
  0 disables; 1..16 slots support exact STANDARD TLS1.3 and SHANGMI_TLS13 only.
  Each entry owns bounded ticket/PSK/original authenticated chain/name/ALPN;
  one mutex serializes copies, never crypto, allocation, callbacks or I/O.
  Cyclic replacement, expiry, consumption and final context/stream destruction
  clear secrets. Repeated host/ticket entries are deduplicated while cached.
  First handshake progress consumes the newest exact-name nonexpired entry
  once, not stream construction; failure does not put it back. No unbounded
  spent-ticket history or persistent/file cache. Monotonic millisecond age plus
  age_add uses modulo-2^32 arithmetic; expiry never extends on selection.
- Initial independent Go TLS test exposed no tickets on the first full handshake:
  PSK_DHE was advertised only on a cache hit. Cache-enabled first handshakes now
  advertise psk_dhe_ke without an identity; the identity/binder appears on hits.
  Pure PSK and 0RTT remain disabled. Server PSK refusal uses the protocol's full
  certificate authentication path. Accepted PSK_DHE restores/revalidates the
  original chain with current trust/name/time/purpose/signature/depth rules,
  checks the original ALPN/cipher and reruns retained peer policy before READY.
  No previously cached revocation decision is treated as current admission.
- Provider candidate remains GmSSL3.2.0#44 in the local provider completion
  worktree. New tls13-client-session-cache.patch adds a synchronous bounded NST
  callback carrying the derived PSK, lifetime, age_add and borrowed ticket.
  Rebuild the matching ABI; no socket/file owner is added to Core/CNet. The
  source snapshots build/provider-session-base/{include/gmssl/tls.h,src/tls_psk.c}
  are pre-session-patch #44 and exist ONLY to generate patches, not a verification
  project. Registry version/baseline and Core pins are still #43: do not claim a
  fresh registry build supports the local changes. Keep the explicit overlay
  until ALL authorized software work is complete, then register/pin/publish
  the exact final port tree with Core. No commit/push/issue closure yet.
- Formal cache tests cover malformed bounds, cyclic eviction, copied secrets,
  exact hostname, exact expiry, UINT64_MAX age arithmetic, backwards clocks,
  duplicate identities and eight concurrent one-entry consumers (one winner).
  Independent Go TLS1.3 and pollux ShangMi peers each prove first full auth,
  two PSK_DHE restorations, disabled-cache controls, rejected tickets after
  server key rotation, data/close and caller-context release before the last
  handshake. Standard TLS also proves changed ALPN, newly denying peer policy
  and original-certificate expiry reject resumed connections with the expected
  retained diagnostic and no application byte. CNet admission rejects enabled
  unsupported ranges/profiles and excessive capacity before absent trust I/O.
- Full configured native-release-user graph built; formal CTest filter
  `crypto\.|saltscore\.(cnet_|crypto_tls_|gmssl_)` passed 60/60 in 191.90s
  (TEMP/salts-219-session-regression.log). Windows x64 LLVM-MinGW Release only;
  Linux sanitizers/macOS/Android/device validation was not executed. CodeGraph
  sync succeeded (58 files, 1100 nodes, 21.4s); its affected analysis returned no
  test candidates, so actual module reads and formal regressions determined
  coverage. .codegraph remains ignored and uncommitted.
- #219 is still incomplete: Core server ticket issuance and other restoration
  profiles, PHA/0RTT, general PKIX/path constraints/cross-signing, richer trust
  parameters, stapling/distribution/advanced CRLs and persistent revocation
  cache, non-no-check delegate revocation, separate TLCP issuers/signing IDs and
  client authentication, first-party DTLS/SCTP (#188), and real SM2/SM9 private
  arithmetic side-channel qualification. Hardware stays user-deferred; hot
  update excluded. Functional tests do not establish constant-time behavior.
- Final affected checks after the 60-test pass: the legacy qualification facade
  rejects nonzero cache capacity only after normal config admission validates
  struct size. Its two static/shared-owner CTests passed after full rebuild.
  The historical standard-TLS aggregate excludes the separately registered new
  resumption test, avoiding duplicate execution; all its previous suites still
  run. Configure/full build and those three affected tests passed (72.61s,
  TEMP/salts-219-session-final-registration.log). Eight additional native NST
  callback cases verify derived-PSK/metadata delivery and fatal rejection for
  callback returns 0/-1/2 without ticket-count publication or application bytes;
  return 1 releases the next application record. Full graph rebuilt and the
  affected saltscore.gmssl_tls_io_abi CTest passed again (TEMP/
  salts-219-session-callback.log). git diff --check passes; no new platform claim.

- 2026-11-08 continuation for server tickets / PKIX / DTLS: server Crypto/CNet
  configs now carry session_ticket_capacity (1..16) and lifetime seconds
  (1..604800), both zero to disable, exact STANDARD TLS1.3 / SHANGMI_TLS13 only.
  The context owns a bounded stateful table; random 32-byte wire identities map
  to PSK/original client chain/exact SNI/ALPN/cipher/selected-local-leaf digest.
  A bounded pending issuance snapshot is published only after Core admission.
  Lookups copy without consumption, so forged binders cannot erase real tickets;
  binder verification remains native and fatal on failure. Resumed mTLS restores
  and revalidates the chain and reruns peer policy. No 0RTT/pure PSK/persistence.
  Invalid/mismatched/expired/missing entries use protocol-defined full auth.
- Native tls13-server-session-cache.patch adds issue/lookup callbacks, bounded
  complete PSK identity/binder vector checking (<=16), correct HRR transcript
  binding, retained SNI, and suppresses CertificateRequest in an accepted PSK
  handshake. It also fixes NST partial output: after issuance count becomes zero,
  pending record bytes must still drain before native handshake completion.
  Issue secrets clear on all paths, and no early_data extension is advertised.
  The independent Go client exposed a real RFC6066 status_request framing error
  (extra outer length); encoder/parser/printer now use the direct OCSP struct.
  Exact bytes, independent empty vectors and malformed lengths are formal cases.
- New formal CNet tickets tests belong to cnet/tests, with registration in that
  owner. Existing BUILD_TESTING gating is reused; no new feature switch or
  consumer/smoke project. Go standard TLS qualifies server auth, REQUIRED-mTLS,
  disabled client/server, changed ALPN/SNI, one-slot eviction, policy rejection,
  original client-certificate expiry and early context release. Pollux qualifies
  ShangMi server auth, bad binders followed by successful original-ticket reuse,
  unknown tickets, invalid ages and actual one-second ticket expiry. Private
  cache tests add readonly concurrent lookup, expiry and identity-collision
  rejection. Eight native output cases cover byte-at-a-time NST and callback/
  bounds/lifetime failures across AES/SM4. Before PKIX/DTLS additions, full graph
  and 62 related CTests passed (191.85s, TEMP/salts-219-server-tickets-regression.log).
  Test-driver pitfall fixed: do not cancel the native server process before
  waiting for its final successful cleanup after peer close_notify.
- PKIX correction: an initial analysis of x509_ext.c's NameConstraints dispatch
  was incomplete; x509_vrf.c DOES implement intermediate constraints. Independent
  Go x509 verification plus real CNet reproduced the narrower HIGH anchor bug:
  anchor constraints checked only the nearest CA, permitting an out-of-subtree
  leaf through an unconstrained intermediate (TEMP/salts-219-pkix-constraints-before.log).
  x509-anchor-constraints.patch now checks every subordinate and excludes an
  identical presented anchor. Six standard-TLS oracle cases cover intermediate/
  anchor controls with/without a presented root. Eight TLCP cases cover direct/
  intermediate chains and both leaves; unequal SANs must still fail the existing
  entity-pair check as CERTIFICATE before constraints, while equal outside SANs
  fail as CONSTRAINTS. Both affected CTests passed after correction. Constraint
  index remains SIZE_MAX. This is not full PKIX/path-building qualification;
  self-issued rollover behavior and general policy/cross-signing remain open.
- DTLS work is INTERNAL ONLY: crypto_dtls_record.{h,c} implements an allocation-
  free DTLS1.2 AES128-GCM epoch/record primitive over GmSSL, not a public DTLS
  API/handshake/provider. It bounds plaintext to 16384, uses 13-byte headers,
  8-byte explicit nonce + 16-byte tag, epoch/48-bit sequence AAD and 64-record
  replay window. Sequence never wraps; no replay update before authenticated
  tag; wrong epochs/replay/auth failures publish no plaintext. Datagram views
  preserve coalesced record boundaries. Alias/capacity failures do not mutate
  keys/sequence, and quiescent clear erases keys. AES temporary initialization
  zeros unused schedule bytes before copying owned state.
  crypto.algorithms.dtls_record uses TinyTest plus an independent Python AESGCM
  oracle (test-only existing cryptography), including a valid explicit nonce
  DIFFERENT from the header sequence, exact native output decryption, maximum/
  empty records, replay/reordering/window edges, forged high sequence/tag/header,
  expiry of the 48-bit sending space, aliases and coalesced input. First formal
  run passed (TEMP/salts-219-dtls-record.log). No DTLS network readiness claim.
- Source-only patch snapshots build/provider-server-session-base (includes
  client-session #44; tls.h/tls_psk.c/tls13.c/tls_ocsp.c) and
  build/provider-pkix-constraints-base/src/x509_vrf.c feed the task-only patch
  generation scripts in build/. They are NOT separate validation projects.
  Provider candidate is still unpublished #44, registry/Core pins still #43;
  keep explicit local overlay. No commit, push, PR or issue mutation performed.
  User root worktree remains untouched. CodeGraph final sync: 82 files, 1800
  nodes, 19.7s; .codegraph stays ignored. All current execution remains native
  Windows x64 Release, without new sanitizer/macOS/Android/device claims.
- Remaining: general PKIX path discovery/policies/cross-signing and fuller
  constraint qualification; DTLS handshake/trust/cookies/anti-amplification,
  bounded fragment/flight/retransmission/close, NativeIO/SCTP ownership and
  independent DTLS network qualification (#188); TLS1.2/TLCP restoration, PHA/
  0RTT, advanced revocation/distribution/stapling, TLCP client auth/separate IDs/
  issuers, and private arithmetic side-channel qualification. Hardware remains
  user-deferred; hot update excluded. #219 is NOT complete, do not push early.
- Final combined local evidence: full configured graph and CTest filter
  `crypto\.|saltscore\.(cnet_|crypto_tls_|gmssl_)` passed 65/65 in 198.64s
  (TEMP/salts-219-tickets-pkix-dtls-final.log). After zero-initializing the private
  AES schedule temporary and making Python oracle checks independent of assert
  optimization, full graph rebuilt and crypto.algorithms.dtls_record passed
  again with PYTHONOPTIMIZE=1 (TEMP/salts-219-dtls-record-final.log). This is the
  last source/test change; do not rerun the same successful scope for ceremony.
  Both worktree diffs pass git diff --check. No commit/push/issue closure.

## DTLS preparation and native PRF failure propagation (2026-11-08)

- Continue the same local-only completion branches. User still requires one
  completed software pass before publication; no commit/push/PR/issue change.
  GmSSL remains the only production provider, hardware deferred and hot update
  excluded. General PKIX and a production DTLS handshake are NOT complete.
- Private crypto_dtls_cookie.{h,c} now implements stateless address/ClientHello
  HMAC-SHA256 cookies, a 60-byte nonamplifying challenge and strict bounded
  epoch-zero input validation. No connection allocation or retained per-peer
  state precedes a valid cookie. A future listener must canonicalize the peer
  address and own the immutable random-key context. Cookie verification is only
  address proof, never certificate trust or handshake READY.
- Private crypto_dtls_handshake.{h,c} provides eight owned 16KiB message slots,
  overlap-aware bounded fragment assembly, once-only complete-message views,
  no sequence wrap and a timer armed only after actual whole-flight send
  terminals. Conflicting fragments fail transactionally. Fake monotonic time
  covers retry authorization, delayed sends, doubling/cap, exhaustion, backward
  clocks, overflow and acknowledgment. Full flight storage/transport draining
  remains the future handshake owner's job.
- Private crypto_dtls_secrets.{h,c} adds bounded canonical SHA256 transcript
  snapshots, EMS-only SHA256 master/key expansion and role-specific Finished
  verification. All supplied shared-secret/random/hash inputs are borrowed only
  for a call; key derivation commits both epoch-one directions atomically.
  Wrong authenticated Finished body/role/hash/length (including empty NULL)
  erases master and both traffic epochs and latches failure. Semantic order,
  certificate trust and authenticated record dispatch remain the owner boundary.
  Transcript initialization accepts actual post-cookie starting sequences;
  hardcoding ClientHello sequence one breaks renewed-cookie challenges under
  RFC6347 section 4.2.1. Excluded ClientHello/HelloVerifyRequest bytes never hash.
- HIGH native finding: tls_prf ignored every HMAC failure, could use unfinished
  output and left secret HMAC state/blocks on the stack. Local provider #44 adds
  tls-prf-failfast-erasure.patch after the existing candidate patches: check all
  HMAC calls and produced lengths, clear the complete requested output after
  any admitted failure, erase all base/work HMAC and block state at exit. No
  replacement PRF or new dependency. Invalid admission leaves output untouched.
  Overlay configure rebuilt this exact patched provider; publication/pins are
  still pending the entire completion pass, as described above.
- Formal crypto.algorithms.dtls_handshake uses TinyTest plus Python stdlib
  SHA256/HMAC and the existing test-only cryptography AESGCM oracle. Tests cover
  Python/native cookie exchange, independently normalized fragmented messages,
  EMS master/directional keys/IVs, both Finished proofs and 65-byte PRF output.
  Synthetic transcript bodies intentionally are not an actual certificate or
  ECDHE handshake. Native digest callbacks fail at EVERY init/update/finish
  invocation, including after prior output blocks, with full output-zero and
  guard checks. The second TinyTest source defines TINYTEST_NO_MAIN to share
  the existing runner; do not introduce a separate consumer/smoke project.
- Full configured native-release-user graph and 3 initial related CTests passed
  (1.73s, TEMP/salts-219-dtls-secrets-first.log). Shared PRF regression through
  CTest filter `crypto\.|saltscore\.(cnet_|crypto_tls_|gmssl_)` passed 66/66
  (198.11s, TEMP/salts-219-dtls-secrets-regression.log), with PYTHONOPTIMIZE=1.
  After final private transcript-start/empty-Finished changes, full graph built
  and both DTLS CTests passed again (0.21s, TEMP/salts-219-dtls-secrets-final.log).
  Handshake suite: 15 TinyTest cases, 679 assertions; record suite: 7/138.
  No need to repeat unchanged successful shared-PRF scope without a new concern.
- Source-only PRF patch snapshot: build/provider-dtls-prf-base/src/tls.c;
  generator: build/provider-dtls-prf.py. These ignored artifacts generate the
  provider patch, not validation projects. The Core user root remains untouched.
- Next: validated P256 exchange, signed key-exchange parameters, credential/
  trust admission and EMS negotiation inside a complete DTLS owner, then bounded
  flight storage/dispatch/close, NativeIO/SCTP and independent network tests.
  General PKIX path discovery/policies/cross-signing, TLS1.2/TLCP restoration,
  PHA/0RTT and other previously listed software qualification gaps remain open.
  Private components alone must not enable a public DTLS API or close #188/#219.

- Follow-on in the same local pass: crypto_dtls_exchange.{h,c} now owns a fresh
  GmSSL P256 ephemeral key with copied public export and a terminal one-use ECDH
  operation. Canonical uncompressed points require coordinate/on-curve checks;
  malformed-point/crypto failure and success all erase the private scalar.
  A repeated exchange/reinit without explicit clear fails. Public flight bytes
  must be retained before exchange consumes the native key.
- Private ServerKeyExchange verification takes an ALREADY trust-admitted DER
  leaf, not an untrusted chain. Bounded exact body/DER consumption, P256 params,
  cipher/scheme/key-type matching and the native proof all precede peer-point
  publication. Current finite internals: ECDSA-P256/SHA256 with ECDHE-ECDSA or
  RSA-PKCS1/SHA256 with ECDHE-RSA, both AES128-GCM/SHA256. Proof binds both randoms
  and exact encoded EC parameters. No signature trial/fallback, signing path or
  public DTLS API. Trust/purpose/expiry/hostname/revocation and offered-scheme
  admission remain the full handshake owner's prerequisite.
- Existing formal handshake test now includes dtls_exchange.c with
  TINYTEST_NO_MAIN. Python independently signs ECDSA/RSA ServerKeyExchange and
  computes P256 ECDH against two native fresh keys, checks the derived EMS master
  and decrypts native AES-GCM output. Negative cases include all short prefixes,
  bad randoms/signatures/algorithms/points, coordinate range, trailing DER/body/
  signature, alias rejection and complete private-scalar erasure. Final full
  graph build and both DTLS CTests passed (0.38s, PYTHONOPTIMIZE=1,
  TEMP/salts-219-dtls-exchange-final.log). Handshake suite now 19 cases / 1147
  assertions; record suite remains 7 / 138. Shared PRF has not changed after the
  earlier 66/66 regression, so that success still covers the provider mutation.
  Next full owner work starts with certificate trust and EMS negotiation plus
  real bounded flights/record dispatch; P256/SKE helper mechanics are now present.
  The final source pass reuses Crypto's signature identifiers and names encoded
  parameter bounds; both worktree diffs pass git diff --check. CodeGraph remains
  local/ignored. No public API/pin publication, commit, push or issue closure.

## Private DTLS client owner and real independent UDP interoperability (2026-11-08)

- Same local-only Core/provider completion branches; no commit, push, PR or issue
  mutation. GmSSL remains the only production provider. Candidate #44 provider
  patches and registry/Core #43 pins are unchanged this turn; keep the overlay
  until the entire software completion pass is ready to publish together.
- Added private crypto_dtls_client.{h,c}, composing existing cookie/framing/
  transcript/ECDH/AEAD primitives into a server-authenticated DTLS1.2 CLIENT.
  It negotiates the two P256 AES128-GCM suites (ECDSA-SHA256 or RSA-PKCS1-SHA256),
  mandatory cookie and EMS, strict ASCII DNS identity and optional one-protocol
  ALPN. No verification-disable, legacy-master, client-auth, ticket, renegotiation
  or worker branch. No public header/capability/API is enabled.
- One exclusive progress owner owns fixed roots/chain storage (4096 bytes and
  <=5 certificates each), eight message slots, three <=1200-byte flight entries,
  one pending wire datagram and one bounded plaintext scratch area. Config
  roots/name/ALPN are copied; existing crypto_tls_stream_peer_policy is retained
  once and released only on quiescent clear. Data context stays caller-owned
  until clear; data views borrow only during callback; mutation reentry rejects.
- Certificate parsing is strict/exact DER and bounded. Native
  tls_cert_chain_verify_ex supplies the same chain/time/purpose/usage/constraints/
  hostname checks as TLS1.2. Trust admission precedes ServerKeyExchange proof;
  certificate verification runs again after Finished before READY. Peer policy
  runs exactly once after Finished, never in lieu of proof or mandatory trust.
  Master secret and ephemeral private scalar are erased once no longer needed.
  No exporter/resumption/PHA capability is implemented by this finite owner.
- Output prepare lends one stable owned wire until an actual sent terminal.
  Input returns BUSY without consumption while output is pending or a flight
  is unsent; the future NativeIO adapter must retain that datagram and route
  actual terminals first. Abort erases secrets but preserves pending wire; clear
  stays BUSY until sent drains it. Retransmission retains logical messages and
  reseals with fresh record sequences, without rehashing or regenerating ECDH.
  Timeouts and recognized repeated HVR/previous complete ServerHelloDone share
  six retries and exponential backoff. Partial old messages do not reset timers.
  A new HVR sequence is a new challenge even if its opaque cookie is unchanged.
- Authenticated Finished fragments can arrive before CCS, but neither READY
  nor policy/data callbacks precede both. Epoch-zero fragments cannot occupy a
  Finished slot. Bad tags/replays/wrong epochs are discard outcomes and do not
  poison replay admission. Invalid authenticated proofs/alerts/policy, terminal
  send failure, exhausted retries and clock rollback permanently fail/erase.
  Record callbacks preserve zero-length and coalesced record boundaries. One
  queued send is bounded to MTU minus AEAD overhead; no application replay.
  close_notify waits for its actual local send terminal before key erasure.
- Formal tests remain module-owned. dtls_client_cases.c joins the existing
  TinyTest runner with TINYTEST_NO_MAIN. dtls_client_endpoint.c is a pipe peer
  for Python/Go tests, matching existing Crypto interoperability endpoints;
  it is not a consumer/smoke project. The scripted Python oracle independently
  computes signatures/ECDH/EMS/Finished/AEAD and checks negotiation, trust/time/
  DNS/usage/critical-extension/constraint negatives, real intermediate paths,
  loss/reordered/overlapping certificate/Finished fragments, pre-CCS gating,
  authenticated bad Finished, policy rejection, bad tags/replay, send BUSY,
  abort during encrypted pending send, clear and policy-reference balance.
- Added a test-only Go module under crypto/tests/algorithms/independent:
  github.com/pion/dtls/v3 v3.1.15, exact go.mod/go.sum, CGO_ENABLED=0/GOWORK=off.
  Four real UDP-loopback cases cover ECDSA/RSA, MTU-512 peer fragmentation,
  bidirectional application data/close and loss of the first client Finished.
  The bridge reports actual Go UDP write returns; it does NOT exercise Core
  NativeIO/CNet/SCTP or their whole-batch routing/cancellation contracts.
- Dependency rationale, profile/ownership/rollback and security-review sources
  are in crypto/docs/SHANGMI-COVERAGE.md, Private DTLS client owner work. Pion
  addresses independent-stack evidence absent from the scripted oracle while
  reusing existing Go tooling, with no production SDK ABI/vcpkg/native provider
  dependency. Upstream signature-confusion/session-caching fixes were reviewed;
  v3.1.15 follows patched v3.1.13/14. Root THIRD_PARTY_NOTICES.md records precise
  MIT/BSD provenance for runtime test-module dependencies; no vendored copies
  or upstream local modifications. Go restore used `go mod tidy`, tests enforce
  `-mod=readonly -count=1`. No separate validation build was created.
- Validation: full native-release-user graph built and `ctest --preset
  native-release-user -R "dtls_" --output-on-failure` passed 4/4 (1.82s,
  PYTHONOPTIMIZE=1, TEMP/salts-219-dtls-client-final.log). Current TinyTest
  handshake suite: 24 cases / 1274 assertions; record suite: 7 / 138. Python:
  11 test methods with negative subcases; Pion: 4 subcases. Configure/build of
  the source GLOB/source_group change also passed through the same user preset
  (TEMP/salts-219-dtls-client-graph.log). No source changed after the final run.
  Shared PRF/provider sources did not change; the earlier 66/66 shared regression
  remains valid and was not repeated for ceremony. Only Windows x64 Release
  ran; no sanitizer/macOS/Linux/Android runtime claims.
- Next: a Core DTLS SERVER and mTLS/credential/policy composition, required
  exporter/transport semantics, then actual NativeIO/CNet/SCTP ownership/drain
  integration and expanded independent qualification. Fixed-profile private
  client success is not production DTLS or completion of #188/#219. General
  PKIX path discovery/policies/cross-signing, TLS1.2/TLCP resumption and other
  previously listed software work remain open. Hardware stays deferred and
  hot reload excluded. Do not push this incomplete overall pass early.

## Private DTLS server and required client authentication (2026-11-08)

- Continue the same local-only completion pass. No commit/push/PR/issue change.
  Provider #44 overlay, provider port/version files and Core's pending #43 pins
  are unchanged this turn. Production still uses GmSSL only; the existing pinned
  Pion v3.1.15 test module is reused without upstream patches or new dependencies.
- Added crypto_dtls_server.{h,c}: immutable listener context plus one exclusive
  progress owner per admitted stream. Context startup reuses
  crypto_tls_memory_validate/identity/trust, including DER/PEM, encrypted PKCS8
  and credential objects, rather than copying credential decoding. Native key
  binding and supported RSA/P256 identity/certificate signatures must succeed
  before publication. Context owns the signing key, chain, cookie key, optional
  client roots/policy, SNI and ALPN; input/password/object pointers do not survive
  init. Shared native signing copies immutable key state into local sign state.
- Context lifecycle/admission is exclusive; atomic stream leases support other
  stream owners draining concurrently. Clear returns BUSY while any lease lives;
  final quiescent stream clear releases its lease, then context clear erases
  keys/cookie and releases its single policy reference. Private C test fixtures
  include this atomic counter, so MSVC targets get the same actual-required
  /experimental:c11atomics admission as the Crypto implementation. MSVC was not
  executed; current evidence remains LLVM-MinGW Windows x64 Release.
- Stateless cookie gate precedes stream storage admission; server_accept checks
  the proof again and takes no lease/generates no ephemeral on invalid MAC,
  address mismatch or expiry. Valid proof initializes the canonical ClientHello
  transcript, fresh random/ECDH, bounded server flights and expected sequences.
  At most five <=4114-byte bodies, eight message slots and one 1200-byte pending
  wire live per stream. Certificate bodies fragment under MTU with original
  handshake seq; every sent/retransmitted record reserves a fresh record seq.
- Required mTLS sends CertificateRequest for P256/RSA SHA256 proofs and verifies
  client path/time/usage, CertificateVerify over the complete canonical DTLS
  transcript, then client Finished and current certificate admission again.
  EMS snapshot is through ClientKeyExchange, before CertificateVerify. A valid
  encrypted Finished may wait behind a reordered CertificateVerify and CCS;
  no policy/data/READY bypass occurs. Before ECDH keys exist, future-epoch records
  are discarded and ordinary peer-flight retransmission recovers them.
- Context peer policy reuses the existing STANDARD / remote-CLIENT contract,
  is retained once per context, and checks once per verified handshake. Local
  server READY waits for actual server Finished send terminal. The master and
  ephemeral private scalar are erased; cached final client/server proof bytes
  permit last-flight responses throughout the active association without PSKs
  or master recomputation. Repeated authenticated client Finished reseals the
  saved server flight and does not rerun policy. Pending wire survives abort;
  neither stream nor context storage can clear until its actual terminal.
- Extracted common DNS validation, strict bounded chain views and outer record
  framing into crypto_dtls_wire.{h,c}; both roles use those same facts. Role
  sequence/proof state, server fragmentation and last-flight ownership remain
  in their explicit owners. No fake client role/key swapping or generic engine
  registry was introduced. Existing source GLOB/source_group collects internals.
- Important interop finding: Pion v3.1.15 ServerName.Unmarshal requires a
  nonempty name list even inside ServerHello, so a standards-valid empty SNI
  acknowledgment is silently dropped and the peer keeps resending ClientHello.
  First attempts therefore timed out in native KEY phase; header-only test
  diagnostics plus reading the pinned parser established the cause. RFC6066
  requires that acknowledgment when SNI guides identity/security policy;
  do NOT treat it as freely optional or suppress configured SNI checks to make
  an interop test pass. The temporary omission was corrected before delivery.
- Server configuration now explicitly permits NULL/0 name for one fixed identity
  without SNI routing/admission, or a configured name requiring exact matching
  SNI plus the proper empty acknowledgment. There is no peer detection, fallback
  or policy retry. Pion tests explicitly select fixed identity; Pion still
  verifies server chain/root/DNS certificate identity. Independent Python client
  tests strict SNI, actual ECDHE signatures and the ENTIRE EMS/Finished transcript
  for RSA/ECDSA, wrong-name rejection, bad authenticated Finished versus bad tag,
  final resealing, READY gating and abort during pending encrypted Finished.
- The test peer initially hid per-subcase failures until a 90-second Go timeout.
  Formal Go test now uses -failfast/-v, and the UDP adapter observes early peer
  handshake errors immediately. Transport traces contain only plaintext record
  headers/phase/verification status, with no key log or credential dump. All
  application traffic is fixed fixture data; unexpected-payload diagnostics
  report only byte count. Logging-guide review: no new production logs.
- Go server suite has 25 subcases: 16 positive combinations of RSA/ECDSA server,
  no client cert or P256/RSA mTLS (plus explicit CertificateVerify/Finished
  record reordering), and loss/no loss of the first server Finished; 9 rejects
  cover missing/untrusted/wrong-purpose client, corrupted CertificateVerify,
  wrong proof scheme, policy refusal, missing EMS, ALPN and group mismatch.
  A legitimate noncritical 1024-byte certificate padding extension forces real
  native certificate fragmentation; Pion uses MTU 512. Positive cases preserve
  negotiated handshake message bytes; reordering only repackages records.
  Negative proof mutations are explicit.
- TinyTest server cases cover address proof before leases, two shared-context
  leases with fresh randoms, BUSY clear, pending-wire/abort/drain lifetime,
  mismatched key rejection and policy reference balance. Existing formal Python
  fixture also supplies PKCS8 keys for these C tests; they remain module-owned.
  dtls_server_endpoint is the formal pipe adapter, not a validation consumer.
- Final full native-release-user graph built; `ctest --preset native-release-user
  -R "dtls_" --output-on-failure` passed 6/6 in 4.92s, PYTHONOPTIMIZE=1
  (TEMP/salts-219-dtls-server-final.log). TinyTest: handshake 28/1421 assertions,
  record 7/138; Python client 11 methods, strict server 4 methods; Pion client
  owner 4 subcases, server owner 25. Only comments/docs and unexpected-payload
  test diagnostics changed after this run.
  After diagnostic cleanup, formal dtls_server_pion CTest passed again (1/1,
  2.85s; TEMP/salts-219-dtls-server-log-check.log). Both worktrees passed
  git diff --check; existing line-ending conversion warnings remain.
  Shared native provider/TLS paths are unchanged; earlier 66/66 broader evidence
  is not relabeled as a rerun. No sanitizer/other OS/runtime-device claims.
- Design, source/protocol links and SNI policy/qualification limits are in
  crypto/docs/SHANGMI-COVERAGE.md, Private DTLS server owner contract. No public
  DTLS API is exposed and #188/#219 remain incomplete. Next: native CLIENT
  CertificateRequest/credential selection and CertificateVerify, exporter and
  transport semantics, actual NativeIO/CNet/SCTP retained I/O/drain integration,
  fatal-alert generation and broader PKIX/DTLS qualification. General PKIX path/
  policy/cross-signing, TLS1.2/TLCP resumption and previously listed software gaps
  are still open. Hardware remains user-deferred; hot update excluded. Do not
  publish the overall incomplete pass early; user root worktree stays untouched.

## Private DTLS client certificate authentication (2026-11-08)

- Continue the authorized local-only #219 pass; no commit/push, PR or issue
  changes. User root worktree and provider #44 overlay remain untouched. No new
  dependencies or production provider; existing GmSSL signing/import and existing
  Pion v3.1.15 formal test module only.
- crypto_dtls_client_config now optionally borrows one crypto_tls_credentials at
  initialization. The existing memory importer validates binding and owns an
  independent RSA/P256 key/chain, including credential-object inputs. Config,
  bytes/password/object storage may be erased/released after init. Invalid raw
  descriptors, aliases, key mismatch and unsupported identity fail before peer
  policy retain or ClientHello. No public API was introduced.
- Client accepts CertificateRequest once between ServerKeyExchange and Done.
  It validates the complete types/signatures/CA-name encoding, checks every DER
  RDN even after a matching name, and selects by signing type, proof scheme,
  every chain signature, and optional root/intermediate issuer hint. Names are
  hints, never trust. Native DER-name comparison is intentionally retained; this
  is not general X.501 name normalization/path discovery. No suitable identity
  sends the RFC-required empty Certificate without CertificateVerify; acceptance
  is the remote optional-auth server's explicit choice. No request sends no cert.
- The final flight now owns up to five messages, each bounded by the 4114-byte
  encoded Certificate body (4096 DER + 5*3 + 3). next fragments at wire MTU1200,
  with a single stable pending wire until actual sent. Actual whole-flight
  terminals arm retry; each retry uses new record sequences and cached identical
  logical proof. All previous BUSY/input/abort/drain contracts are retained.
- EMS hashes through ClientKeyExchange including the optional Certificate.
  CertificateVerify signs that canonical SHA256 digest using native ECDSA or
  RSA-PKCS1, then client Finished hashes through CertificateVerify. Actual Done
  sequence determines the shifted server Finished sequence; HVR bounds reserve
  enough sequence space. Imported identity/key is erased once the final flight
  is constructed, or on failure/abort/clear. Retransmission never signs again.
- Formal independent Python oracle verifies certificate bytes, both signature
  kinds, EMS and Finished without native PRF/key outputs. Added raw/object inputs,
  request/type/scheme/chain-signature/CA matching, root/intermediate hints,
  malformed names including invalid RDN after an earlier match, duplicate
  requests, no-request privacy, no credential, reordered server flight,
  retransmission and abort during pending Certificate. 19 test methods total.
- Pion client suite now has 12 combinations: RSA/ECDSA server, no identity or
  P256/RSA client, with/without first client Finished loss. mTLS cases require
  actual chain/purpose/proof verification by Pion. A legitimate noncritical
  padding extension forces native client certificate fragmentation. Fixed data
  and authenticated close still pass; wire loss is after actual local send.
- TinyTest adds independent credential import/borrow lifetime and failed-init
  cases. Important fixture correction: GmSSL EC key storage is the actual
  secp256r1 private scalar; X509_KEY.has_private_key is used by its RSA path,
  so that field was an invalid EC test expectation. The test now checks scalar
  presence, independent imported certificate bytes, and whole identity erasure.
  Earlier compile-time pointer comparison assertion was also corrected to C
  pointer inequality; no production workaround was added for either test bug.
- Full native-release-user graph built successfully. Initial formal `ctest
  --preset native-release-user -R "dtls_" --output-on-failure` passed 6/6 in
  6.40s (TEMP/salts-219-client-mtls-test.log). Subsequent stricter RDN validation
  passed client Python/Pion; the only failed test was the EC flag expectation
  above (TEMP/salts-219-client-mtls-final.log). After correcting that fixture,
  final handshake CTest passed 1/1 in 0.23s, 30 TinyTest cases/1466 assertions
  (TEMP/salts-219-client-mtls-lifetime.log). Final expanded request/reordering
  oracle passed 1/1 in 0.94s, 19 Python methods
  (TEMP/salts-219-client-mtls-requests.log). No behavior changes after these runs;
  unchanged passing scopes were not repeated for ceremony. PYTHONOPTIMIZE=1 in
  all Python runs; Windows x64 LLVM-MinGW Release, no sanitizer/other OS claims.
- CodeGraph sync succeeded (TEMP/salts-219-client-mtls-codegraph.log); index is
  ignored and remains local. git diff --check passed with existing line-ending
  conversion warnings. Contract/protocol references are in
  crypto/docs/SHANGMI-COVERAGE.md, Private DTLS client certificate authentication.
- #188/#219 remain incomplete: exporter, fatal alerts, general negotiation and
  credential lists, actual NativeIO/CNet/SCTP lifetime/transport integration,
  broader PKIX/platform qualification and the previously recorded ticket/PKIX
  gaps remain. Hardware stays deferred; hot reload excluded. Do not publish
  this overall software pass until complete.

## Private DTLS RFC5705 exporter (2026-11-08)

- Same local-only #219 completion pass. No commit/push/PR/issue action; user root
  worktree and provider #44 overlay untouched. Reused GmSSL SHA256 TLS PRF and
  the existing Python/Pion formal peers; no dependency or public DTLS API added.
- Private client config and listener config gain enable_exporter, default false.
  Owner export succeeds only in authenticated READY, outside callbacks. Server
  READY still waits for its final Finished's actual send terminal; peer policy,
  Finished and CCS gates remain mandatory. Export during a pending application
  or final-flight retransmission is read-only and preserves the pending wire.
- HIGH lifetime tradeoff documented in SHANGMI-COVERAGE.md: arbitrary post-READY
  labels/context need the original master. Explicit opt-in retains that same
  owned 48-byte EMS master, not a second copy. Default admission still erases it.
  Accepted local/remote close erases it immediately, before close_notify send
  terminal; abort/failure/clear also erase it. Traffic epochs remain until their
  actual terminal. New master_live records availability independently of epochs;
  use after forgetting returns ESTATE without damaging traffic keys.
- Rejected alternatives: unconditional retention changes default secret lifetime;
  preconfigured cached label outputs cannot serve later application context.
  No global cache, session persistence, automatic retry or alternate PRF. Disable
  the private option to recover default erasure behavior. Full rationale/ownership
  and protocol links are in Private DTLS exporter and master retention.
- RFC5705 derivation uses master, label, client_random then server_random;
  optional context adds uint16 length and exact bytes. Absent and present empty
  context are distinct. Limits: 1..255 printable ASCII label bytes, context
  0..1024 bytes and output 1..1024 bytes. Handshake labels, prefix/extension
  collisions (including extended master secret), embedded NUL and invalid sizes
  fail. Application must agree on registered/private EXPERIMENTAL label purpose;
  this does not implement SRTP/SCTP or validate every registry collision.
- Invalid state/arguments/aliases leave output unchanged. Admitted native PRF
  failure propagates ECRYPTO and zero output, covered by existing native PRF
  stage-failure tests. External requests/output cannot alias owner/listener
  storage; helper rejects secret/random/input/output aliases. No retained input
  pointers or exporter logs. Caller owns/erases exported bytes; formal pipe
  adapters zero delivered material and their whole state on error cleanup.
- Python peers independently compare both endpoint roles across absent/empty/
  binary/maximal context, output boundaries/multiple PRF blocks, invalid labels,
  before READY/default-off/close/failure rejection, pending send and post-retry
  stability. Client has 20 test methods; strict server 5. Server abort/forged
  Finished cases run with exporter enabled so erasure is observed as well.
- Go/Pion existing 12 client and 25 server subcases are retained. Loss cases
  enable native exporter; no-loss cases verify default-off refusal. Successful
  peers compare 65-byte no-context exports in both native roles, including mTLS,
  and require master erasure on close admission. Pion v3.1.15's State exporter
  rejects nonempty context and conflates empty/absent; no upstream changes or
  wire rewrite. Context semantics are independently covered by Python.
- Full native-release-user graph built. Initial dtls_ CTest passed 6/6 in 7.23s
  (TEMP/salts-219-exporter-test.log). After master-use guard and adapter cleanup
  refinements, final affected CTest filter dtls_(handshake|client_|server_) passed
  5/5 in 6.36s (TEMP/salts-219-exporter-final.log), PYTHONOPTIMIZE=1. TinyTest
  handshake: 33 cases/1616 assertions. Unchanged record test's earlier pass is
  not relabeled a rerun. No sanitizer or other OS qualification; current runtime
  remains LLVM-MinGW Windows x64 Release. git diff --check passed with existing
  line-ending warnings.
  CodeGraph sync completed (TEMP/salts-219-exporter-codegraph-final.log,
  5908 nodes, 35.7s); its ignored index remains local.
- #188/#219 remain incomplete: fatal-alert delivery, general negotiation and
  identity lists, actual NativeIO/CNet/SCTP retained I/O/transport integration,
  broad PKIX/platform coverage and prior software gaps. Hardware stays deferred,
  hot reload excluded. Do not push the overall incomplete pass early.

## Private DTLS fatal alerts and error-output drain (2026-11-08)

- Continue the local-only #219 pass. No commit/push/PR/issue action. User root
  worktree and GmSSL #44 overlay untouched; no new production dependency/provider
  or public API. Existing formal module-owned C/Python/Pion tests only.
- Added a bounded crypto_dtls_fatal snapshot in each private owner: at most
  39 sealed wire bytes, size, local/peer description and secondary alert error.
  Protocol reject prepares it BEFORE clearing both traffic epochs/master,
  ephemeral key, transcript, scratch and logical flights. The primary failure
  remains immutable. A failed seal/nonce admission records its own error and
  exposes no alert; never substitutes plaintext after epoch-one activation.
- Current local write epoch advances only after successful actual CCS send
  terminal. Derived keys alone do not activate it: server rejecting encrypted
  client Finished before sending server CCS emits plaintext epoch zero; client
  rejecting server Finished/policy after local CCS emits encrypted epoch one.
  Cookie gate still precedes server lease/admission; no fatal is generated for
  unverified server addresses or before the client has an admitted cookie.
- Added pure crypto_dtls_finished_check. Owners reject/prepare/erase immediately
  on error, without consuming keys before fatal sealing. Existing destructive
  crypto_dtls_finished_verify delegates to it and retains its erasure contract.
  Synthetic tests compare pure/destructive checks, not handshake qualification.
- FAILED may still publish exactly one fatal through next. Its immutable wire
  obeys the same native borrow/BUSY/actual-sent terminal protocol. sent preserves
  the original failure, including actual send failure; alert error records that
  secondary failure. No automatic retry/timer, READY or session resurrection.
  Abort drops unprepared alert output but preserves pending bytes until terminal;
  clear can discard unprepared output, never reclaim a native borrow early.
- Local abort/I/O/clock failure does not initiate an alert. Received well-formed
  peer fatal stores its description and fails without echo. After peer CCS or
  authenticated epoch-one traffic, epoch-zero alerts are discarded. Bad tags,
  replay/wrong epoch and invalid outer framing remain discard outcomes; this
  change does not turn unauthenticated corrupt records into fatal alert oracles.
- Finite descriptions cover handshake/decode/certificate/proof/policy/callback
  failures; authenticated incorrect repeated client Finished after server READY
  also uses decrypt_error. Full per-X509-error taxonomy remains outside this
  finite profile. Context leases/policy references still drain at stream clear.
- Python peers verify epoch-zero and decrypt epoch-one alerts, correct local
  direction, proof/policy rejection, keys erased BEFORE alert output, pending
  abort/clear, original failure on failed sends, no retransmission, peer fatal
  without echo, bad-tag/replay and late-plaintext resistance. Client now has 23
  methods; strict server 7. A Q opcode reports bounded alert metadata for these
  formal pipe tests only. It is not a public protocol/config/API.
- TinyTest adds fatal framing/nonce reservation, exhaustion without plaintext
  fallback, actual owner failure preservation and borrow/abort/drain cases.
  Final handshake suite is 36 cases/1686 assertions. The synthetic overflow
  fixture is explicitly not a network handshake. Independent Python supplies
  the separate cryptographic wire proof.
- Pion has 16 client subcases (12 successes plus 4 native peer-policy rejects)
  and 25 server subcases (16 successes plus 9 rejects). Negative server tests now
  actually deliver the native fatal and await a peer alert error BEFORE any
  cancellation/socket close. Client policy failures deliver encrypted fatal.
  Initial new client test correctly failed because Pion reports post-handshake
  fatal to Read as EOF, not its private alertError. Reading pinned conn.go showed
  that its decoder logs the alert classification before closing the read queue.
  Test-only fatalObserver uses the existing logger interface, observes ONLY
  decoded AccessDenied into one atomic boolean, discards all other log output,
  and requires that observation for EOF to qualify. No upstream patch, wire
  rewrite, acceptance of bare EOF or packet/key logging. The already pinned
  pion/logging v0.2.4 import is now direct; versions/checksums/licenses unchanged.
- Full native-release-user graph built. Initial dtls_ CTest passed 6/6 in 7.17s
  (TEMP/salts-219-fatal-test.log). Expanded Pion run exposed the EOF distinction;
  server passed while client failed (TEMP/salts-219-fatal-pion.log). After fixing
  the test observation, client Pion passed 1/1 in 2.70s
  (TEMP/salts-219-fatal-pion-client-final.log). Added nonce exhaustion owner case
  passed handshake CTest 1/1 in 0.34s (TEMP/salts-219-fatal-nonce.log). Final
  server proof-description refinement passed affected Python/Pion CTests 2/2 in
  3.61s (TEMP/salts-219-fatal-server-final.log). Unchanged successful scopes were
  not repeated for ceremony; do not relabel prior logs as a new matrix run.
  PYTHONOPTIMIZE=1; LLVM-MinGW Windows x64 Release. No sanitizer/other OS claims.
  CodeGraph sync completed (TEMP/salts-219-fatal-codegraph-final.log, 641 nodes,
  13.3s). git diff --check passed with existing line-ending warnings; index stays
  ignored and local.
- Contract, architecture tradeoffs and RFC links are in SHANGMI-COVERAGE.md,
  Private DTLS fatal alert delivery. One-shot terminal shutdown intentionally
  erases keys rather than retaining a failed association to generate additional
  alerts for later repeats. Actual NativeIO/CNet host integration must honor this
  error-output drain; this is not evidence of transport integration yet.
- #188/#219 remain incomplete: general negotiation/identity policies, actual
  NativeIO/CNet/SCTP integration, broader PKIX/platform qualification, and prior
  software gaps. Hardware deferred, hot reload excluded. Keep this overall pass
  local until all authorized software work is finished.

## Opaque DTLS client and real CNet/NativeIO composition (2026-11-08)

- Continue in feat/crypto-219-completion, local only, no commit/push/PR/issue
  actions. User root worktree and unpublished provider #44 overlay unchanged.
  This is one implemented client slice, not completion of all #188/#219.
- New public crypto/dtls_stream.h is an opaque, fully backed finite client:
  mandatory DTLS1.2 cookie/EMS, P256 ECDHE, AES128-GCM, RSA/ECDSA SHA256,
  explicit trust/DNS, optional single ALPN/client identity/policy and exporter.
  No provider types, server placeholder, resumption or new dependency. Private
  client/server structures remain private. Config/credential byte borrows end
  at create; policy retains until quiescent destroy. Destroy guards recursive
  invocation from policy.release after the private client has been cleared;
  TinyTest exercises this callback and independent imported-root storage.
- New cnet/dtls.h borrows an existing bound datagram/fixed peer. CNet depends
  only on public Crypto/datagram APIs; Crypto does not depend on NativeIO.
  Host owns receive credits, observation and whole-batch routing. No worker,
  alternate backend, observer replacement or cancellation of shared sockets.
  At init allocate 1..64 full-wire input slots; copy receive views and <=1163
  application bytes. Input ENOBUFS consumes nothing and requires host lifetime
  handling. Production wiping reuses existing CNet crypto_wipe, with GmSSL
  still implementing all DTLS cryptography. No duplicate production erase loop.
- Prepared wire remains immutable through real local send completion. Native
  send ENOBUFS proves nonadmission and retains it for later capacity; accepted
  output is never resubmitted. Domain high32/sequence low32 tags do not wrap and
  must be reserved against every sender on the shared datagram. Actual datagram
  request/generation matching stays in its existing owner. Unknown tags do not
  match; duplicate terminal is rejected before settlement.
- Application tag is pending at admission, even before wire preparation. One
  callback reports local terminal, not peer receipt. Abort before submission
  reports cancellation; after submission waits/reports the actual native result.
  Aborting never cancels/stops a shared datagram/backend. First bridge errors
  immediately reject admission instead of appearing as retryable BUSY while
  fatal output drains. Concrete negative application callback status survives
  alongside Crypto's failure diagnostics. Host retires protocol input after
  abort/failure but still routes all actual send terminals and whole batches.
- Module-owned formal CNet test uses only public APIs and actual UDP NativeIO,
  with independent Pion v3.1.15 server in the existing Go test module. Same exact
  Pion/logging/dependency versions/licenses already qualified in Crypto; no new
  production provider or upstream patches. Added readonly go.sum, C++17 header
  and linked-symbol test. Sources use CONFIGURE_DEPENDS GLOB/source_group and
  existing single CNet owner, including original/static-owner variants.
- Seventeen native scenarios: fourteen ordinary/external interop cases cover
  RSA/ECDSA, mTLS, policy/callback failures with decoded fatal49/80 (EOF alone
  cannot pass), max/oversize/empty messages, exporter agreement, foreign source,
  abort before/after native application submission and actual tagged terminals.
  Three handshake abort cases distinguish capacity-proven nonadmission from
  actual pending output. External backend has three requests/two endpoints;
  neighboring UDP progresses during failure and after bridge destruction.
  Owned ingress probe copies invalid input, mutates source to a fatal and checks
  full-ring rejection cannot overwrite it; the real handshake must still pass.
  Callback mutation reentry, policy references and whole-batch error routing
  are checked without synthetic successful send completions.
- Fixture bring-up exposed real contract mistakes: completion batch capacity
  exceeded the backend's three-request bound; changed the declared batch to
  three. Ordinary observe ETIMEDOUT means no events, not protocol failure; kept
  that documented outcome while propagating real errors. External backend must
  close before destroy after endpoint/request drain; fixed cleanup ordering.
  No toolchain/dependency fallback or skipped tests was introduced.
- Full native-release-user graph built. Related CTest filter
  dtls_|crypto.algorithms.cpp17_header|saltscore.cnet_owner_original passed
  10/10 in 13.56s (TEMP/salts-219-dtls-native-regression.log), covering Crypto's
  six DTLS tests, public header and existing CNet owner regressions. Expanded
  seventeen-scenario native test passed 1/1 in 1.69s
  (TEMP/salts-219-dtls-native-tag-drain.log). After the final pending/error guard
  changes, full graph + cnet_dtls_ passed 2/2 in 1.67s
  (TEMP/salts-219-dtls-native-failfast.log). Earlier passing scopes were not
  relabeled as reruns. All through formal CTest; no standalone validation project.
  Final public create-contract review also fixed NULL config to clear a valid
  output slot, matching the documented failure publication; existing opaque
  TinyTest now checks it from a non-NULL sentinel. Full graph + handshake and
  cnet_dtls_ CTests passed 3/3 in 1.86s
  (TEMP/salts-219-dtls-native-create-final.log).
  Final git diff --check passed (existing LF/CRLF warnings only). CodeGraph sync
  completed in 8.7s (TEMP/salts-219-dtls-native-codegraph-final.log); no index
  files appear in git status and no local analysis artifacts are staged.
  Runtime is Windows x64 LLVM-MinGW Release, PYTHONOPTIMIZE=1; no sanitizer,
  Linux/macOS or Android device claims. Stale skill references cnet/README.md,
  native-io/ARCHITECTURE.md and cmake/CmakeUtils.cmake are absent in this checkout;
  actual public headers, sources, formal tests and existing architecture docs
  supplied the contracts instead. This is analysis-source handling, not a
  substitute for missing build dependencies.
- Architecture tradeoffs/rollback and exact owner/capacity/error contracts are
  in docs/CNET-POLICY-HIERARCHY.md and crypto/docs/SHANGMI-COVERAGE.md. Remaining:
  public server/listener and real server NativeIO admission, SCTP, general
  negotiation/identity policies, broader PKIX/platform/sanitizer qualification
  and prior software gaps. Hardware remains deferred, hot reload excluded.
  Do not push this overall incomplete pass early.

## Opaque DTLS server and real NativeIO admission (2026-11-08)

- Continue the same local feat/crypto-219-completion worktree. No commit/push,
  PR/issue action, CI wait, provider-overlay change or root-worktree edit.
  GmSSL remains the production DTLS provider; no new dependency/version.
- Extended crypto/dtls_stream.h with an opaque immutable listener and finite
  server admission. Existing stream operations dispatch internally by role,
  preserving private GmSSL/owner layouts. Config/credential byte borrows end at
  create; optional required-mTLS policy retains once per listener. Cookie expiry
  is explicit 1..60000 ms. Lifecycle create/admit/destroy is exclusive; separate
  admitted owners may progress independently. Listener clear rejects live leases
  and recursive destruction from policy release. No server placeholder/versioned
  interface, peer table, background worker or hot reload was introduced.
- Public allocation-free gate copies no peer state, issues at most 60-byte HVR
  no larger than input, and maps malformed packets to DROP/no reply. Outputs
  and listener storage cannot alias inputs or each other. Valid cookies prove
  return routability only. Accept rechecks proof BEFORE allocating its stream
  or acquiring the shared listener lease. Wrong proof publishes no owner.
  Post-cookie negotiation rejection may publish an already FAILED owner: OK
  means ownership admission, never authentication. Its get_info error is visible
  immediately, and next/sent retains the fatal/actual-terminal drain contract.
- CNet uses the public listener gate with canonical family/address/port/IPv6
  scope bytes, independent of sockaddr padding and host byte order. New accept
  rechecks proof before bridge allocation and uses the same bounded ring,
  application tags and native output settlement as client. Invalid proof is
  EPROTO with unchanged zero owner. Host owns bounded peer table, duplicate
  association admission, rate/capacity limits, cookie reply reservation/terminal,
  receive credits and whole-batch routing. Raw sockets/backends stay borrowed.
  No NativeIO dependency moved into Crypto.
- A post-cookie FAILED stream can be admitted during observe. The next normal
  advance latches its first Crypto error BEFORE submitting a fatal; no redundant
  post-route advance. All new application admission then refuses the permanent
  error, while output and neighboring completions still drain. Both roles use
  identical send/close/export/abort/destroy contracts. Keys erase on failure;
  retained sealed wire still waits for actual completion.
- Build caught direct listener calls from CNet consumers being unavailable from
  the CNet import library: the static Crypto member is private to that DSO.
  Corrected the owner boundary with cnet_dtls_listener_create/destroy forwarding
  through its sole existing Crypto instance, returning Salts statuses. Did NOT
  link another static Crypto into the tests/consumer or export private provider
  structs. Existing physical-owner and negative owner audits passed afterward.
- First native server handshake stalled on strict SNI. Existing coverage docs
  and pinned Pion source confirm v3.1.15 drops a valid empty ServerHello SNI ACK.
  Positive Pion fixtures now EXPLICITLY configure fixed identity; they still
  verify CA/DNS/key-exchange proof. Strict mismatch is a separate native reject;
  unchanged independent Python tests verify full strict-positive SNI wire.
  No production policy fallback, peer detection, wire rewriting or upstream
  patch. RSA fixture also needed its generated CA added to identity.roots for
  its new client-verifier role; previously it supplied only CA file/server key.
  The test preserves mandatory verification rather than bypassing trust.
- Extended the existing public-only native CNet fixture/Go module. One bounded
  host cookie reservation and peer slot; actual cookie sends use raw tag5 and
  accepted owners use domain7. Every cookie-less/malformed receive also checks
  accept refuses without publishing state. The host pauses/reposts receive
  demand around actual cookie terminal. Shared backend remains three requests,
  two endpoints; no second observer. Existing CTest registration covers it.
- 24 server scenarios (12 ordinary + 12 external): ECDSA/RSA, mTLS, missing and
  untrusted client identity, policy, strict SNI mismatch, ALPN/EMS rejection,
  callback encrypted fatal, abort before/after native application submission.
  Positive paths cover max/oversize/empty messages, exporter agreement, exact
  local tags and authenticated close. Malformed actual UDP before cookie
  exchange yields no state/reply. Every scenario requires a real cookie send
  terminal, BUSY listener destroy with a stream, and correct final policy release.
  Shared IOCP neighbor survives failure and complete listener teardown. Export
  comparisons wipe both native response and independent exported byte arrays.
  Combined with unchanged 17 client cases: 41 actual NativeIO scenarios.
- Added formal opaque-listener TinyTest: invalid config before policy retain,
  malformed/aliased gate, wrong-address proof, two live context leases, BUSY
  listener clear, pending wire stable through abort, real terminal before destroy,
  and recursive listener policy release. C++17 links new CNet listener entry.
  No independent consumer/smoke validation or new feature switch.
- Complete native-release-user graph built. Initial public handshake/C++ tests
  passed while the new native test correctly exposed the fixture problems above.
  After fixes, full graph and affected/adjacent filter
  dtls_|crypto.algorithms.cpp17_header|saltscore.cnet_native_crypto_owner|saltscore.cnet_owner_original
  passed 13/13 in 14.75s (TEMP/salts-219-dtls-server-native-regression.log).
  Added malformed real-UDP negative passed native CTest 1/1 in 2.92s
  (TEMP/salts-219-dtls-server-native-framing.log). Final unverified-accept check
  and full graph/native CTest passed 1/1 in 2.69s
  (TEMP/salts-219-dtls-server-native-admission-final.log). All executable tests ran
  through CTest/preset, PYTHONOPTIMIZE=1, LLVM-MinGW Windows x64 Release.
  No other OS, IPv6 runtime or sanitizer claim. Final git diff --check passed
  with existing LF/CRLF warnings. CodeGraph final sync succeeded in 25.7s
  (TEMP/salts-219-dtls-server-native-codegraph-final.log); no index files appear
  in git status. Stale skill paths from the prior handoff
  remain absent; actual headers/sources/formal callers are the contract source.
- Architecture, error/ownership/admission, single-provider linking, rollback and
  scope are synchronized in docs/CNET-POLICY-HIERARCHY.md, Crypto README and
  SHANGMI-COVERAGE.md. Remaining #188/#219 work includes SCTP, general negotiation/
  identity policies, broader PKIX, concurrent multi-peer native load and wider
  platform/sanitizer evidence, plus prior software gaps. Hardware is deferred.
  Keep the overall pass local until the authorized software scope is finished.

## 2026-11-09 — #219 SCTP, supplied-chain PKIX and concurrent native load

- Continued the authorized local one-shot pass in
  `C:/projects/cpp/turbonet/.worktrees/salts-core-cnet-policies`, branch
  `feat/crypto-219-completion`, base `260097031e83c73138e6f23a0ec8f95bce9d7c16`.
  Existing uncommitted completion work remains intact. No commit/push, PR/issue
  update or macOS-runner wait. The unrelated dirty root housekeeping worktree
  was not modified. The unpublished GmSSL 3.2.0#44 overlay is unchanged in this
  step; manifest publication remains coordinated with that provider revision.
- Added `<cnet/sctp_dtls.h>` and `Salts::SCTPDTLS`: SCTP owns the bounded bridge,
  borrows Session/CNet DTLS, copies 1..64 inputs and reserves one 1163-byte output
  before Session transactions. Host reserve/commit preserves existing Session
  poll/receipt semantics. No second engine, observer/backend or static Crypto
  owner; pure `Salts::SCTP` stays independent. Immutable CNet binding and
  sequence exhaustion checks prevent old Session traffic after DTLS replacement.
  Abort discards only unsubmitted work and waits for real admitted terminals.
  Session exposes unversioned readonly binding/data-ready queries; no ABI version
  bump or parallel API. Query tests cover NULL, Owner and stopped states.
- Real load first exposed premature Session poll/pump before SCTP DATA readiness;
  fixed the explicit readiness gate instead of treating CLOSED as EMPTY. Then
  a full upper ring became fatal80: fixed authenticated application backpressure.
  Only CNet ENOBUFS/Crypto BUSY is non-consuming. Opaque Crypto owns one 16384-byte
  plaintext slot plus a 16421-byte encrypted tail, rejects new raw input until
  drained, retries delivery without AEAD/replay reconsumption and keeps output
  separate. `pending_receive` exposes it; failure/abort erases retained bytes.
  Deferred terminal rejection seals fatal80 and preserves concrete CNet error.
  Output descriptor validation precedes callbacks; mutation reentry is refused.
  This is bounded protocol flow control, not an automatic recovery/fallback.
- Added exporter-bound GmSSL HMAC through Crypto/CNet's same physical owner.
  Review caught that ordinary exporters are shared with the peer and cannot by
  themselves authenticate a server-only SCTP cookie. Before delivery, changed
  the formal provider to an OS-random private 32-byte per-association exporter
  context, never transmitted/logged and erased at cleanup. Independent Pion
  checks ordinary exporter HMAC agreement and private-context MAC separation.
  Opaque TinyTest checks pre-READY, oversize/alias rejection and unchanged output.
- Formal module-owned `saltscore.sctp_dtls_native` uses production CNet/GmSSL
  and existing pinned Pion modules, no new production dependency. Ten scenarios
  cover both native roles, ordinary/external progress, 1/4/8 peers including
  eight healthy peers and mixed authentication failure/cancel. Across 44 real
  attempts: four untrusted, four canceled after DCEP, 36 healthy peers each with
  four echoed messages and exactly four separate cumulative ACK receipts.
  Payloads: 1/1024/24576 bytes and logical-empty PPID57. One-slot upper ingress
  and two encrypted records coalesced in one actual UDP datagram exercise pressure.
  Wrong binding/Owner, reservation/CAPACITY, wrong/duplicate terminals and stale
  same-wrapper replacement are negatives. A four-request/two-endpoint external
  backend neighbor survives full teardown. Early successful peer close caused
  actual Winsock ICMP10054; fixed worker lifetime through ACK/drain, not ignored.
  These tests establish functional concurrency, not throughput or loss behavior.
- Existing CNet native test now has 113 scenarios: 53 base client/server cases
  (including nonempty/empty backpressure and deferred fatal) plus 60 PKIX cases.
  Fifteen PKIX profiles run in both roles/modes: valid two-intermediate chain,
  wrong-first same-name anchors, expiry/future, path length, non-CA, CA KU/EKU,
  intermediate/root DNS constraints, leaf KU/EKU, unknown critical extension,
  signature corruption and required explicit policy without certificate policy.
  Go independently generates/signs/parses/prechecks fixtures; leaf signing KU
  has its explicit TLS-specific exception to Go Verify. Negatives require actual
  decoded CertificateUnknown, no READY/policy admission and complete fatal drain.
  Initial fixture mistakes (same-name root PublicKey and non-CA MaxPathLen)
  correctly failed and were repaired. Existing GmSSL passed without provider edits.
  This does not implement arbitrary path discovery/AIA/WebPKI or positive policy
  mapping/tree processing. Existing five-cert/4096-byte chain limits remain.
- Preserved this older checkout's existing BUILD_TESTING gate; no new feature
  switch. SCTP tests are registered from its own tests/CMakeLists.txt. An initial
  accidental placement under the Linux DSO guard produced No tests found on
  Windows, caught and corrected before acceptance. No installed-consumer/smoke
  project. Root's unrelated BUILD_TESTS housekeeping migration remains untouched.
- Build environment recovery: process-level tool bootstrap was lost at a turn
  boundary. Root .env alone has stale pkgconf/re2c settings for this isolated
  build. Restore credentials/cache settings internally from root .env, then use
  this build's CMakeCache inputs for Qigao toolchain, chainload, triplets,
  PKG_CONFIG_EXECUTABLE, RE2C_EXECUTABLE root, install prefix and installed-bin
  PATH; derive overlay triplets from the configured shared cache checkout.
  QIGAO_PKGCONF_VERSION is the configured wheel METADATA version (3.0.7.post0),
  not native --version (3.0.7) or root .env pkgconf (2.4.3). Missing triplets and
  stale values failed rather than silently falling back. The temporary wrong
  2.4.3 package identity caused genuine vcpkg ABI misses/rebuilds; restoring tool
  facts made subsequent configure no-work. Shared cache remains enabled; misses
  may build and cache as authorized. No secret values printed or MSYS2 added.
- Validation (Windows x64 LLVM-MinGW Release, native-release-user full graph,
  PYTHONOPTIMIZE=1, all executables through CTest):
  - `TEMP/salts-219-sctp-pkix-multi-final.log`: 31/31 passed, 28.13s, filter
    `dtls_|crypto.algorithms.cpp17_header|saltscore.cnet_native_crypto_owner|saltscore.cnet_owner_original|^cnet_sctp_`.
    Covers Crypto DTLS, C++17, CNet native (then 109 scenarios), SCTP native ten
    scenarios and existing SCTP/single-Crypto-owner/original-owner regressions.
  - Subsequent empty-record backpressure and Session-query edges: full graph
    build, then `^saltscore.cnet_dtls_native$|^cnet_sctp_public_api_test$`, 2/2
    passed in 8.65s, `TEMP/salts-219-sctp-pkix-edge.log` (CNet now 113 scenarios).
  - Both-role SCTP run: 1/1 passed in 5.63s,
    `TEMP/salts-219-sctp-dtls-both-roles.log`.
  Architecture/tradeoffs/migration/rollback and evidence are synchronized in
  CNET-POLICY-HIERARCHY, SCTP/Crypto README, SHANGMI-COVERAGE and NATIVE-TESTING.
  THIRD_PARTY_NOTICES records the pinned test-only dependencies and licenses.
  Final CodeGraph sync succeeded in 35.6s
  (`TEMP/salts-219-sctp-pkix-multi-codegraph-final.log`); index remains ignored.
  Final git diff --check passed with existing LF/CRLF conversion warnings.
- Scope still open: broader negotiation/identity/path-building/policy-tree work,
  full browser/interoperability/platform and sanitizer qualification, prior
  software gaps in the overall pass. IPv4 Windows IOCP only for these new native
  cases; no Linux/macOS/IPv6/device/benchmark claims. SDF/SKF stays deferred.
  Do not close #188/#219 or publish the overall pass from this slice alone.

## 2026-11-09 — explicit push request and immutable dependency registration

- User explicitly requested "push code", superseding the prior local-only
  publication hold. Publish the current completion candidate branches; this
  does not declare all #188/#219 scope complete, merge or create a release.
- Registered GmSSL 3.2.0#44 and its exact port tree
  `29cd5565d2fc85b03b1f555206e4745ca85f55bd` in vcpkg-cache commit
  `3c9cb8cbcc6b3645d47e02585e987b708406cd98`, pushed branch
  `feat/gmssl-219-completion`. Six already-qualified patches cover TLCP
  certificate signature policy, depth positions, client/server TLS sessions,
  anchor constraints and PRF fail-fast erasure. Upstream patch context whitespace
  is preserved; metadata diff check passed, and the real registry build applied
  all patches successfully. No extra validation project or provider rewrite.
- Core registry reference/baseline and CI dependency action now pin that exact
  pushed commit. Added the three new formal Go modules to existing setup-go
  cache inputs; shared vcpkg caches/ccache and build-on-miss behavior remain.
  README/coverage now describe the registered dependency rather than requiring
  unpublished local patches. No credentials or local environment file staged.
- Removed the cached local GmSSL overlay via the existing user preset:
  `cmake --preset native-release-user -DVCPKG_OVERLAY_PORTS=` followed by
  `cmake --build --preset native-release-user`. Registry resolution fetched the
  pushed port tree and rebuilt GmSSL #44 in 14s; full graph build succeeded.
  The active cache has an empty VCPKG_OVERLAY_PORTS. Log:
  `TEMP/salts-219-registry-publish-build.log`.
- With the registered dependency, formal CTest filter
  `crypto|tls|tlcp|sctp|cnet_pkix|cnet_owner_original|gmssl_shangmi` passed
  82/82 in 238.52s (`TEMP/salts-219-registry-publish-tests.log`). The five
  ShangMi cases omitted by that name filter ran once separately with
  `-R shangmi -E "crypto|tls|tlcp|sctp|cnet_pkix|cnet_owner_original|gmssl_shangmi"`,
  passed 5/5 in 21.43s (`TEMP/salts-219-registry-publish-shangmi.log`). Thus
  87 distinct related tests passed against the published port, including
  standard/ShangMi session tickets, PKIX/revocation, TLS/TLCP identities,
  DTLS/SCTP load and sole-Crypto-owner audits. Same Windows Release preset and
  PYTHONOPTIMIZE=1; no repeat of successful cases for the additional filter.
- Staged only the ongoing completion scope in Core's feature worktree; root
  user changes, .env, local build/cache/index artifacts remain untouched.
  Staged diff check passed. Push the feature branch without merge/release;
  cross-platform CI acceptance and outstanding issue scope remain separate.

## 2026-11-09 — authorized merge and vcpkg-cache v0.1.7 release

- User explicitly requested "merge code, relese vcpkg-cache 0.1.7", extending
  the prior push-only instruction. Merge the completion candidate without
  closing unfinished #188/#219 scope. The earlier request not to wait for macOS
  runners remains in force; report pending CI separately from local results.
- Created and merged vcpkg-cache PR #307 with expected head
  `abdf62e0ad1af32cad73f3d7895150953b126af5`; merge commit
  `47e38f1465f95e9211edcbcfd5e3c8e96289a20c`. Published stable source release
  https://github.com/qigao/vcpkg-cache/releases/tag/v0.1.7 at that exact commit.
  Created a new tag atomically; no existing tag/package was overwritten.
  The cache repository has no automatic check runs for this PR.
- Copied all three Lemon 1.0.0 assets from v0.1.6 after local SHA-256 checks,
  then verified v0.1.7's tag, published state, asset sizes and digests against
  v0.1.6. Native dependency ABI packages were not rebuilt/published by release.
  Assets/notes are under TEMP/qigao-vcpkg-cache-v0.1.7-nhocjl8h.
- Core registry reference is v0.1.7; baseline is the exact release commit.
  All five shared setup Actions select v0.1.7. Git diff confirms the GmSSL port,
  Actions, scripts, toolchain and vcpkg identity are unchanged from the previously
  qualified 3c9cb8c candidate. Only release documentation/merge metadata changed.
  Native user-preset configure succeeded using the release registry, vcpkg was
  no-work (853us), and complete graph build was no-work. Log:
  TEMP/salts-219-vcpkg-017-adoption.log. The 87 distinct formal Windows tests
  remain the runtime evidence; unchanged tests were not repeated for ceremony.
  Staged diff check passed. Cross-platform/sanitizer acceptance remains separate
  and must not be inferred from this explicit merge or source release request.

## 2026-11-09 — vcpkg-cache v0.1.1 binary-cache adoption

- Published provider v0.1.1 at `4ac631f89e07cebfd347848af642f31fe8c4edec`:
  148 exact native ABI ZIPs plus `cache-index.json`, for Linux x64/ARM64,
  Windows LLVM-MinGW x64/ARM64 and macOS ARM64. All five native producer jobs
  passed. All 149 native/index uploaded asset sizes and server SHA-256 digests
  matched local artifacts. Lemon assets retain the prior bytes; GmSSL remains
  #44 at port tree `29cd5565d2fc85b03b1f555206e4745ca85f55bd`.
- Core CI now restores its Actions binary/download cache before shared setup,
  uses v0.1.1 Actions/registry, and supplies the real `cnet,media,zstd` features.
  Published exact ABIs restore first; unlisted ABIs compile and populate the
  writable files cache. Authentication, TLS, bad metadata and corrupt archives
  remain fatal. macOS x64/Android target ABIs are not prewarmed by this release.
- Windows reference builds acquire no MSYS2: libpq 16.9#5 has a native CMake
  frontend backend; tree-sitter CLI uses native Python gzip extraction; pkgconf
  uses the verified standalone executable. ZeroMQ 4.3.5#4 fixes its ARM clock
  constant and explicit <new> include. Successful Windows producer logs contain
  no MSYS2 acquisition. This does not qualify libpq database/NLS runtime tests.
- Local adoption used canonical vcpkg scripts
  `04a9d8e5212d01ee1dd9478eadd9caade4f8b0d4` and tool
  `2026-07-27-98d7cb0cf1f4686a3e43aa5672b6230c1d56bce8`, via the ordinary
  shared setup/manifest restore, then `cmake --fresh --preset native-release-user`,
  complete `cmake --build --preset native-release-user --parallel 8` and
  `cmake --build --preset install-native-release-user --parallel 8` under
  VsDevCmd. The 11 local ABIs were unlisted (local toolchain identity differs
  from the hosted producer); ordinary source builds completed and cached them.
- `ctest --preset native-release-user -R
  "^saltscore\.(cnet_tcp_loopback|gmssl_tls_io_abi|gmssl_shangmi_provider)$"`
  passed all 3 cases. CMeta's existing `user-release`/`release`/`install-release`
  presets then built and installed against this SDK; `ctest --preset release
  -R "^salts.native."` passed all 15 formal integration cases. No independent
  consumer/smoke project was created. Other downstream/sanitizer CI is separate.
- Local configuration lessons: keep RUNNER_TEMP short on Windows (the initial
  deeply nested TEMP directory hit Git's path limit; the successful job used
  `C:/t/qc012`). Shared bootstrap requires a fresh job directory. After changing
  vcpkg/toolchain ownership, refresh CMake's configuration cache: otherwise its
  cached `Z_VCPKG_ROOT_DIR` can retain the old checkout despite a new outer
  toolchain path. Do not silently select that old toolchain.
- The local .env's GITHUB_TOKEN overrode `gh auth token`; the first live restore
  correctly stopped at HTTP 401. The verification selected the already active
  GitHub login before importing project environment settings. Credentials and
  TLS handling were unchanged, and the user's .env was not edited.

### TLS context session-cache cleanup (2026-11-09)

- ASan in run 42519288128 reported a direct 10408-byte leak in five formal
  ticket/PKIX/session-resumption cases. The cache destructor had been placed in
  ALPN allocation-error cleanup instead of the owning context destructor.
- Move cache cleanup to final context disposal. Streams retain that context;
  the last release is the quiescent boundary that destroys its mutex, securely
  wipes cached tickets/PSKs and frees storage. ALPN cleanup only owns ALPN.
- Complete native-release-user build passed; CTest regex selecting
  crypto.algorithms.tls_session_cache and the five affected cnet cases passed
  all six (25.09 seconds). Existing server-ticket tests already drop the public
  TLS context while the final accepted stream remains alive. Windows execution
  checks lifetime behavior; leak detection still requires the unchanged ASan CI.

### Issue #219 review corrections (2026-11-09)

- A malformed epoch-zero handshake could reach fragment parsing after READY,
  fail the authenticated session and erase its traffic keys without a valid
  MAC. Both private endpoint formal peers reproduced it. Discard old plaintext
  before parsing after client READY / server verified-Finished final flight;
  authenticated malformed handshakes remain terminal. The regressions verify
  normal authenticated data still arrives after each ignored plaintext probe.
- Shared session-cache lookup sampled time outside its mutex. A concurrent
  later receipt could therefore appear to be a backwards clock and abort an
  unrelated handshake. The private cache now owns a bounded internal OS clock
  sampler and samples after locking; client ticket age uses that exact sample.
  No public clock setting/API or new provider is introduced. Clock failure and
  a sample preceding a published receipt still fail without consuming tickets.
  Tests use an atomic deterministic internal clock; existing eight-contender
  client consume/server lookup checks remain, with publication-interleaving,
  sampled-age, genuine regression and clock-failure cases added.
- Windows x64 LLVM-MinGW, under VsDevCmd: complete native-release-user build
  passed. ctest --preset native-release-user -R
  "(dtls|session_cache|session_resumption|server_tickets|pkix_name_constraints)"
  --output-on-failure passed all 15 tests (45.93 seconds). After the final null
  sampler admission assertion, the complete build and three cache/independent
  DTLS peer tests passed again (1.93 seconds). Cross-platform and sanitizer
  results belong to the subsequent CI, not this local validation.

### PR #273 macOS x64 TLS aggregate timeout (2026-11-09)

- Run 42546894775/job 128933718060 completed the full graph build, then failed
  saltscore.cnet_tls_client_identities at the Go package's aggregate 150-second
  deadline. TestServerVerificationTime had run for only one second and its
  active child case for less than one second. All nine other matrix jobs passed.
- The entry selected every standard-TLS Go test except session resumption;
  unrelated credential, diagnostic and time matrices shared the identity budget.
  Register the seven existing capabilities separately with exact top-level Go
  selectors. Session resumption keeps its existing eighth entry. Preserve all
  scenarios and the existing 150s Go / 180s CTest capability limits; no retry,
  skip, new feature switch or independent validation project was added.
- Actual native-release-user CMake regeneration and complete build passed under
  VsDevCmd/Windows x64 LLVM-MinGW. The eight TLS CTest entries passed in 89.57s;
  encrypted credentials was the slowest local entry at 34.79s. CTest's generated
  JSON confirms all eight exact Go selectors and unchanged timeouts. macOS x64
  must still execute the corrected registration in the subsequent CI.

### PR #273 Windows ARM64 SCTP content failure investigation (2026-11-09)

- Run 42548223680/job 128937770174 failed the eight-peer owned/non-mixed
  SCTP/DTLS scenario: a 24576-byte PPID-53 echo had the right length and no
  read error, but different bytes. macOS x64 and all other matrix lanes passed.
  Thirty local Windows x64 formal repetitions passed (158.35s); that does not
  establish a fix for the ARM64 content failure.
- Strengthen the native formal host to validate each peer's known ingress
  pattern and immediately poison caller storage after copied echo admission.
  The Go failure includes first differing offset and both payload digests.
  The enhanced formal test passed once locally (5.76s). Preserve the original
  content assertion; the next ARM64 CI supplies the missing failure boundary.
- Cleanup previously closed one DTLS peer, then waited for every worker before
  closing the other peers. Close all connections before one bounded group join,
  so one primary content failure does not add repeated sibling-drain failures.

### Recurrent Windows ARM64 SCTP echo integrity failure (2026-11-09)

- PR #274 exact-head CI #411/run 42553750600 passed nine matrix jobs, including
  macOS x64 and both sanitizers, but Windows ARM64 failed the existing
  `saltscore.sctp_dtls_native` owned/eight-peer/non-mixed case. Client 4 received
  24576 bytes/PPID 53 without a read error; first difference was 14364. All new
  SM2 AES256 container tests passed on that lane. This repeats the pre-#274
  symptom recorded above; #409's successful run does not establish its repair.
- Native ingress assertions did not fail. Add a read-only formal peer audit
  after DTLS authentication and before Pion SCTP reassembly: verify packet CRC
  and each nonempty-binary I-DATA payload byte, reporting TSN/SID/MID/FSN and
  the first wrong byte window. The final end-to-end content assertion remains,
  now with a byte window too. No wire rewrite, retry, skip, timeout change,
  provider modification or standalone validation project is introduced.
- Protocol: each Association's one reader borrows the caller buffer until Read
  returns; the audit neither retains nor mutates it. It adds bounded packet
  inspection only. Error propagation stops that Association with the original
  audit evidence; sibling progress/cleanup retains its existing ownership.
- Complete native-release-user build and the enhanced existing formal SCTP/DTLS
  CTest passed on Windows x64 (5.97s); after the final continuation/CRC cases,
  the affected CTest passed again in 5.33s. The seven in-entry audit cases cover
  binary/control/empty packets, CRC-valid bad first/continuation payloads,
  invalid CRC and a truncated header, including input immutability. Subsequent
  Windows ARM64 execution is required to locate the failing boundary; this
  instrumentation is not a claimed fix for the observed corruption.

### SCTP copy/loss and sustained-association isolation (2026-11-09)

- The first read-only audit candidate passed full CI #412 on exact head
  00f815aaa1fefa155780f54b928e98f259caf094, including 204/204 Windows ARM64
  CTests. The intermittent #411 corruption did not reproduce; no repair is
  established by that passing run.
- Add a deterministic case to existing `cnet_sctp_data_test`: eight independent
  sender/receiver pairs queue 24 KiB nonuniform copies from one reused producer
  buffer, poison it immediately, and round-robin protocol progress. Drop each
  sixth I-DATA fragment once, require exactly one repair from an owned TX
  ticket, poison each delivered wire buffer, and compare every serialized
  fragment and the complete reassembled message. Gap SACKs transact over live
  pending copies; all 25 emitted packets per sender and final TX drain are
  checked. The pure SCTP owner has no TLS/socket/Go dependency in this case.
- Extend the real `saltscore.sctp_dtls_native` entry with owned/external
  eight-peer sustained scenarios: 16 large messages per live authenticated
  association plus the original small/empty boundaries. Require all 19 native
  message receipts and cumulative ACKs per peer and all 16 coalesced encrypted
  flights. Original cases remain unchanged; process/test deadlines and feature
  configuration are unchanged. This exercises slot/MID/TSN reuse within live
  connections rather than retrying failed or completed handshakes.
- Windows x64 LLVM-MinGW Release under VsDevCmd: complete native-release-user
  graph passed, then the two affected existing CTests passed in 9.90s (pure
  DATA 0.01s, real SCTP/DTLS 9.88s). Log:
  TEMP/salts-219-sctp-sustained.log. New Windows ARM64 evidence is required;
  neither this coverage nor the earlier full matrix is a corruption fix.
