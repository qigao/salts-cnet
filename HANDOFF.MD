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
