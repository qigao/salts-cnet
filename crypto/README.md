# Crypto native module

`Salts::Crypto` is the first-party cryptographic facade of
[SaltsCNet](../README.md). It produces exactly **one first-party static
archive** and links the **separate imported vcpkg `GmSSL::GmSSL` static
provider**. Do not compile a second GmSSL native implementation or a generic
ASN.1 reader inside Crypto.

`crypto/src/asn1/crypto.c` contains ECDSA DER SignatureValue and RFC 8410
SPKI/PKCS8 format logic. The canonical general-purpose BER/DER, OID, TLV,
reader and owned Value Tree belong to the separately installed SaltsBase SDK, imported as
`Salts::ASN1` and consumed directly through `<asn1.h>`. All public APIs are `Salts::XXX`
CMake targets, C11 source and C++17-usable C headers.

Use the repository's user presets for the ASN1/Crypto/CNet build and formal
CTest suite. The native GmSSL implementation is installed from the immutable
`gmssl 3.2.0#44` vcpkg port, whose extension sources are pinned from
`gmssl-extensions/`. `Salts::Crypto` links the imported `GmSSL::GmSSL` static
library; it never compiles a duplicate GmSSL implementation.
The GmSSL registry uses `v0.1.1`, with immutable baseline
`4ac631f89e07cebfd347848af642f31fe8c4edec`. CI restores the exact published
ABI binaries from the selected vcpkg-cache SDK; missing ABIs fail restoration.
It registers #44 with TLCP
certificate policy, depth positions, bounded TLS sessions, anchor constraints
and PRF erasure fixes. No local GmSSL overlay is required.
Private Ed448 libecc objects live under `vendor/libecc/` in this module.
No backwards-compatibility alias, fallback or duplicate BER/DER owner.

GmSSL provenance and licenses remain explicit. Production CNet calls only the
opaque Crypto stream API; Crypto's external GmSSL archive is linked transitively
into the single CNet shared owner. Runtime consumers still link `Salts::CNet`;
applications linking the static Crypto target resolve its GmSSL dependency
explicitly.

Installed consumers resolve `SaltsBase` and `GmSSL`, then use
`find_package(SaltsCNet CONFIG REQUIRED)` and link `Salts::Crypto`.
`Salts::ASN1` comes from the matching separately installed SaltsBase SDK.
Direct codec consumers use `find_package(SaltsBase CONFIG REQUIRED)` and link
`Salts::ASN1`; Crypto does not export a second ASN1 owner.

## Unified SDK packaging

Crypto's archive, headers and `Salts::Crypto` target belong to the root
SaltsCNet export set. The former independent `CryptoConfig.cmake` and package
version are no longer produced. Restoring that separate package would retain
two SDK configuration/version owners; the unified export instead keeps the
module and its dependencies in one root-owned build and installation graph.

Consumers migrate `find_package(Crypto ...)` or `find_package(SaltsCore ...)`
to `find_package(SaltsCNet ...)`;
the linked target, archive filename and public header paths stay the same.
The static Crypto target retains its link-only GmSSL dependency. Consumers
linking only the CNet shared runtime do not need to discover that private
provider. The package rename changes CMake discovery, not TLS behavior,
physical runtime ownership, library filenames or the `Salts::` namespace.

## ShangMi algorithm APIs

The public `<crypto/sm2.h>`, `<crypto/sm3.h>`, `<crypto/sm4.h>` and
`<crypto/zuc.h>` interfaces expose GmSSL algorithms through `Salts::Crypto`.
They use caller-owned buffers and private provider state, with explicit
identity/nonce, capacity, overlap, authentication and secret-erasure contracts.
Applications do not need native GmSSL headers.

`<crypto/sm2_keys.h>` provides canonical SPKI/PKCS#8 and two explicitly selected
password-protection profiles: the existing PBKDF2-HMAC-SM3/SM4-CBC operations
and `salts_crypto_sm2_pkcs8_aes256_encrypt`/`_decrypt` for
PBKDF2-HMAC-SHA256/AES-256-CBC. Both enforce bounded work and failure erasure;
CBC does not authenticate stored keys. See
[key containers and ownership](docs/SHANGMI-COVERAGE.md#sm2-key-containers).

Reusable immutable identities and authenticated PKCS#12/PFX inputs are exposed in
`<crypto/tls_credentials.h>`. Contexts import independent provider state, so input
bytes, passwords and the caller's object reference can be released before stream
progress. Profile-specific group lists are copied at initialization. See
[identity objects and PFX](docs/SHANGMI-COVERAGE.md#immutable-identity-objects-and-authenticated-pfx).

`<crypto/sm2_cms.h>` provides bounded SM2/SM3 SignedData with explicit pinned
signer trust. `<crypto/sm2_cms_envelope.h>` provides one-recipient SM2/SM4-GCM
authenticated envelopes with recipient trust; sender identity requires an inner
verified SignedData. `<crypto/sm2_ocsp.h>` verifies direct-issuer or explicitly
selected delegated OCSP responses. Delegates require an issuer-signed no-check
certificate. Crypto/CNet snapshot factories copy all admission material and
recheck current status before application readiness. See
[the finite CMS and OCSP profiles](docs/SHANGMI-COVERAGE.md#current-software-coverage).

TLS contexts can select certificate-chain signature algorithms independently
of handshake signatures in standard TLS1.2/1.3 and range negotiation. TLS1.2
client identity selection also respects CertificateRequest's shared list. The
local candidate adds TLCP client-side SM2/RSA issuer lists independently of its
SM2 handshake. See
[certificate signature policy](docs/SHANGMI-COVERAGE.md#separate-certificate-signature-policy-tls-1213).

TLS memory credentials accept explicit PBKDF2-HMAC-SHA2 (SHA224, SHA256, SHA384,
SHA512, SHA512/224 or SHA512/256) with AES-128/192/256-CBC, alongside SM3/SM4.
Existing work/size limits, initialization
ownership and private-key/certificate binding apply. See
[memory credentials](docs/SHANGMI-COVERAGE.md#memory-credentials-and-trust-inputs).

ShangMi TLS1.3 client/server contexts also accept immutable
`key_update_interval_ms`: zero disables it, while a nonzero millisecond interval
checks local sending-key age before new application records. It composes with
record/byte budgets and preserves mandatory peer responses and pending writes.
See [rotation interval and duplex ownership](docs/SHANGMI-COVERAGE.md#local-sending-key-rotation-interval).

TLS1.3 KeyUpdate and NewSessionTicket reception supports bounded record
fragmentation/coalescing while preserving key-change boundaries and independent
duplex storage. Ticket serialization checks its fixed capacity before writing.
See [post-handshake framing](docs/SHANGMI-COVERAGE.md#bounded-tls-13-post-handshake-framing);
this framing coverage alone does not qualify restoration.

Exact STANDARD TLS1.3 and ShangMi TLS1.3 clients can enable a fixed context-owned
ticket cache using `session_cache_capacity` (0 disables, 1..16 entries).
Only streams sharing the immutable context share tickets. Accepted PSK_DHE
resumption revalidates the original certificate chain and current peer policy,
and enforces the original ALPN, before application data. Crypto and CNet expose
`*_session_reused` for actual accepted restoration. Independent Go TLS and
ShangMi peers cover full/resumed data/close and ticket refusal; certificate expiry,
ALPN/policy rejection and bounded concurrency have formal regression coverage.
See [ownership and limits](docs/SHANGMI-COVERAGE.md#context-owned-client-tls13-session-cache).
Server contexts can enable one stateful ticket per admitted TLS1.3 handshake
with `session_ticket_capacity` (1..16) and `session_ticket_lifetime_seconds`
(1..604800); both zero disables. The retained server context owns PSKs and
authenticated peer state; a ticket carries only a random lookup identity.
Fresh binder/ECDHE/Finished verification and original mTLS chain/policy checks
remain mandatory. Independent standard TLS clients cover mTLS/SNI/ALPN/expiry
and capacity; independent ShangMi clients cover server-authenticated resumption
and ticket/binder negatives. See [server ownership and qualification](docs/SHANGMI-COVERAGE.md#context-owned-tls13-server-tickets-local-implementation-contract).
TLS1.2/TLCP restoration, persistence and 0-RTT remain open.

Configured-anchor name constraints now cover every subordinate certificate,
including through an unconstrained intermediate and in TLCP dual-leaf paths.
This is not general PKIX/path-building qualification. DTLS1.2 AES-GCM records,
replay protection, stateless cookies, bounded reassembly/timers, EMS/Finished and
P256 exchange/signed-parameter helpers are internal only, with independent
Python wire/key-schedule/signature/ECDH tests.
Internal DTLS1.2 client/server owners now compose those pieces into cookie/EMS
negotiation, verified certificate admission, Finished, application records and
close. The client can select one imported P256/RSA identity from the server's
CertificateRequest and prove possession; the server supports required client authentication
and retained peer policies, shared credential contexts and explicit SNI admission.
Independent Python and Pion UDP-loopback tests cover ECDSA/RSA, fragmented/lost/
reordered flights and negative authentication paths. General negotiation policy
and broader platform qualification remain unfinished. The bounded SCTP bridge
and supplied-chain PKIX cases now have local native evidence described below. Finite opaque
client/server APIs in `<crypto/dtls_stream.h>` expose these profiles without
provider headers; `<cnet/dtls.h>` composes either role with an existing bound
datagram in ordinary or host-owned NativeIO mode. Server cookie gating precedes
stream allocation; shared listener credentials remain leased until all accepted
streams drain and are destroyed. CNet consumers create/destroy listeners through
`cnet_dtls_listener_create`/`cnet_dtls_listener_destroy` in the same CNet DSO,
preserving its single physical Crypto instance. See the
[server admission contract](docs/SHANGMI-COVERAGE.md#opaque-dtls-server-listener-and-native-admission).
See the [client composition and limits](docs/SHANGMI-COVERAGE.md#opaque-dtls-client-and-cnet-datagram-composition) and the
[private contract](docs/SHANGMI-COVERAGE.md#dtls12-handshake-preparation-private-contract).
The [private client owner](docs/SHANGMI-COVERAGE.md#private-dtls-client-owner-work)
documents verification, bounded sends, teardown and the exact test scope.

Authenticated application delivery supports bounded backpressure: Crypto's
`CRYPTO_DTLS_BUSY`, mapped from CNet `on_receive` returning `SALTS_ENOBUFS`,
consumes no application data. The stream owns one deferred plaintext record and
the remaining encrypted datagram tail until later progress; it never decrypts
or consumes replay state twice for a delivery retry. Other callback errors
remain terminal. `pending_receive` exposes that retained obligation.

`crypto_dtls_stream_hmac` derives an exporter-bound key and computes a bounded
HMAC-SHA256 proof without exposing that key. CNet callers use `cnet_dtls_hmac`
through the same physical Crypto owner. An exporter is shared with the peer:
server-only SCTP cookie authentication must additionally use an independent
secret key/context, never a public exporter label alone. The native fixture
uses an OS-random private per-association context and erases it at teardown.

The C11 [SCTP bridge](../sctp/README.md#cnet-dtls-bridge) links through
`Salts::SCTPDTLS`, preserving the provider-independent `Salts::SCTP` target.
See [current SCTP, backpressure and PKIX qualification](docs/SHANGMI-COVERAGE.md#sctp-composition-and-authenticated-delivery-backpressure)
for the real multi-peer load and rejection matrix; these are bounded profiles,
not a general WebPKI/path-builder qualification.
The [private server contract](docs/SHANGMI-COVERAGE.md#private-dtls-server-owner-contract)
documents credential ownership, listener leases, mTLS and SNI test boundaries.
Both private owners also support an explicit opt-in RFC5705 exporter after READY.
Default sessions erase the master after admission; exporter sessions retain it
until close admission, abort, failure or clear. Context-aware derivation and
independent peer agreement are described in the
[exporter contract](docs/SHANGMI-COVERAGE.md#private-dtls-exporter-and-master-retention).
Private DTLS protocol failures can also prepare one fatal alert in the actual
local write epoch, erase secrets immediately and retain the output through its
real send terminal. Peer fatal alerts terminate without echo; malformed outer framing,
bad tags and replays retain their discard behavior. See the
[fatal alert contract](docs/SHANGMI-COVERAGE.md#private-dtls-fatal-alert-delivery).

ShangMi TLS1.3 client/server contexts can require minimum peer KeyUpdate time
and authenticated application-byte spacing with `peer_key_update_min_interval_ms`
and `peer_key_update_min_bytes`. Zero disables each minimum; after one initial
update, all enabled minima must pass before another receiving-key derivation.
These restrictive policies include replies and may reject legitimate bursts.
See [peer spacing and its ownership](docs/SHANGMI-COVERAGE.md#peer-keyupdate-minimum-spacing).

TLS1.3 encrypted fatal alerts use the local role's sending keys and sequence,
including during handshake and partial transport output. See
[alert direction and qualification](docs/SHANGMI-COVERAGE.md#tls-13-fatal-alert-direction).

See [ShangMi coverage and production gates](docs/SHANGMI-COVERAGE.md) for the
implemented operations, formal tests and remaining requirements. Algorithm
tests do not qualify a TLS/TLCP/DTLS protocol or a hardware deployment.

## Opaque TLS streams for transport owners

`<crypto/tls_stream.h>` owns the production context and session implementation
previously in CNet. It retains the established TLS 1.2/1.3 range and exact-version
profiles, ShangMi TLS 1.3, TLCP 1.1, ALPN, mTLS, DNS/IP identity checks, explicit
CA file/directory loading and platform trust stores. Unsupported TLCP client
identity/required client authentication remains rejected. The original versioned
`tls.h` APIs and their qualification tests remain available; this change does
not broaden their advertised capabilities.

Contexts consume configuration synchronously and are immutable reference-counted
objects. Each stream retains its context, so the creator may release its own
reference immediately. A stream has one exclusive progress owner and fixed-size
ciphertext/plaintext storage. Native receive/transmit buffers are separate from
plaintext staging and remain valid until stream destruction. The host must stop
admission and drain native completions before destroying the stream; Crypto does
not own sockets, cancellation completion, timers or a progress thread.

Servers can configure up to four ordered file or memory identities for SNI
selection in TLS 1.2/1.3, ShangMi TLS 1.3 and TLCP. All identities are loaded at
context creation, share one trust/authentication policy and remain immutable.
See [identity selection and its bounds](docs/SHANGMI-COVERAGE.md#immutable-server-identity-selection).

Clients can similarly configure up to four file or memory identities. TLS 1.2,
TLS 1.3 and ShangMi select the first compatible identity from CertificateRequest
CA hints and signature constraints. With no match they send an empty certificate;
without a request they send no identity. Trust policy remains independent and
mandatory. See [client identity selection](docs/SHANGMI-COVERAGE.md#immutable-client-identity-selection).

Protocol range selection is rejected after the first handshake call. TLS errors
cannot trigger plaintext fallback or a new trust source. A local shutdown record
is distinct from authenticated peer close_notify. CNet translates stream results
to its existing error/terminal contract and retains its send and receive resource
policies. Those policies do not replace Crypto-owned allocations.

The existing TLS I/O formal test now exercises both exact versions through this
opaque API, including failed creation, creator-reference release, copied ALPN,
bounded input rejection, application data and reciprocal shutdown. Production
CNet/NativeIO and independent Python peer tests exercise the same stream
implementation through the shared runtime. Cross-platform acceptance requires
the new exact-head LLVM CI; local results alone do not complete that gate.

## X.509 certificate inspection for TLS callers

The Crypto module also exposes read-only `<crypto/x509_der.h>`, whose
`crypto_x509_der_inspect` and `crypto_x509_der_chain_next` validate and
walk DER certificates through the one sibling `Salts::ASN1` codec. The
existing `crypto_tls_session_copy_peer_chain_v1_2` returns a bounded
caller-owned concatenated DER chain that can be consumed by this inspector
without changing GmSSL's authenticated TLS handshake or trust decisions.
See [X.509 DER scope](docs/X509-DER-ASN1-INSPECTION.md).

Handshake diagnostics retain expired/not-yet-valid results and the zero-based
position of the certificate actually checked in the peer's presented chain.
This includes intermediate CAs and TLCP's encryption leaf. The local candidate
also reports the first presented issuer beyond the configured depth, accounting
for both TLCP leaves. Local-only trust
anchors and failures without a known position use `SIZE_MAX`; the diagnostic
remains an owned value after stream teardown. See `<crypto/tls_diagnostic.h>`.

Client and REQUIRED-auth server configurations accept `verification_time`, an
optional pointer to Unix seconds in `0..253402300799`. Initialization copies the
value; the caller can then erase it. NULL preserves the system clock, while an
explicit zero selects the Unix epoch. The fixed value applies to certificate
validity checks for every peer leaf, presented CA and local trust anchor in
STANDARD TLS1.2/1.3, ShangMi TLS1.3 and TLCP server authentication. It does not
change signature, usage or identity checks, nor the clocks/freshness rules of
additional peer policies, CRLs or OCSP. Servers without client authentication
reject the option with EINVAL; iOS implicit platform trust returns ENOTSUP.

For example, configure a context with `.verification_time = &unix_seconds` where
`unix_seconds` is an `int64_t`. A fixed context-owned value avoids process-global
clock changes, callback lifetimes and mutable shared TLS contexts. No per-stream
override is provided. Clear the pointer before creating a new context to restore
system-time behavior; existing contexts retain their original value. Updating
the pinned GmSSL headers and archive together is required for its changed context
layout and extended verifier signatures.

The handshake role determines the required certificate purpose: server/client
authentication for TLS signing leaves, the encryption role for TLCP's second
server leaf, and CA signing plus applicable EKU restrictions for issuers.
Decoded KU/EKU mismatches report `CRYPTO_TLS_FAILURE_PURPOSE`, with the actual
presented-chain index when known. Local-only anchors keep `SIZE_MAX`. Missing
extensions retain the provider's existing acceptance rules; malformed extensions
and unrelated constraints retain their existing failure categories. Diagnostics
come from the check that failed, without a second parse or verification pass.
Validity checks still precede extension checks, so a certificate that is both
expired and unsuitable retains its expiry diagnosis. This diagnostic addition
does not add a purpose override or change trust/admission decisions.
