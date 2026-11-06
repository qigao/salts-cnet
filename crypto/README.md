# Crypto native module

`Salts::Crypto` is the first-party cryptographic facade of
[SaltsCore](../README.md). It produces exactly **one first-party static
archive** and links the **separate imported vcpkg `GmSSL::GmSSL` static
provider**. Do not compile a second GmSSL native implementation or a generic
ASN.1 reader inside Crypto.

`crypto/src/asn1/crypto.c` contains ECDSA DER SignatureValue and RFC 8410
SPKI/PKCS8 format logic. The canonical general-purpose BER/DER, OID, TLV,
reader and owned Value Tree are under [../asn1/](../asn1/), exported as
`Salts::ASN1` and consumed directly. All public APIs are `Salts::XXX`
CMake targets, C11 source and C++17-usable C headers.

Use the repository's user presets for the ASN1/Crypto/CNet build and formal
CTest suite. The native GmSSL implementation is installed from the immutable
`gmssl 3.2.0#35` vcpkg port, whose extension sources are pinned from
`gmssl-extensions/`. `Salts::Crypto` links the imported `GmSSL::GmSSL` static
library; it never compiles a duplicate GmSSL implementation.
Private Ed448 libecc objects live under `vendor/libecc/` in this module.
No backwards-compatibility alias, fallback or duplicate BER/DER owner.

GmSSL provenance and licenses remain explicit. Production CNet calls only the
opaque Crypto stream API; Crypto's external GmSSL archive is linked transitively
into the single CNet shared owner. Runtime consumers still link `Salts::CNet`
without importing the private provider package.

Installed consumers require `find_package(Crypto 0.1 CONFIG REQUIRED)`
and link `Salts::Crypto`. This imports the sibling `Salts::ASN1` via
`find_dependency(ASN1)`. Direct protocol consumers should instead use only
`find_package(ASN1 0.1 CONFIG REQUIRED)` and `Salts::ASN1`.

## ShangMi algorithm APIs

The public `<crypto/sm2.h>`, `<crypto/sm3.h>`, `<crypto/sm4.h>` and
`<crypto/zuc.h>` interfaces expose GmSSL algorithms through `Salts::Crypto`.
They use caller-owned buffers and private provider state, with explicit
identity/nonce, capacity, overlap, authentication and secret-erasure contracts.
Applications do not need native GmSSL headers.

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
This includes intermediate CAs and TLCP's encryption leaf. Local-only trust
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
