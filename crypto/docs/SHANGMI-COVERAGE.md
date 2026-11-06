# ShangMi coverage and production qualification

GmSSL remains the production provider for national cryptography. Salts::Crypto
owns the application API; CNet owns transport progress and lifetime. Applications
select an explicit protocol/security profile and use the same CNet ownership,
buffering and failure contracts. No profile silently changes provider, trust
source or falls back to plaintext.

## Current software coverage

| Capability | Public Core interface / status | Formal evidence |
|---|---|---|
| SM2 | Raw private/public keys, identity-bound SM3 signatures, canonical DER public-key encryption | Standard generator, signature identity/message negatives, invalid scalar/point, maximum plaintext, corrupted/truncated ciphertext |
| SM3 | Streaming and one-shot digest/HMAC; HKDF; PBKDF2 | Known answers, fragmented input, erased state, invalid reuse, overlap/length/iteration rejection |
| SM4 | ECB/CBC without padding; CTR/OFB/CFB8/64/128; XTS; GCM/CCM | Block and independent mode vectors, RFC 8998 GCM/CCM vectors, partial segments, XTS ciphertext stealing, bad tag erasure, counter wrap rejection |
| ZUC | ZUC128/256 whole-message encryption and bit-length MAC/verification | Known keystream/MAC answers, all tag sizes, ignored unused final bits, corrupt tag, key/length rejection |
| SM9 signature/encryption/KEM | Public identity-based signing, XOR encryption and KEM; fixed canonical key points and DER messages | Published signature/KEM/encryption vectors, scripted nonce/failure paths, finite prime-order subgroup admission, DER/tamper/identity negatives and output erasure; cross-platform CI required |
| SM9 key exchange | First-party bounded exchange over existing GmSSL primitives, with mandatory mutual key confirmation and distinct exchange keys | Published session-key and both confirmation vectors; identity/master/purpose binding, wrong phase, forged/replayed confirmations, RNG failure, cancellation and erasure; cross-platform CI required |
| SM2 full authenticated key exchange | GB/T 32918.3 curveSM2 agreement with explicit static peer trust, Z bindings and mandatory mutual confirmation | GB/T 32918.5 Annex B shares/key/confirmation vectors; independent gmsm key vector; identity/static-key mismatch, invalid points, infinity sum, zero combined scalar, RNG/phase/replay/erasure; cross-platform CI required |
| SM2 key containers | Canonical SPKI and PKCS#8 import/export; PBES2 PBKDF2-HMAC-SM3 / SM4-CBC password protection | Public API negatives, RNG failure, GmSSL key-file interop and independent Python bidirectional interop; cross-platform CI required |
| SM2 certificate primitives | SM2 public-key extraction, local private-key binding and explicit-issuer signature verification | Native and independent gmsm certificates; ID/issuer/DER/algorithm/tamper negatives; these operations do not validate certificate trust |
| SM2 pinned-peer trust | Explicit bounded chain/anchor, leaf-key identity, validation time, signing purpose and revocation policy | Independently signed paths, CA/pathLen/KU/EKU/time/constraint negatives, callback gating and failure erasure; cross-platform CI required |
| SM2 complete direct CRL | Explicit issuer/SM2 signing ID, full-CRL scope, time/age/number policy and serial checking | Independent gmsm CRLs, real pinned-trust callback, revoked/stale/rollback/scope/DER negatives; cross-platform CI required |
| CMS / SM2 certificate workflows | CMS enabled in provider; public workflow qualification pending | Generic ASN1 parsing and existing X509 inspection alone do not qualify signing or trust |
| TLCP 1.1 ECC_SM4_GCM_SM3 | Explicit CNet client/server profile with dual SM2 server certificates | Independent GoTLCP bidirectional handshake/data/close, CA/DNS/IP/time/signature/KU negatives, local dual-identity admission and signature-extension/cipher rejection; cross-platform CI required |
| TLS 1.3 ShangMi | Explicit CNet client/server RFC 8998 SM4-GCM profile with SM2 server authentication and REQUIRED-mTLS | Independent server-authenticated handshake/data/close, certificate/CertificateVerify/Finished negatives, exact profile rejection, fragmentation and abnormal EOF; native/native mTLS with independent certificates/digests and independent mTLS in both native directions; cross-platform CI required |
| DTLS | Issue #188 resumed; implementation and CNet/SCTP qualification pending | Existing TLS tests do not qualify DTLS |
| SDF / SKF hardware | Requires selected vendor runtime/device and its integration tests | No software fallback for non-exportable keys |

GmSSL 3.2.0 port revision 24 enables SM9, ZUC and CMS and exports the enabled
algorithm feature definitions. It also clears the PBKDF2 password-derived
template and rejects invalid/infinity uncompressed SM2 points. These changes
belong to the external package, not a duplicate in-tree GmSSL build. Revision 20
preserves the original digest/pairing base and recipient point across SM9
retries, bounds attempts, rejects zero KEM nonces/infinity and cleans up
extraction scalars and KEM/signing working state on error paths.
Revision 21 admits curveSM2 plain PKCS#8 keys in the existing bounded loader
and uses the TLCP SM3/SM2 signature pair `0x0704` in ClientHello extensions.
The internal SM2 scheme and RFC 8998 TLS 1.3 wire identifier remain `0x0708`.
Revision 22 honors peer-requested TLS 1.3 KeyUpdate independently of automatic
local rotation settings or previous record count. A pending encrypted update
retains its control-write state across backpressure, so it cannot report stale
application completion or rotate the sending key twice.
Revision 23 adds a per-context consecutive authenticated peer-KeyUpdate limit.
It checks the budget before deriving new traffic keys and resets only when a
nonempty authenticated application record is received.
Revision 24 adds bounded in-memory certificate-chain and plain PKCS#8 key
admission. It checks the complete chain ordering and each private-key binding
before committing the context's owned identity.

### Memory credentials and trust inputs

Crypto/CNet client and server configurations accept `ca_data` and `credentials`
from `crypto/tls_credentials.h`. Each input explicitly selects DER or PEM and
provides a byte length; no NUL terminator, temporary file or filesystem lookup
is needed for memory inputs. Certificate chains and anchors use concatenated
DER certificates or `CERTIFICATE` PEM blocks. Plain private keys use one
PKCS#8 `PrivateKeyInfo`, DER or `PRIVATE KEY` PEM, for RSA or EC SM2/P-256.
TLCP servers provide separate signing and encryption keys and a chain ordered
as signing leaf, encryption leaf, then issuers. Both certificate/key bindings
and the two KeyUsage roles are checked before initialization succeeds.

Memory trust excludes `ca_file`/`ca_path`; memory identity excludes
`cert_file`/`key_file`/`key_password`. Conflicts, invalid descriptors and
unsupported encodings fail before trust loading or publication. Empty or invalid
explicit anchors never select system trust. Input bounds are 1 MiB for trust
and 16 KiB for each identity input; decoded chains are at most 8189 bytes and
each decoded key at most 8192 bytes. PEM rejects foreign labels, noncanonical
base64 padding, extra keys and non-whitespace trailing text. Each certificate
PEM block must encode exactly one complete certificate.

Inputs are borrowed only during initialization. Successful contexts own their
certificate/key state and anchors; internal decoded private keys are cleared
on success and failure. Existing retain/release, fixed owner, authentication,
protocol profile and additional peer-policy contracts remain unchanged.
There is no hot update, file watcher or replacement of an established identity.

Formal provider/Crypto tests cover both memory encodings, TLS 1.2/1.3 handshake
and application data after source erasure, malformed/oversized/conflicting
inputs, key mismatch and explicit-trust failure. Independent CNet tests cover
both encodings with native/native and independent-peer ShangMi REQUIRED-mTLS,
TLCP in both directions, and malformed dual identities. The CNet adapter frees
all credential input before progressing a handshake and links only CNet's
canonical Crypto owner.

Set `private_key_password` or `encryption_key_password` in the credential
descriptor to load an encrypted PKCS#8 key, independently for either TLCP key.
Passwords use a byte pointer and length (up to 1024 bytes); embedded NULs are
significant. NULL/0 selects plaintext, while a non-NULL pointer with zero length
selects an empty password. Password bytes are borrowed only during init.
Encrypted inputs use DER `EncryptedPrivateKeyInfo` or `ENCRYPTED PRIVATE KEY`
PEM: PBES2 with either explicit PBKDF2-HMAC-SM3 / SM4-CBC or explicit
PBKDF2-HMAC-SHA256 / AES-128/192/256-CBC. Salt is 8..64 bytes, IV is 16 bytes, optional
key length is absent or the cipher key size (16, 24 or 32 bytes), and iterations are
10000..1000000. PRF AlgorithmIdentifier parameters may be absent or NULL; an
omitted PRF is rejected, including the implicit SHA1 default. Padded ciphertext is capped at
8192 bytes before derivation/decryption; decoded keys still undergo exact
PKCS#8 parsing and certificate binding. Derived keys, cipher state and decoded
private keys are cleared on every exit. Unsupported schemes and malformed
input fail without publishing a context or trying a plaintext fallback.

Formal tests cover encrypted RSA TLS 1.2/1.3 IO after password/input erasure,
empty and embedded-NUL passwords, malformed PKCS#8, wrong passwords, KDF bounds,
salt/key-length/PRF admission, padding and output bounds. Independent Go fixtures
cover encrypted SM2 credentials in native/native and independent ShangMi mTLS,
and separate encrypted TLCP signing/encryption keys, in both memory encodings.

GmSSL #31 extends the existing PKCS8 encryption-algorithm whitelist to AES128
and AES192. The common algorithm decoder already knows both OIDs. Crypto selects
the exact 16/24/32-byte PBKDF2 output and AES schedule from the cipher OID;
explicit mismatched key lengths fail before derivation. No cipher inference
from ciphertext/key length and no unsupported-PRF fallback.

The AES credential tests use independently generated Go standard-library PBES2
fixtures for RSA/P256 in PEM/DER: explicit/absent key length and PRF parameters,
empty/binary passwords, salt/iteration bounds, wrong passwords, invalid padding,
invalid plaintext, malformed/truncated envelopes, unsupported parameters, output
capacity and key/certificate mismatch. Both context roles must fail atomically.
Authenticated TLS1.2/1.3 with preconfigured encrypted identities releases the
input/password storage before progress. Independent gmsm fixtures additionally
qualify AES-protected SM2 credentials in native/native and independent ShangMi
mTLS, and both TLCP server keys with separate passwords. The existing SM3/SM4
cases remain covered. CBC envelope encryption does not provide authentication;
strict PKCS8 parsing and certificate binding remain mandatory. This addition
applies to TLS memory credentials; the separate SM2 key-container export API
keeps its documented SM3/SM4 protection format.

PKCS#12/PFX, other encrypted PKCS#8 algorithms and retained credential/key objects
remain unimplemented. SDF/SKF hardware integration is deferred by user decision.

### Immutable server identity selection

Crypto streams and CNet servers accept an ordered `identities` array with
`identity_count` from 1 to `CRYPTO_TLS_SERVER_IDENTITY_MAX_COUNT` (4). Each
`crypto_tls_server_identity` / `cnet_tls_server_identity` uses either certificate
and key files or the memory credential descriptor above. Clear the top-level
`cert_file`, `key_file`, `key_password` and `credentials` when supplying the set.
NULL/0 keeps the existing single identity configuration.

Initialization validates every descriptor before file access, then loads and
binds every identity before publishing a context. A later entry failure releases
the entire context. Inputs, passwords and descriptors can be erased on return;
accepted streams retain the context after the creator releases it. The provider
has one 8192-byte encoded chain budget per protocol variant, including three
bytes per identity. A valid individual chain can still exceed the aggregate
budget when combined with others. Descriptor/count errors return EINVAL,
oversized memory inputs ERANGE, and loading/binding/aggregate failures EIO.

GmSSL selects the first identity compatible with SNI, signature schemes and
other handshake parameters. All DNS SAN entries participate, matching ASCII
case-insensitively. Only a complete leftmost wildcard label is supported and
it consumes exactly one host label. There is no CN fallback. Unknown SNI
rejects the handshake; absent SNI selects the first compatible identity.
Prepare internationalized host names as ASCII A-labels. Trust, mTLS, ALPN,
version, cipher and signature policies apply to the whole immutable set.
There are no selection callbacks, handshake-time file reads or hot replacement.
Client CertificateRequest identity selection remains outstanding.

TLS 1.2/1.3 independent Python clients check the selected certificate bytes,
required client authentication, all input encodings, secondary SANs, case,
wildcards, absent/unknown SNI and skipping a signature-incompatible first key.
The SNI matrix uses the explicit P-256 group profile; additional TLS 1.3 cases
use Python's default groups to cover HRR negotiation. GoTLCP verifies the
second dual identity under its separate CA through authenticated IO and close;
the independent ShangMi mTLS client sends SNI and checks the second SM2
identity, including encrypted PEM/DER keys. Native formal tests cover four
identities, malformed descriptors, late key/password failures and aggregate
capacity. Cross-platform qualification still requires the matching LLVM CI.

### TLS 1.3 HelloRetryRequest padding and rejection

GmSSL #28 accepts adding, removing, growing, shrinking or emptying ClientHello2
padding, as permitted by [RFC 8446 section 4.1.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2).
Present ClientHello2 padding must contain only zeros. Duplicate extensions,
truncation, changed random/SNI, removed SNI/signature algorithms and an unrelated
new extension still reject before ServerHello. HRR rejection sends a plaintext
fatal alert before handshake traffic keys exist, avoiding the previous
uninitialized-key access. Failure remains terminal on subsequent progress.

Fifteen native formal cases force HRR and inspect ServerHello or fatal-alert
output. These cases qualify the parsing/rejection boundary, not a full client
handshake. Independent Python clients separately complete TLS 1.3 mTLS and
authenticated application IO with the second SNI identity, using file, PEM and
DER credentials and default key shares. The test observes HRR and ClientHello
padding lengths without rewriting the transcript. On the local Windows
runtime all three cases took one HRR with padding changing from absent to 237
bytes. Default shares may differ on other Python platforms; the native cases
remain deterministic. This does not qualify PSK resumption, 0-RTT or every HRR
extension combination.

### Handshake failure diagnostics

`crypto_tls_stream_get_diagnostic` copies the first local handshake failure
into a provider-neutral `crypto_tls_diagnostic`. Query from the stream's
exclusive progress owner, including after failure and until destroy. ENOENT
with a zero value means that no failure was recorded; it does not mean that
authentication succeeded. Invalid queries and repeated handshake calls do not
replace an existing diagnostic.

CNet delivers the same value in `cnet_error.tls` during the FAILED callback.
The owner snapshots it before draining alerts and destroying TLS state, and
copies it through direct dispatch, queued dispatch and queue backpressure.
The application can copy the value beyond callback return. It contains no
borrowed certificate/key/provider pointers and allocates no diagnostic payload.
Non-TLS, transport-only, context-init and post-handshake failures have NONE.

Categories distinguish certificate, chain signature, trust anchor, depth,
CRL/OCSP, constraints, certificate extensions, identity, absent required
certificate, application peer-policy rejection, profile and platform trust
failures when the underlying verifier supplies that information. Generic
HANDSHAKE means that no more specific local verification result is available.
An alert from the remote endpoint is not evidence of its detailed verification
result. In particular, a server can reject SNI before sending any certificate;
the client may observe a handshake alert or a transport close.

Certificate position is zero-based in the presented peer chain. Identity
failures identify leaf index 0; other currently unreported positions use
SIZE_MAX. CERTIFICATE currently groups parsing/validity/usage errors rather
than inventing an expired/not-yet-valid classification. More detailed provider
reasons, certificate positions and configurable validation time remain
separate work.

Formal tests cover real TLS trust/identity rejection, standard and ShangMi
peer-policy rejection, TLS 1.2/1.3 first-failure stability and peer-alert
classification, plus owned event snapshots under queue pressure and slot reuse.

### Certificate verification depth

Crypto/CNet client and server configurations expose immutable
`verification_depth`: zero retains the default of 4; explicit values 1..5
select the maximum number of peer-supplied issuer certificates after the leaf.
For TLCP server authentication both signing and encryption leaves are excluded.
A root included in the transmitted chain counts; an anchor loaded locally does
not. This bounds the provider's presented-chain verification, not a new general
path builder or an OpenSSL-compatible intermediate-only count. Other mandatory
trust, identity, purpose, pathLen, chain-count and byte limits still apply.

Values above 5 fail with EINVAL before allocation/trust loading. Servers must
enable REQUIRED client authentication to configure a nonzero depth; otherwise
initialization fails with EINVAL. The iOS implicit system-trust bridge does not
expose this provider depth contract, so a nonzero depth there fails with ENOTSUP;
explicit CA file/path/memory sources use the normal provider path. No requested
bound is silently ignored. Zero never disables certificate verification.

Every initialized TLS variant receives the same normalized depth after loading
trust, including memory anchors. The context consumes the numeric value at init;
caller config changes cannot widen it. A rejected peer chain reports DEPTH via
the first-failure diagnostic, without publishing CONNECTED or application data.

Formal tests use independently signed two-issuer chains in TLS 1.2, TLS 1.3 and
ShangMi mTLS, accepting depth 2 and rejecting depth 1 on either endpoint. The 36
cases cover file/PEM-memory/DER-memory inputs, default/maximum settings, included
root accounting and early context release. Five invalid configuration cases
fail before reading nonexistent credential paths. Independent TLCP clients use
depth 1 with dual-leaf server identities. iOS device execution is not claimed.

### Cipher-suite policy

Crypto/CNet client and server configurations accept `cipher_suites` and
`cipher_suite_count`. NULL/0 retains the existing profile defaults. An explicit
list is bounded to three unique `crypto_tls_cipher_suite` values and is consumed
synchronously; callers can overwrite/release it after initialization. Contexts
and subsequently created streams retain the copied policy. There is no hot update.

STANDARD permits TLS_AES_128_GCM_SHA256 for TLS 1.3, and
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 / TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 for
TLS 1.2. SHANGMI_TLS13 permits TLS_SM4_GCM_SM3; TLCP11 permits its distinct
ECC_SM4_GCM_SM3 identifier. These are restrictions of the qualified profile,
not a pass-through to every suite the provider recognizes. Signature selection has its own list below; group selection retains profile defaults.

Each enabled protocol version must have a permitted suite, and every supplied
suite must apply to the context's profile and version bounds. For TLS 1.3 only,
set `minimum_version = maximum_version = 13` together with its one-suite list.
For the default TLS 1.2–1.3 range, include at least one TLS 1.2 suite and the TLS
1.3 suite. Selection never silently narrows protocol bounds or restores defaults.
Pointer/count mismatches, duplicate entries and excess count return EINVAL;
unknown/unqualified suites and profile/version conflicts return ENOTSUP before
credential loading, allocation or peer-policy retention. Local order is preserved
within each protocol; peer offers, credentials and signature policy still govern
successful negotiation. No suite intersection fails before application readiness.

GmSSL revision #25 filters range-context suites by the negotiated TLS 1.3
protocol before initial and certificate-based selection. A regression against
#24 reproduced selection of a TLS 1.2 suite when it appeared first in a mixed
list. Formal tests cover that ordering, 28 invalid client/server configurations,
nine explicit/default endpoint/version combinations, two disjoint-suite failures,
caller-list erasure and direct stream narrowing. A TLS 1.3 ClientHello offering
only TLS 1.2 suites must receive a fatal alert before any ServerHello. Independent
Python TLS 1.2/1.3 and Go ShangMi/TLCP peers exercise explicit lists in both roles,
including authenticated data/close and existing authentication negatives.

### Signature policy

Crypto/CNet contexts accept `signature_algorithms` / `signature_algorithm_count`.
NULL/0 keeps defaults; an explicit list contains 1..4 unique public
`crypto_tls_signature_scheme` identifiers. Initialization copies the list into
every enabled provider variant. Source arrays can be overwritten immediately,
and stream-level version narrowing cannot restore excluded schemes.

STANDARD admits RSA-PKCS1-SHA256, RSA-PSS-RSAE-SHA256, ECDSA-P256-SHA256 and
ECDSA-P384-SHA384. TLS 1.2 excludes RSA-PSS in this qualified implementation;
TLS 1.3 admits PKCS1 for certificate signatures only, and needs another scheme
for CertificateVerify. ECDSA-P384 supports verification of the existing P384
certificate profile; this does not add P384 private-key loading. SHANGMI/TLCP
admit only SM2/SM3. Unknown schemes/profile/version conflicts and lists with
no handshake-capable scheme for an enabled version fail with ENOTSUP before
allocation/trust loading. Pointer/count mismatches, duplicates and excess count
fail with EINVAL. A valid list still requires compatible keys, certificates,
peer offers, trust and identity; it does not bypass authentication checks.

The list constrains handshake signatures and certificate-chain signatures.
There is no independently configurable certificate-signature list. GmSSL #26
preserves the certificate list while filtering PKCS1 out of TLS 1.3 handshake
selection, so PKCS1-before-PSS order cannot select an invalid CertificateVerify.
Without `signature_algorithms_cert`, signature_algorithms also supplies the
certificate policy, as required by
[RFC 8446 §4.2.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3).
The top presented certificate is checked with its authenticated locally trusted
issuer even when that issuer was not sent. The trust anchor's own signature is
exempt. This applies to both server and REQUIRED-client authentication.

Explicit signature lists with iOS implicit system trust return ENOTSUP because
the provider cannot obtain the native trust bridge's terminal issuer key;
explicit anchors retain the normal contract. No iOS device qualification is
claimed. Separate certificate-signature lists and general path building remain
open work.

Formal tests cover 26 fail-fast configurations, nine endpoint/version successes
and three P384-issuer rejections, caller-array erasure, RSA range narrowing with
PKCS1 first, and independent Python RSA mTLS / Go SM2 TLS/TLCP peers. Independently
signed Go fixtures add 51 mTLS scenarios across file/PEM/DER inputs, including
both endpoint policies, no common RSA/ECDSA scheme, and server-side rejection of
P384-signed client certificates whose issuer is only loaded locally.

### Context protocol-version policy

Crypto/CNet client and server configurations expose `minimum_version` and
`maximum_version`. STANDARD defaults to TLS 1.2 through TLS 1.3; setting only
the minimum to 1.3 or only the maximum to 1.2 restricts every connection using
that context. SHANGMI_TLS13 permits only default/1.3 bounds. TLCP11 requires
default bounds because TLCP is a separate profile, not a TLS version. Unknown
or reversed ranges fail with EINVAL; a known incompatible profile/version
request fails with ENOTSUP before allocation or trust loading.

The selected context initializes only permitted provider variants. The lower
Crypto per-stream range selector can narrow before handshake progress; it
cannot widen the context policy. A DEFAULT bound in that selector resolves to
the corresponding context bound. Failed widening leaves the original stream
state intact. Protocol negotiation never retries another security profile.

Formal CNet coverage includes all nine intersections of default/1.2-only/
1.3-only client and server contexts, exact version assertions and handshake
rejection for both disjoint pairs. Ten configuration negatives use absent
credential paths to verify early rejection. Memory-source Crypto cases verify
failed widening and default selection preserve both TLS 1.2 and TLS 1.3
connections. Independent Python peers exercise explicit bounds in both native
directions; ShangMi and TLCP formal suites retain their profile checks.

This does not add configurable group lists, verification
time/depth/purpose or session restoration.

### TLCP stream qualification

Select `CNET_TLS_SECURITY_PROFILE_TLCP11` on the existing CNet TLS configuration.
The server certificate PEM contains signing then encryption certificates; its
key PEM contains the two matching private keys in the same order. The client
uses an explicit trusted CA and expected DNS/IP identity. The admitted suite
is `TLS_ECC_SM4_GCM_SM3`; CBC-only peers fail negotiation. TLCP client
certificates and server `REQUIRED` client authentication remain unsupported
and fail explicitly.

`saltscore.cnet_tlcp_independent` runs production CNet/NativeIO through the
existing native TLS test executable against test-only
[GoTLCP v1.4.3](https://github.com/Trisia/gotlcp/tree/v1.4.3), using independently
generated SM2 identities. Both directions exchange authenticated application
data and reciprocal close_notify, with one CNet terminal event. Negative
cases cover unknown roots, DNS/IP mismatch, both certificates' validity,
signatures and key usages, missing/reversed/mismatched local dual identities,
CBC-only offers and malformed or wrong-protocol signature lists. Native
failures must occur during handshake without CONNECTED/plaintext events;
timeouts are not accepted as authentication rejection. The test checks the
actual native ClientHello signature extension as well as the independent
client's offer.

This gate covers the server-authenticated TLCP profile. It does not establish
TLCP mutual authentication, TLS 1.3 ShangMi interoperation, revocation-policy
integration or DTLS support. GoTLCP and gmsm are formal test dependencies only;
production continues to link the single packaged GmSSL provider.

### TLS 1.3 ShangMi stream qualification

Select `CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13` for TLS 1.3 with
`TLS_SM4_GCM_SM3`, `curveSM2` and `sm2sig_sm3`. Configure one SM2 signing
certificate and matching key on the server, plus explicit CA trust and the
expected DNS/IP identity on the client. The profile rejects standard TLS
suites/groups, TLCP's signature pair and TLS 1.2 offers.

`saltscore.cnet_shangmi_tls13_independent` uses the existing production
CNet/NativeIO peer and the test-only
[pollux-go v0.5.0 handshaker](https://github.com/iuboy/pollux-go/tree/v0.5.0/tls13gm).
The independent engine owns curveSM2 ECDHE, the SM3 transcript/key schedule,
certificate and CertificateVerify checks, and Finished authentication. A
bounded test adapter supplies TLS TCP records and SM4-GCM protection. It uses
the RFC 8446 `key`/`iv` labels; the engine's unused QUIC initial keys do not
participate in this TCP exchange. There is no provider code shared with GmSSL.

The 21 cases include both native directions, DNS/IP success, encrypted data
and reciprocal close_notify, seven-byte handshake fragments across encrypted
records, untrusted/invalid certificates, forged CertificateVerify and Finished,
wrong version/cipher/signature/group offers, invalid SM2 shares and raw EOF.
Authentication failures must publish no CNet CONNECTED/plaintext events and
must not be timeouts. The explicit IP-SAN check can reject after the provider's
Finished processing while the CNet connection remains in handshake admission.

The formal peer requires Go 1.26; CI selects it from this test module and
caches all independent-peer modules together. The production dependency stays
GmSSL 3.2.0#22. These independent protocol cases qualify server authentication.

For mutual authentication, configure the client's SM2 certificate/key and set
the server's `client_auth` to `CNET_TLS_CLIENT_AUTH_REQUIRED` with an explicit
client CA. `saltscore.cnet_shangmi_required_mtls` runs ten cases with production
CNet/NativeIO/GmSSL at both ends and independently generated SM2 identities.
Distinct server and client roots are supported. Success checks the exact
TLS 1.3 suite, both peer SHA-256 fingerprints, the server certificate's SM3
`tls-server-end-point` binding, bidirectional application data and reciprocal
close. Rejection cases cover missing client certificates, either untrusted
issuer, expired/future client certificates, client KU/EKU and both certificate
signatures. Authentication rejection must occur at handshake admission without
plaintext delivery and must not be a timeout. Every case checks one terminal
event per connection and successful stop/destroy of its transport owners.

`saltscore.cnet_shangmi_mtls_independent` additionally qualifies the native server
against an independent test client. The upstream pollux handshaker has no client
certificate flow, so a finite test-only RFC 8446/8998 state machine composes its
SM2 ECDHE/signature, SM3 transcript/HKDF and SM4 record primitives. The client
verifies server identity, CertificateVerify and Finished before sending its own
certificate flight. CertificateRequest is included in the transcript; client
CertificateVerify uses the client context and the RFC 8998 TLS SM2 identifier.
This peer uses no Core/GmSSL implementation, shares no production code and only
admits the initial full handshake (no HRR, PSK or post-handshake authentication).

The 16 cases cover a verified client with a distinct root, seven-byte encrypted
client-flight fragments, reciprocal close, abnormal raw EOF, missing/invalid
client certificates, forged CertificateVerify/Finished, the wrong signature
context or SM2 ID, TLCP's signature number and a mismatched request context.
The native server checks the peer fingerprint and exact suite. Rejection must
occur before CONNECTED or plaintext and cannot be a timeout; the test also
requires proof that the independent client reached its certificate flight.
Raw-EOF injection waits for the native SEND completion marker after the reply.

`saltscore.cnet_shangmi_mtls_native_client` covers the reverse direction with
19 cases. Its independent server authenticates the native client's exact
certificate, clientAuth purpose, CertificateVerify possession proof and Finished
before exchanging data. The native client validates the server's independent
SHA-256 fingerprint, exact suite and DNS/IP identity. Success includes encrypted
server-flight fragmentation, reciprocal close and checked owner stop/destroy.
Negative cases cover server trust/time/KU/EKU/signature, incorrect DNS/IP,
CertificateVerify context/SM2 ID/scheme/signature and Finished authentication.
Nonempty initial request contexts, absent signature_algorithms and duplicate
signature_algorithms in CertificateRequest must fail before CONNECTED/plaintext;
timeouts cannot count as authentication rejection. The peer confirms that its
negative authentication flight was actually sent.

Both independent mTLS peers use the finite test-only state machine and external
primitives described above.

### TLS 1.3 peer key updates

`saltscore.cnet_shangmi_key_update` covers 15 peer-initiated scenarios: one-way and
requested updates, consecutive requests before an application send, both native
directions and REQUIRED-mTLS server connections. The peer derives each traffic
secret with `traffic upd`, resets that direction's sequence and authenticates
the next records with the new key. A requested response must be encrypted under
the old sending key and precede the next Application Data; automatic local
rotation remains disabled in these tests. Reciprocal close uses the final keys.
Illegal request values, malformed message length and old-key application data
after a valid update must fail the authenticated native stream without delivering
extra plaintext; these rejection cases run with and without mutual authentication.

`saltscore.gmssl_tls_io_abi` also checks one-byte-at-a-time external writes for
both roles with SM4-GCM/SM3 and AES-128-GCM/SHA-256. It authenticates the exact
two-record output and checks that control-record retries report zero application
bytes. All tests link the pinned provider; no second GmSSL build is embedded.

### Application-selected local key rotation

Both Crypto and CNet client/server TLS configurations expose
`key_update_record_limit`. For SHANGMI_TLS13, select a threshold from 1 through
`CRYPTO_TLS_STREAM_KEY_UPDATE_RECORD_LIMIT_MAX` (CNet has the corresponding
`CNET_TLS_KEY_UPDATE_RECORD_LIMIT_MAX`), currently 2^20. Zero disables this
record-count trigger; the independent byte budget and mandatory peer responses
retain their own contracts.
A value above the maximum returns EINVAL. A nonzero threshold with STANDARD or
TLCP returns ENOTSUP before allocation/trust loading: the STANDARD profile can
negotiate TLS 1.2, which cannot honor TLS 1.3 KeyUpdate.

The threshold counts records under the current sending application traffic key,
not bytes, API writes or elapsed time. At the threshold, the next application
send first emits KeyUpdate under the old key, rotates the sending secret and
resets its sequence. Local initiation requests reciprocal rotation; an already
pending peer response can perform the same sending-key transition without
another reciprocal request. Control records are separate overhead. Immutable
TLS contexts own this setting; established connections keep their original
context. No timer or background worker is added.

The same formal CTest adds 12 independent local-rotation scenarios: thresholds
1, 2, maximum and disabled, each with native client, server and REQUIRED-mTLS
server. Five request/reply rounds assert exact update placement, repeated key
transitions, no early update, successful decryption and reciprocal close under
the final keys. CNet callbacks count only completed application writes.
`saltscore.gmssl_tls_io_abi` now covers both local initiation and pending peer
responses under one-byte-at-a-time writes for both roles and both AEAD suites.
Configuration negatives reject unsupported profiles and out-of-range limits
before reading deliberately absent trust/key files.

### Consecutive peer KeyUpdate admission

Set `peer_key_update_limit` in a Crypto/CNet client or server TLS context to
bound consecutive authenticated KeyUpdates in SHANGMI_TLS13. Zero disables the
bound; any nonzero uint32 value selects the permitted count. STANDARD/TLCP
reject a nonzero request with ENOTSUP during configuration. Both update request
kinds count, including responses to locally initiated rotation. Only receiving
nonempty authenticated application data resets the counter; outgoing application
data, repeated progress calls, empty records and other control messages do not.

GmSSL authenticates and parses the record before checking the limit. The excess
update fails before another traffic-secret derivation. Crypto permanently
latches EPROTO; CNet publishes FAILED without delivering subsequent plaintext.
The counter is fixed-size per connection, is owned by its progress thread and
survives partial records and retryable reads. Snapshot replacement affects new
connections; it does not reset existing counters. Mandatory update responses
remain active for admitted updates.

`saltscore.cnet_shangmi_key_update` adds 12 independent scenarios across native
client/server and REQUIRED-mTLS server: the exact two-update boundary twice with
application progress between, disabled admission accepting three updates,
third-update rejection, and rejection despite an intervening empty record.
Failures require EPROTO at the read stage after an authenticated exchange;
timeouts and orderly close do not qualify. Four provider cases cover both roles
and SM4-GCM/AES-GCM with one-byte read budgets; the third update leaves the
receiving traffic secret unchanged after two admitted updates. Public context
tests reject unsupported profiles before loading absent files.

This is a consecutive-update burst bound, not a time/byte rate limiter: a peer
that sends nonempty application records can reset it. Time/byte budgets,
fragmented post-handshake messages, session resumption, DTLS and hardware-backed
keys remain separate work. Additional peer admission is described below.

### Authenticated-peer admission and revocation composition

`crypto/tls_peer_policy.h` defines the provider-neutral `check/retain/release`
contract shared by Crypto streams and `cnet_tls_peer_policy`. Set `peer_policy`
in a client or server TLS configuration to require an additional decision before
handshake completion (and before CNet publishes CONNECTED). NULL keeps mandatory
TLS verification but supplies no additional revocation assurance. Server policies
require REQUIRED client authentication; partial callback descriptors fail at
context creation.

Policies declare `supported_profiles` and `supported_peer_roles` using the
`CRYPTO_TLS_PEER_POLICY_*` bits. Zero means unrestricted in that dimension;
otherwise the selected profile and remote peer role must be included. Unknown
bits return EINVAL; an excluded profile or role returns ENOTSUP during TLS context
creation, before allocation, trust loading or policy retain. A server context
checks the CLIENT role; a client context checks SERVER. These declarations do
not authorize peers or change protocols. Policy decorators must preserve the
wrapped restrictions. Built-in CRL factories declare their exact profile and
configured peer role; their handshake checks still enforce both.

The hook cannot override certificate/hostname/proof-of-possession failures.
It receives the bounded peer-supplied DER chain, peer role and security profile
only after mandatory authentication. The chain is not a constructed trust path:
the policy must select and authenticate issuers and check every certificate
required by its profile. TLCP has separate signing and encryption certificates.
Only return value zero admits. Errors, unknown results and positive values all
reject with ECONNABORTED; retries cannot run the callback again or resurrect the
stream. Application reads/writes remain unavailable after rejection.

Crypto copies the descriptor and retains its context once on successful context
creation. The final release occurs after all streams release the TLS context.
CNet initialization may acquire and release a temporary reference on an outer
allocation failure; it retains nothing on failure. Callers keep ownership of
their original reference. Use immutable snapshots with thread-safe reference
counts, or synchronize shared state: streams on different owners may invoke the
same policy concurrently. The check is synchronous, nonblocking and cannot reenter
the stream or retain chain views. Publish a replacement TLS context for new
connections when changing snapshots; existing connections are not revalidated.

For a direct authenticated SM2 issuer, a Crypto policy can call
`salts_crypto_sm2_check_crl` with its retained complete CRL snapshot, authenticated
issuer, explicit signing ID, validation time, maximum age and rollback floor.
Time acquisition, persistent rollback state and snapshot refresh remain external.
There is no automatic network fetching, OCSP, cache or general path builder.
CNet exposes the data contract without making static Crypto/GmSSL a transitive
link dependency; do not copy those archives into a CNet consumer/plugin.

Formal tests cover two boundaries separately. `saltscore.cnet_tls_ca_san` checks
real-TCP admission, mandatory trust/identity precedence, invalid descriptors and
retained lifetime. `saltscore.cnet_shangmi_required_mtls` checks both authenticated
roles and denial before CONNECTED, including early server-context release.
`saltscore.crypto_tls_shangmi_revocation` drives production Crypto streams over a
bounded in-memory ciphertext transport with independently signed Go fixtures:
both roles accept current CRLs and reject revoked, stale, bad-signature,
rolled-back, wrong-issuer, malformed and future CRLs. An IP identity mismatch
skips the callback, rejected streams remain rejected on retry, and final destroy
releases the retained snapshot. These are 17 scenarios, not independent TLS
engine interoperation or production network CRL distribution. TLCP dual-certificate
revocation has the separate profile and tests described below.

Established streams also latch their first fatal protocol/I/O error. Subsequent
valid handshake, read, write, close-probe and shutdown calls return that same
error without entering the provider, reporting readiness, producing plaintext
or completing an orderly close. Logical pending plaintext/write borrows are
discarded; transport buffers and native requests retain their existing drain
and destruction contract. Queued ciphertext can still be inspected/drained;
historical negotiated metadata is not evidence that the stream remains usable.
Invalid arguments, capacity admission and incomplete progress do not poison an
otherwise live stream.

The formal Crypto fixture peer adds eight established ShangMi failures across
both roles: corrupted AEAD tags and oversized record headers, each first
observed through application read or the close probe. Each checks three rounds
of cross-API retries and retained-policy release. `saltscore.gmssl_tls_io_abi`
adds eight equivalent AEAD failures for standard TLS 1.2/1.3 and both roles.
The regression reproduced continued writes/reads before the fix. This does not
qualify KeyUpdate flood limits or fragmented post-handshake message support.

### Ready-to-configure CNet SM2 CRL snapshots

`cnet_tls_sm2_crl_peer_policy_create` provides a retained immutable policy inside
CNet's existing Crypto owner. Applications link only `Salts::CNet`. Direct Crypto
stream users have `crypto_tls_sm2_crl_peer_policy_create` with the same configuration
and lifetime. The supported profile is RFC 8998 SHANGMI_TLS13, for either server
authentication or REQUIRED client authentication, with one explicitly configured
direct issuer. STANDARD, TLCP and the wrong peer role fail TLS context creation
with ENOTSUP. Paths beyond leaf + optional identical issuer fail the handshake.

Creation copies DER and both explicit SM2 signing identities into one bounded
allocation below 87 KiB. It first authenticates the entire CRL and checks issuer
CA/cRLSign/SKI, signature, supported extensions, entries, validity, maximum age
and minimum CRL number; invalid snapshots fail immediately. This uses
`salts_crypto_sm2_validate_crl`, which authenticates a snapshot without deciding
whether a particular peer is revoked. Every handshake then reads the trusted
host UTC clock again, verifies the leaf signature against the configured issuer
key and certificate-signing ID, and calls `salts_crypto_sm2_check_crl`. Matching
issuer names alone cannot authorize a foreign CA's CRL. The configured peer role
must also match. Clock failure and any unknown/error result deny admission.

For a client verifying a server, after loading and authenticating `issuer_der`
and the local `crl_der`, initialize a reusable TLS client as follows (all status
returns are checked):

```c
cnet_tls_peer_policy policy = {0};
cnet_tls_sm2_crl_config revocation = {
    .size = sizeof(revocation),
    .issuer_certificate = issuer_der, .issuer_certificate_size = issuer_size,
    .crl = crl_der, .crl_size = crl_size,
    .certificate_signing_identity = cert_id,
    .certificate_signing_identity_size = cert_id_size,
    .crl_signing_identity = crl_id, .crl_signing_identity_size = crl_id_size,
    .minimum_crl_number = authenticated_floor, .maximum_age_seconds = 3600,
    .peer_is_server = true
};
int status = cnet_tls_sm2_crl_peer_policy_create(&revocation, &policy);
if (status != SALTS_OK) return status;
cnet_tls_client_config tls = {
    .size = sizeof(tls), .ca_file = ca_file, .server_name = expected_name,
    .security_profile = CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13,
    .peer_policy = &policy
};
status = cnet_tls_client_init(&tls_client, &tls); /* tls_client starts zeroed */
policy.release(policy.context); /* TLS context owns its own reference on success. */
if (status != SALTS_OK) return status;
/* Set connect_options.tls_client = &tls_client for subsequent connections. */
```

For a server, select `peer_is_server=false` and set REQUIRED client authentication
in its TLS configuration. Release the caller's policy reference after server
initialization as above. Input buffers can be released immediately after policy
creation. Destroy the reusable TLS handle when no longer needed; streams retain
their own context references until quiescent destruction. Publish a new policy
and TLS context when refreshing CRLs or advancing the rollback floor. Existing
connections are not revalidated, and old contexts keep their original floor.
The host must maintain an accurate trusted wall clock and authenticate/persist
the floor. No fetching, distribution-point routing, OCSP, general path builder
or automatic connection eviction is supplied.

`saltscore.cnet_shangmi_crl_policy` exercises 29 independently generated fixture
scenarios through the production CNet DSO: immediate invalid-snapshot rejection,
both TCP/mTLS roles, revoked peers, substituted same-name issuers, both signing
IDs, role/identity mismatches and leaf-only/leaf-plus-issuer chains. It overwrites
all original DER/ID buffers and releases the caller's policy reference before
handshake progress; the server TLS facade is released early too. Formal ownership
audits retain the single CNet provider owner. These tests do not qualify TLCP
revocation, live CRL distribution or hardware-backed signing.

### TLCP dual-certificate CRL admission

`cnet_tlcp_sm2_crl_peer_policy_create` (or the direct Crypto equivalent
`crypto_tlcp_sm2_crl_peer_policy_create`) uses the same immutable snapshot
configuration and ownership contract for TLCP11 server authentication. Set
`peer_is_server=true`, create this policy, then attach it to a client configuration
with `CNET_TLS_SECURITY_PROFILE_TLCP11`. The RFC 8998 factory remains separate;
using either policy under the other profile returns ENOTSUP at TLS context
creation, before trust loading or connection establishment.

The policy requires two distinct DER certificates in TLCP wire order: signing,
then encryption, with an optional third certificate equal to the configured
issuer. It checks the signature binding and CRL status of **both** certificates
against that one explicit issuer, certificate-signing ID and complete CRL.
Revocation of either serial rejects before CONNECTED. The check uses one current
UTC timestamp for both certificates. Duplicate/missing leaves, malformed views,
wrong role/profile, substituted issuers and extra chain entries reject. Snapshot
authentication, freshness, minimum-number enforcement, bounded storage and
reference ownership are unchanged from the RFC 8998 policy.

TLCP client authentication remains unsupported: creation with
`peer_is_server=false` returns ENOTSUP before acquiring a snapshot. Separate
signing/encryption issuers or signing IDs, longer paths, CRL fetching/OCSP and
automatic revalidation of established connections are outside this profile.
The current GmSSL TLCP verifier uses one CA for both leaves and the default SM2
certificate-signing ID. Separate issuers/IDs require provider verification work;
adding revocation configuration alone cannot enable them.

Formal `saltscore.cnet_tlcp_crl_policy` adds 15 scenarios with an independent
GoTLCP server and independently signed certificates/CRLs. Real handshakes cover
current/unrelated-serial CRLs, revocation of just the signing certificate, just
the encryption certificate or both, an optional transmitted issuer, signature-ID
mismatch, same-name issuer substitution and IP identity
rejection. Factory tests cover stale/invalid-signature/rolled-back/future CRLs
and unsupported client authentication. Context tests reject a mismatched policy
profile before loading an absent trust file, with no retained reference or
callback. Native handshake failures must report the handshake
stage without CONNECTED/application data; timeouts are not accepted as rejection.
Positive cases exchange data and reciprocal close_notify. The harness also checks
structural/profile negatives using the authenticated DER views, overwrites input
DER/IDs, releases the caller's reference before progress, and verifies final
reference balance. Go dependencies remain test-only; no new provider is linked.

## API use and boundaries

Link `Salts::Crypto` and include the relevant algorithm header. Every operation
returns `SALTS_CRYPTO_OK` or an explicit error; callers must check the result.
SM2 signing always takes an identity. It never substitutes the default identity
or signs without the Z binding. Its signature representation is fixed-width
`r || s`; the existing ASN1 signature helpers handle DER at format boundaries.

SM4 AEAD callers must provide a unique nonce per key and consume plaintext only
after successful authentication. Raw SM4 modes and ZUC encryption do not
authenticate messages. ZUC's API handles one bounded message per invocation;
calling it repeatedly with the same key/IV is not streaming continuation.
Key storage, rotation and hardware authorization remain explicit application
or key-service responsibilities. Public headers document sizes and ownership.

`crypto/sm9.h` uses separate signing and encryption master keys. A key service
extracts the user's private key for an explicit identity; applications retain
the master public key and clear each owned private-key copy after use. Public
key structs contain canonical point bytes, never provider structs or handles.
Master private keys and extracted keys require protected application storage;
this API does not implement a protected key-file container.

SM9 XOR encryption authenticates with `SM3(C2 || K2)` and releases plaintext
only after checking the tag. Its bounded plaintext is 1..255 bytes. Composition
uses GmSSL KEM and the existing SM3 facade, with DER owned by Salts::ASN1;
GmSSL's native HMAC-based SM9 encryption wrapper is not used by this API.
Raw KEM derives 1..1024 bytes and is not sender authentication or key
confirmation: changing an identity or valid capsule can yield a different key
successfully. A protocol must authenticate/confirm that key before using it.

`crypto.algorithms.sm9_public` checks the published examples also exercised by
[gmsm v0.41.1](https://github.com/emmansun/gmsm/blob/v0.41.1/internal/sm9/sm9_test.go).
`crypto.algorithms.sm9_provider_failure` resolves the installed static provider's
RNG symbol only inside that formal test executable, allowing fixed nonces and
injected failure without modifying production RNG behavior. It additionally
checks an on-curve G2 point outside the prime-order subgroup, an infinity
recipient, zero-nonce retry/exhaustion and failure erasure. These functional
tests do not establish constant-time execution of the underlying pairing and
scalar arithmetic; side-channel qualification remains a production gate for
deployments exposing private-key operations to local or timing attackers.

### SM2 key containers

`crypto/sm2_keys.h` imports/exports SPKI and PKCS#8 through the canonical
Salts::ASN1 owner. The bounded profile uses id-ecPublicKey with curveSM2,
PrivateKeyInfo version 0 and ECPrivateKey version 1. Outer curve is mandatory;
optional inner curve/public key must match the derived key. No attributes,
unknown fields, compressed points, other curves or noncanonical encodings are
accepted. Public-key import is structural/curve validation, not identity trust.
Private scalars through N-1 are admitted for exchange; signing excludes N-1.

EncryptedPrivateKeyInfo uses PBES2 with explicit PBKDF2-HMAC-SM3 and SM4-CBC.
Export draws a fresh 16-byte salt and IV. Passwords are explicit opaque bytes
(1..1024), so embedded NUL is preserved. The caller selects iterations within
10000..16777215; import additionally requires an explicit maximum work factor
and rejects higher document values before running the KDF. This ceiling is
not a recommendation to perform maximum-cost derivation on a network worker.
Callers schedule this synchronous operation outside latency-sensitive I/O.

Output is caller-owned (SPKI 91, private PKCS#8 150, encrypted PKCS#8 320-byte
capacity). No heap, file, PEM parser or retained input exists. Admission errors
preserve outputs. Admitted malformed/key/password failures erase outputs;
decrypted DER, password-derived keys and secret staging buffers are erased on
all completion paths. No plaintext is returned before padding, canonical DER,
scalar and embedded public-key checks finish.

The CBC key-file profile provides password-based confidentiality, not a MAC,
provenance or authenticated storage. Applications must separately protect stored
files and bind the imported public key to a trusted identity. A successful
import is not certificate validation. Do not expose this variable-time file
operation as a remote password/decryption service. SM2 side-channel and
certificate/CMS qualification remain separate gates.

The format follows [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958),
[RFC 5915](https://www.rfc-editor.org/rfc/rfc5915) and
[RFC 8018](https://www.rfc-editor.org/rfc/rfc8018) composition, with GmSSL's
HMAC-SM3 and SM4-CBC identifiers. Missing PBKDF2 PRF means HMAC-SHA1 under
RFC 8018 and is rejected, never silently interpreted as HMAC-SM3. Formal tests
cover native GmSSL interoperation and independent Python hashlib/cryptography
encryption/decryption, including optional inner fields, PRF NULL/absent
parameters and omitted keyLength. Test-only Python providers introduce no
explicit native OpenSSL/BoringSSL dependency.

### SM2 certificate primitives

`crypto/sm2_x509.h` consumes one canonical DER certificate up to 4096 bytes.
`public_key` extracts a validated, finite curveSM2 point using the existing
id-ecPublicKey/curveSM2 SPKI profile. `matches_private_key` verifies the local
private scalar derives that subject public key. Neither operation verifies the
certificate signature or establishes remote possession of the key.

`verify_signature` checks SM2-with-SM3 over the exact encoded TBSCertificate,
using the caller's explicit issuer public key and binary signing identity
(1..8191 bytes). It rejects incorrect parameters/OIDs, inner/outer algorithm
mismatch, noncanonical signature integers, out-of-range scalars, tampered
content and wrong issuers/identities. Parameters may be absent or NULL, but
inner/outer AlgorithmIdentifier encodings must match exactly. A subject key of
another algorithm does not prevent checking its issuer's SM2 signature.

Signing identities are not interchangeable. [RFC 8998 section 3.2.1](https://www.rfc-editor.org/rfc/rfc8998.html#section-3.2.1)
distinguishes certificate signing identities from the TLS handshake identity;
CAs can select their own certificate signing identity. The API does not guess
or retry identities. A published OpenSSL 3 fixture signs with an empty identity;
the formal test independently establishes that fact with native primitives and
checks rejection under the supported nonempty-ID profile. This fixture also
uses an alternate id-SM2 SPKI OID, outside the extraction profile.

All operations are synchronous, allocation-free and borrow input only during
the call. Extraction returns an owned 65-byte public key; admitted failures
clear it, while invalid buffer admission preserves it. No pointer to a parsed
view, provider key or temporary private material escapes the API.

Successful signature verification does not check dates, CA constraints, KU/EKU,
critical extensions, SAN/hostname, issuer-name chaining, policy or revocation.
It does not select a trust anchor. Applications must complete those checks
before authenticating a peer; a self-signature does not establish trust.
Formal fixtures deliberately include expired certificates and an unsupported
subject curve with a valid issuer signature to preserve this separation.
The TLS trust path is unchanged; full SM2 certificate/CMS profile qualification
remains open in #219.

`crypto.x509.sm2_signatures` contains the native positive/negative cases and
the attributed OpenSSL fixture from [gmsm v0.41.1](https://github.com/emmansun/gmsm/blob/v0.41.1/smx509/x509_additional_test.go).
`crypto.x509.sm2_independent` uses a pinned, test-only gmsm Go module to sign
fresh certificates and call the production-linked native peer through pipes.
It covers standard, embedded-NUL and maximum identities, separate issuer and
subject keys, tampering and authentication negatives. Go is required for native
formal tests; Android remains build-only. CI caches the Go modules/builds with
the existing SCTP peer. No Go code or new provider is linked into production,
and no extra consumer/smoke CMake project is created.

### Pinned SM2 peer trust policy

`crypto/sm2_trust.h` adds a restricted path-validation profile for applications
that already authenticate an expected peer public key and an explicit CA anchor
through configuration. The same `salts_crypto_sm2_validate_pinned_chain` API
accepts server-signing or client-signing purpose and either external revocation
checking or an explicit decision not to check revocation. Zero/default policy
values are rejected. The existing TLS constructor/handshake trust path is not
changed by this API.

Pass one to four non-anchor certificates, leaf first, with an explicit SM2
signing identity for each signature. The anchor is a separate configured
certificate, not a root selected from peer input. Each certificate is bounded
to 4096 bytes and must have a validated curveSM2 key and canonical v3 structure.
Every child signature and exact encoded issuer/subject Name link is checked.
Empty/malformed RDNs, duplicate certificates and self-issued intermediates are
rejected; no path search or DN normalization is performed. An anchor's
self-signature is not its trust source and is not required to verify.

Validation time is supplied explicitly as Unix seconds, with Gregorian date
checks and inclusive validity boundaries. Anchor and intermediates require
critical CA=true basicConstraints, keyCertSign and sufficient pathLen; CA EKU,
when present, must permit the requested purpose. The leaf must be an end entity
with digitalSignature, no certificate/CRL signing usage and the exact requested
serverAuth/clientAuth EKU. anyExtendedKeyUsage alone is insufficient. This
profile deliberately applies these constraints and time checks to the anchor
as well, rather than inheriting implicit platform trust-store exceptions.

Unsupported critical extensions are rejected. Name constraints, certificate
policies, policy mappings/constraints and inhibitAnyPolicy are also rejected
when noncritical. Noncritical SAN/SKI/AKI and unrelated metadata do not replace
identity checking: the leaf public key must equal the authenticated expected
key. Critical SAN and SAN-only empty-subject certificates are outside this
profile. DNS/HTTP hostname identity, alternate trust paths, TLCP encryption
certificates and unrestricted PKIX policy processing remain separate work.

External revocation mode invokes the caller's synchronous callback only after
all other checks pass, once per non-anchor certificate in leaf-first order.
Only OK admits a certificate; revoked, unknown, stale or unavailable status
must fail. The callback owns freshness and CRL/OCSP authenticity validation;
it can call the explicit CRL API below. The chain validator does not fetch or
parse revocation data itself. NOT_CHECKED requires NULL
callback/context and provides no revocation assurance. There is no fallback
from unavailable status to acceptance.

All inputs remain immutable and borrowed only for the call; the callback must
not retain spans or mutate the policy, chain or output. Core allocates no heap,
reads no clock and performs no network/file I/O. Output is a caller-owned
65-byte leaf key, published only after every required check succeeds. Invalid
pointer/size/overlap/policy admission preserves it; admitted rejection clears
it. CNet/application owners still control scheduling, peer proof of possession,
session binding, deadlines and generation lifetime.

Formal C admission tests and independently generated gmsm path tests cover
depths one through four, both purposes, per-issuer binary identities, Gregorian
dates and UTC/GeneralizedTime boundaries, missing/wrong CA and usage constraints,
unknown/unsupported extensions, invalid Names, wrong pins/anchors/signatures,
callback ordering/rejection and failure erasure. The checks implement this
documented restricted profile using [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html)
certificate fields; they do not claim a general WebPKI validator or completion
of all certificate/CMS/TLS qualification in #219.

### Complete direct SM2 CRLs

`crypto/sm2_crl.h` supplies `salts_crypto_sm2_check_crl` for the pinned-chain
policy's external revocation callback. It checks an already authenticated path
certificate against an explicitly supplied, complete direct-issuer SM2/SM3 CRL.
This operation does not establish issuer trust or replace certificate signature,
path or identity validation. The pinned-chain validator completes those checks
before calling the revocation callback and withholds the leaf key until every
callback succeeds.

The issuer needs a valid v3 CA certificate, critical CA basicConstraints,
cRLSign and a nonempty subject key identifier. The CRL's issuer Name must match
the certificate issuer and CA subject exactly; its keyIdentifier-only AKI must
match the CA SKI. The SM2 signature uses the explicit CRL signing identity,
which may differ from certificate-signing identities. No identity retry occurs.

The caller supplies validation time, nonzero maximum CRL age, and a minimum
acceptable CRL number. Acceptance requires `thisUpdate <= time < nextUpdate`,
age within the limit, and number at or above the floor. The floor belongs to
authenticated, persistent application state; a stale floor can still admit an
older CRL within its validity window. This synchronous API reads no clock,
fetches no URL, retains no data and updates no cache or rollback state.

The profile is bounded to 65536 CRL bytes, 256 entries, 64 extensions per list,
positive certificate serials of at most 20 DER bytes, and uint64 CRL numbers.
It requires canonical v2 DER with nextUpdate, AKI and CRL number. Duplicate
serials/extensions, invalid dates, future revocations, malformed or unsupported
entries, and unknown critical CRL extensions reject. Every listed serial,
including certificateHold, rejects the certificate. removeFromCRL is not a
way to restore a certificate in this full-CRL profile.

Delta/freshest CRLs, issuingDistributionPoint and indirect certificateIssuer
extensions are rejected even when noncritical. Certificates with CRL
distribution/freshest points are also outside this profile. Entry extensions
support reasonCode only (0..6, 9, 10); invalidityDate and other entry semantics
are not silently accepted. The implementation follows the relevant fields of
[RFC 5280 section 5](https://www.rfc-editor.org/rfc/rfc5280.html#section-5), with
these explicit restrictions; it is not a general CRL/OCSP distribution service.

A caller can select a CRL policy for each already authenticated issuer:

```c
struct revocation_snapshot {
  salts_crypto_sm2_crl_policy by_depth[SALTS_CRYPTO_SM2_TRUST_MAX_CHAIN];
  size_t count;
};

static int check_revocation(void *context, size_t depth,
    const salts_crypto_sm2_cert_span *certificate,
    const salts_crypto_sm2_cert_span *issuer, int64_t now) {
  const struct revocation_snapshot *snapshot = context;
  if (depth >= snapshot->count) return SALTS_CRYPTO_EVERIFY;
  return salts_crypto_sm2_check_crl(certificate, issuer, now,
      &snapshot->by_depth[depth]);
}
```

Set the trust policy to `SALTS_CRYPTO_SM2_REVOCATION_EXTERNAL` with this callback
and a complete immutable snapshot, including its borrowed DER and identity
bytes, alive until validation returns. Missing, expired or invalid CRLs must
remain failures; refreshing the snapshot is application work. Each direct
check returns OK only for a valid CRL with the serial absent. An application
using this operation outside the pinned-chain callback must first authenticate
the certificate path and issuer itself.

Formal `crypto.x509.sm2_crl_independent` uses the existing pinned test-only
gmsm module to generate and verify independent CRLs, then exercises both the
public check and its actual pinned-trust callback. It covers freshness/number
boundaries, custom binary/maximal SM2 identities, supported revocation reasons,
malformed/scope/signature/issuer negatives, entry/extension limits and withheld
or erased key output. No production provider or test dependency was added.

### SM2 confirmed agreement

`crypto/sm2_exchange.h` implements full curveSM2 key agreement, including
`t=d+xbar*r mod n`, the peer's static/ephemeral point combination, Z(identity,
static-key) binding, SM3 KDF and both confirmation values. It requires the
caller's authenticated peer static public key and explicit identities; it does
not establish trust through certificate inspection or by receiving a key.
Only the fixed curveSM2 domain (cofactor 1) is admitted. Public derivation and
exchange admit private scalars through N-1; signing continues to reject N-1.

The start/respond/finish sequence follows the SM9 confirmed exchange lifecycle
below, with a caller-owned 1536-byte context, identities of 1..8191 bytes and
session keys of 1..1024 bytes. Identities are consumed into Z hashes during
admission; no identity/private-key buffer is borrowed. Only the combined scalar
and transcript needed for the next step are retained. A responder retains its
pending derived key until initiator confirmation. Both finishes erase context,
including on admitted peer/state failure; clear cancels a pending exchange.
Parameter/overlap errors preserve live state. Zero nonces/combined scalars have
bounded retries; infinity combinations and all-zero derived keys fail.

`crypto.algorithms.sm2_exchange_vectors` verifies shares, the session key and
both confirmation values from [GB/T 32918.5 Annex B](https://www.gmbz.org.cn/upload/2018-07-24/1532401863206085511.pdf),
plus an independent non-default-identity key vector from
[gmsm v0.41.1](https://github.com/emmansun/gmsm/blob/v0.41.1/sm2/sm2_keyexchange_test.go).
Its RNG override exists only in that formal test executable. Production uses
the provider CSPRNG; no duplicate curve/arithmetic implementation is built.
`crypto.algorithms.sm2_exchange` covers identity/static-key authentication
negatives, phase/replay, input ownership, capacity, cancellation and erasure.
These tests establish functional correctness; private-key arithmetic still
needs the separate side-channel qualification gate, as does SM9.

### SM9 confirmed exchange

`crypto/sm9_exchange.h` supplies the complete two-party confirmation sequence.
Generate a separate `SALTS_CRYPTO_SM9_EXCHANGE` master and extract keys with
`salts_crypto_sm9_exchange_extract` (`hid=0x02`). Encryption keys (`hid=0x03`)
cannot be reused: admission checks the private key against the local identity,
master public key and exchange purpose, including subgroup checks.

Each party owns one zero-initialized 2048-byte context, used from one thread.
Identities are copied (1..255 bytes each); the session key is bounded to
1..1024 bytes. No caller buffer is retained and no allocation or I/O occurs.

1. Initiator calls `exchange_start`, retaining its context and sending RA.
2. Responder calls `exchange_respond`, retaining its context and sending RB/SB.
   Its pending key remains internal until SA is verified.
3. Initiator calls `exchange_finish_initiator` with RB/SB. Only a valid SB
   releases its session key and SA. It sends SA to the responder.
4. Responder calls `exchange_finish_responder` with SA. Only valid SA releases
   its session key. Both finish calls erase their context on success or an
   admitted protocol/state failure. Invalid buffer admission leaves state intact.

Both parties must agree identities, master, key length and application profile.
The standard confirmation transcript does not encode the requested key length;
the enclosing authenticated protocol must agree that parameter. Confirmation
does not acknowledge SA delivery or business success. An all-zero derived key
fails the exchange; restart with fresh shares, never reuse the old nonce.

Call `exchange_clear` at cancellation/deadline or when abandoning a pending
exchange. CNet/application owners remain responsible for message framing,
generation routing, retransmission/deadlines and retained-send lifetime. These
pure Crypto operations do not by themselves implement a CNet channel, DTLS,
SCTP integration or a negotiated network profile. GmSSL's unfinished exchange
entrypoints are not called, and no second copy of its primitives is compiled.

RFC 8998 defines TLS 1.3 suites. Its registry marks these suites and curveSM2
as not DTLS-OK; this implementation must not simply reuse their identifiers in
DTLS. See https://www.rfc-editor.org/rfc/rfc8998.html#section-4 .

## Completion gates

1. Every advertised operation has public API known-answer, invalid-input and
   failure-atomicity tests, with independent implementations or published vectors.
2. Peer-facing profiles have real positive and authentication-negative
   interoperation, lifetime/cancel/drain and replay/timeout tests where relevant.
3. Exact-head native CI passes on Windows/Linux/macOS and their supported
   architectures, plus the applicable sanitizers. Android compilation does not
   stand in for device execution.
4. Hardware-backed capability is qualified with the actual selected SDF/SKF
   module/device and non-exportable key lifecycle. Algorithm availability alone
   is not a product certification statement.

All tests belong to the root formal CTest graph. Use the versioned user presets
for the full build and tests; no extra consumer or smoke CMake projects.

## Immutable client identity selection

`crypto_tls_stream_client_config` and `cnet_tls_client_config` accept an ordered
`identities`/`identity_count` set of up to four file or memory credentials. It
excludes the top-level identity fields; NULL/0 preserves those fields. Descriptor
validation precedes file I/O. Every identity must load before the context is
published; late failure releases the entire unpublished context. Inputs can be
erased immediately after creation / `cnet_connect`. Encoded chains share the
provider's 8192-byte aggregate capacity, including three bytes per chain.

TLS 1.2, TLS 1.3 and ShangMi TLS 1.3 select the first configured identity compatible
with the peer's CertificateRequest, local signature policy and chain signatures.
CA hints can name root or intermediate issuers; an empty/absent hint does not
restrict issuers. Selection and signing-key index belong to the connection,
never to the shared immutable context. No request sends no identity; no match
sends an empty Certificate and omits CertificateVerify, as required by
[RFC 5246 section 7.4.6](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.6)
and [RFC 8446 section 4.4.2.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2.3).
The remote server decides whether to accept missing client authentication. This
does not weaken the native client's mandatory server authentication.

The shared GmSSL #29 provider completes TLS 1.2 selection across all configured
chains and preserves the matching private-key index; TLS 1.3 uses its existing
selector with explicit empty-selection state. No production dependency is added.
TLCP client authentication remains ENOTSUP. No handshake callback, file reads,
hot reload, post-handshake authentication or established-connection mutation.

Formal CTest `saltscore.cnet_tls_client_identities` uses Go's independent standard
TLS engine to check exact peer certificates, CA selection, local order, empty
hints, incompatible first keys, no-match/no-request non-disclosure and range
negotiation. File/PEM/DER tests erase input storage before native progress.
`saltscore.cnet_shangmi_mtls_native_client` adds independent SM2 CA selection for
both positions and all input formats, plus malformed CA hints with and without
compatible signature schemes. Native API cases reject malformed lists before
I/O and verify four identities, late load failure and unsupported TLCP.
Cross-platform/sanitizer qualification is the PR's normal LLVM CI gate.

## Separate certificate signature policy (TLS 1.3)

Crypto and CNet client/server configurations accept an immutable
`certificate_signature_algorithms` / `certificate_signature_algorithm_count`
list. NULL/0 retains the shared handshake/certificate policy. An explicit list
is copied before publication, contains at most four unique supported schemes,
and independently controls CertificateRequest/ClientHello certificate offers,
local identity selection and remote chain signature admission. Trust, hostname,
purpose and revocation checks remain mandatory.

STANDARD requires explicit TLS1.3-only bounds. SHANGMI_TLS13 accepts SM2/SM3.
TLS1.2/ranges and TLCP reject explicit certificate lists with ENOTSUP before
trust/credential I/O. RSA-PSS certificate signatures are not supported by this
slice; RSA-PSS handshake signatures remain available. The STANDARD certificate
list admits PKCS1/SHA256 and ECDSA P256/SHA256 or P384/SHA384. Invalid counts,
pointer/count mismatches and duplicates return EINVAL. iOS implicit system trust
rejects explicit policy because issuer keys needed for final signature admission
are unavailable; explicit anchors work normally.

The TLS1.3 provider sends extension 50 independently and uses the same copied
list for chain selection and verification. If a peer omits extension 50, its
signature_algorithms offer also constrains its certificate acceptance, per
[RFC 8446 section 4.2.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3).
Both this peer constraint and local policy must match; an empty intersection
never falls back to a wider list.

## Retained certificate validity diagnostics

`crypto_tls_diagnostic.reason` now distinguishes `CRYPTO_TLS_FAILURE_EXPIRED`
and `CRYPTO_TLS_FAILURE_NOT_YET_VALID` when GmSSL's actual certificate check
rejects the current host time. Crypto maps the provider result, and CNet retains
the same owned value in the terminal error. Existing enum values remain stable.
No post-failure date rescan or interpretation of a remote alert is used. The
first failure remains latched across retries and TLS object teardown.

The provider retains its existing verification order, clock and inclusive
notBefore/notAfter checks from
[RFC 5280 section 4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5).
Malformed dates/intervals, parsing and usage failures keep their existing generic
category (TLS1.2 can reject malformed Certificate data before verification and
report HANDSHAKE); an unavailable clock remains CERTIFICATE. Native platform trust can still report its
existing platform category. These values do not add a validation-time override
or change admission. The certificate position stays SIZE_MAX when unavailable;
no leaf/issuer position is guessed from the error category.

Formal tests use independently signed RSA/P256 certificates for TLS1.2/1.3,
file/PEM/DER anchors, expired/future leaf and local anchor, and malformed validity
intervals. Independent SM2 peers verify both mTLS roles and generic usage
failures; TLCP peers cover signing and encryption leaf validity separately.

## Retained certificate signature failure positions

`CRYPTO_TLS_FAILURE_CHAIN_SIGNATURE` now retains the zero-based presented-chain
index recorded at the actual failed certificate-signature check. It identifies
the certificate being verified, rather than its issuer: standard TLS/ShangMi
leaf 0 and subsequent intermediates, or TLCP signing leaf 0 and encryption leaf 1.
Crypto copies this owned diagnostic into the existing first-failure value; CNet
retains it in `cnet_error.tls` across transport/TLS destruction.

This does not change verification order, trust selection, time/purpose checks or
error categories. If a top certificate cannot be matched to a verifying local
anchor, the existing TRUST_ANCHOR result and unknown index remain. Local-only
anchors and remote alerts do not supply a presented-certificate position. No
chain rescan or position inference runs after failure.

Formal independent peers corrupt only certificate signature bytes while keeping
keys, authenticated handshake signatures and chain structure intact. Tests cover
RSA/P256 TLS1.2/1.3, both native mTLS endpoint roles, two intermediate levels,
ShangMi mTLS, TLCP dual leaves, and file/PEM/DER trust/identity inputs. Undamaged
controls and top-certificate root-selection failures keep their prior behavior.
The CNet probe checks the retained value again after owner destruction.

## Local sending-key rotation interval

`key_update_interval_ms` is copied into the immutable SHANGMI_TLS13 client/server
context. Zero disables it; every nonzero uint32 value is an interval in
milliseconds. STANDARD/TLCP reject nonzero values with ENOTSUP before trust I/O
or retained-policy callbacks. This is a local age policy, independent of record
and plaintext-byte budgets; any enabled trigger requests one KeyUpdate.

The existing exclusive progress owner starts the interval when the provider
handshake completes. Before preparing each new application record, it samples
a monotonic clock and checks `now - origin >= interval`. Pending application
ciphertext finishes unchanged even if the interval expires during backpressure.
Pending KeyUpdate ciphertext also finishes before new-key application data.
Successful local sending-key derivation starts the next interval, including a
mandatory peer response. Receiving a peer's new key does not reset local age.
Shutdown retains the existing authenticated-close behavior without an age-triggered
update. No idle traffic, deadline scheduling or background thread is introduced.

One fixed origin, last-observed sample and initialized flag belong to each
connection. The provider stores an immutable clock callback and borrows its user
context for the TLS context lifetime; Crypto supplies a stateless internal callback, never an application
pointer. Windows uses GetTickCount64; Unix uses CLOCK_MONOTONIC. Clock resolution
and system-suspend accounting follow the selected OS clock, rather than civil
time or certificate verification_time. Clock failure, a backward sample or use
before timer initialization is fatal before further application encryption.
Comparing before subtraction avoids overflow; deadline addition is unnecessary.
Failures preserve the existing first-fatal-error latch and quiescent cleanup.

The design extends the existing provider control-record state machine rather
than introducing a second Core-side age counter, which could miss mandatory
responses. No new buffer, allocation, queue or worker is needed. A very short
interval can cause frequent updates and reduce useful throughput; it is not an
idle-update delivery guarantee or peer-flood limiter. Deterministic provider tests
control the clock, while independent peers exercise the real clock through CNet.
For example, set `key_update_interval_ms = 60000` before context creation to
check for local rotation at the next application record after one minute.
Applications migrate by setting this scalar on either context; zero restores
the previous behavior. Downgrading the provider requires reverting the matching
Core header/implementation and dependency pin together.

See [RFC 8446 section 4.6.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6.3)
and [GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64).

## Local sending-key plaintext byte limit

The immutable client/server `key_update_byte_limit` adds a per-sending-key
application-plaintext budget for SHANGMI_TLS13. Zero disables this budget;
1..2^34 bytes is accepted. Larger values return EINVAL, and nonzero values for
STANDARD/TLCP return ENOTSUP before trust/identity I/O or policy retention.
The record-count limit remains independent; either exhausted budget triggers
one KeyUpdate before more application data is encrypted. This is a local key
usage policy, not a received-update rate limiter or a delivery counter.

Counting whole writes would depend on application chunking and mishandle partial
I/O. Rounding the limit to record size would exceed a requested byte budget.
Instead, GmSSL's existing record builder limits each application prefix to the
remaining budget. The provider increments one fixed uint64 counter only after
successful record encryption, then retains the same bounded pending ciphertext
through partial writes. Re-entering the send path neither counts nor encrypts
that record again. A small limit can split one application write across records;
stream byte order and retained-input completion semantics remain unchanged.

The fixed progress owner alone mutates the counter. Local sending-key derivation
resets it, including a mandatory peer-request response; receiving a peer's new
sending key does not reset this independent local budget. The existing pending
KeyUpdate control path must finish before any new-key application record.
Control/alert records do not consume application bytes. No extra buffers,
queues, timers, background work or unbounded storage are introduced.

The provider rejects an impossible counter greater than the configured budget
before subtraction. Encryption failure preserves normal fatal error propagation;
KeyUpdate secret/key derivation errors also terminate before control output or
budget reset; an incomplete transition is not resumed. Crypto's first-failure
latch prevents continuing that stream. Budgeting is a
finite upper bound, so no saturating arithmetic is used. See
[RFC 8446 section 4.6.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6.3)
for key-update ordering and mandatory peer responses.

The existing context configuration owns the copied scalar; callers may erase it
after initialization. For example, set `key_update_byte_limit = 1024 * 1024`
and optionally `key_update_record_limit = 4096` before initializing a ShangMi
client/server context. Existing zero-initialized configurations keep their prior
behavior. Applications rebuild against the extended configuration structs; no
parallel versioned interface or hot update is introduced. Returning the field to
zero at configuration time restores the prior byte-policy behavior. The optional
interval above composes with both budgets; general post-handshake fragmentation
remains separate work.

## Established TLS 1.3 duplex record ownership

A formal isolated-KeyUpdate regression exposed shared provider record state:
`tls13_recv` could consume the update and leave `recordlen = 5` while waiting for
another header. A subsequent send interpreted that receive state as outgoing
ciphertext, bypassed the new-record policy checks and returned zero-byte success.
The same shared buffers could corrupt partial incoming/outgoing records and
unconsumed plaintext when the exclusive owner interleaved read and write calls.
Single-owner progress does not imply half-duplex application traffic.

The established TLS 1.3 receive path now owns one fixed `TLS_MAX_RECORD_SIZE`
ciphertext array plus receive offset/remaining/plaintext-length scalars, separate
from the existing send/handshake record fields. Received plaintext uses the
existing `databuf`, so retained `data/datalen` cannot alias outgoing plaintext.
The receive state machine and record-ready gate keep their current authority.
No record is copied to another queue, no capacity grows and no new allocation
occurs during progress. All profiles share the TLS_CONNECT ABI, so their fixed
connection allocation increases by one record array and its metadata/alignment, although only TLS1.3
uses the new receive buffer. This correctness cost is preferable to
serializing duplex traffic or overwriting an admitted pending operation.

Handshake parsing retains its existing buffers. Existing NewSessionTicket
processing reads the received plaintext buffer; this ownership fix does not
qualify session restoration. Early-data reception uses the same receive owner;
0-RTT remains unqualified. Fatal errors and destroy still follow the existing
terminal latch/quiescence contract. Formal tests must cover isolated control
records followed by sends, partial receive headers/bodies interleaved with writes,
partial outgoing records interleaved with reads, and retained plaintext tails.
