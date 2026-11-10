# ShangMi coverage and production qualification

GmSSL remains the production provider for national cryptography. Salts::Crypto
owns the application API; CNet owns transport progress and lifetime. Applications
select an explicit protocol/security profile and use the same CNet ownership,
buffering and failure contracts. No profile silently changes provider, trust
source or falls back to plaintext.

## Current software coverage

The local completion pass keeps all remaining software work on one branch until
implementation and formal tests are ready together. Credential objects own bounded,
decrypted immutable material with explicit references; TLS contexts import independent
provider key state. New policy inputs are validated before trust I/O and copied at
initialization. Datagram security must preserve message boundaries, fixed progress
ownership, bounded reassembly/replay/retransmission state, and native storage until
real completion. CMS, PKIX and revocation workflows must authenticate their inputs
before publication, and cached validation never bypasses freshness or trust policy.
Session restoration must bind the authenticated peer, profile, hostname, ALPN and
verification policy; 0-RTT additionally requires bounded replay protection. Functional
completion and platform/side-channel qualification are recorded separately. SDF/SKF
and hot update remain outside the authorized implementation scope.

| Capability | Public Core interface / status | Formal evidence |
|---|---|---|
| SM2 | Raw private/public keys, identity-bound SM3 signatures, canonical DER public-key encryption | Standard generator, signature identity/message negatives, invalid scalar/point, maximum plaintext, corrupted/truncated ciphertext |
| SM3 | Streaming and one-shot digest/HMAC; HKDF; PBKDF2 | Known answers, fragmented input, erased state, invalid reuse, overlap/length/iteration rejection |
| SM4 | ECB/CBC without padding; CTR/OFB/CFB8/64/128; XTS; GCM/CCM | Block and independent mode vectors, RFC 8998 GCM/CCM vectors, partial segments, XTS ciphertext stealing, bad tag erasure, counter wrap rejection |
| ZUC | ZUC128/256 whole-message encryption and bit-length MAC/verification | Known keystream/MAC answers, all tag sizes, ignored unused final bits, corrupt tag, key/length rejection |
| SM9 signature/encryption/KEM | Public identity-based signing, XOR encryption and KEM; fixed canonical key points and DER messages | Published signature/KEM/encryption vectors, scripted nonce/failure paths, finite prime-order subgroup admission, DER/tamper/identity negatives and output erasure; cross-platform CI required |
| SM9 key exchange | First-party bounded exchange over existing GmSSL primitives, with mandatory mutual key confirmation and distinct exchange keys | Published session-key and both confirmation vectors; identity/master/purpose binding, wrong phase, forged/replayed confirmations, RNG failure, cancellation and erasure; cross-platform CI required |
| SM2 full authenticated key exchange | GB/T 32918.3 curveSM2 agreement with explicit static peer trust, Z bindings and mandatory mutual confirmation | GB/T 32918.5 Annex B shares/key/confirmation vectors; independent gmsm key vector; identity/static-key mismatch, invalid points, infinity sum, zero combined scalar, RNG/phase/replay/erasure; cross-platform CI required |
| SM2 key containers | Canonical SPKI and PKCS#8 import/export; explicit PBES2 PBKDF2-HMAC-SM3/SM4-CBC or HMAC-SHA256/AES-256-CBC password protection | Public API negatives, RNG failure, GmSSL SM3/SM4 key-file interop and independent Python bidirectional interop for both profiles; new AES256 profile requires cross-platform CI |
| SM2 certificate primitives | SM2 public-key extraction, local private-key binding and explicit-issuer signature verification | Native and independent gmsm certificates; ID/issuer/DER/algorithm/tamper negatives; these operations do not validate certificate trust |
| SM2 pinned-peer trust | Explicit bounded chain/anchor, leaf-key identity, validation time, signing purpose and revocation policy | Independently signed paths, CA/pathLen/KU/EKU/time/constraint negatives, callback gating and failure erasure; cross-platform CI required |
| SM2 complete direct CRL | Explicit issuer/SM2 signing ID, full-CRL scope, time/age/number policy and serial checking | Independent gmsm CRLs, real pinned-trust callback, revoked/stale/rollback/scope/DER negatives; cross-platform CI required |
| SM2 direct-issuer OCSP | Bounded SM2/SM3 BasicOCSPResponse checking and immutable ShangMi/TLCP admission snapshots | Independent ASN.1/SM2 responses and pollux OCSP producer/parser; actual ShangMi mTLS and TLCP dual-certificate data/close; explicit no-check delegated responders; stapling/distribution remain separate |
| CMS authenticated envelopes | Local finite RFC5083 container with SM2 key transport and SM4-GCM; authenticated pinned recipient paths | Independent Go ASN1/SM2/SM4 bidirectional tests, maximum signed payload composition, recipient-trust/corruption/output-erasure gates; sender identity requires inner SignedData |
| CMS signed data | Local bounded SM2/SM3 RFC-content and ShangMi-content profiles; explicit pinned certificate trust | Independent gmsm/PKCS7 attached/detached signing and verification; rejection/output-erasure/callback gates; general PKIX and encryption workflows remain separate |
| TLCP 1.1 ECC_SM4_GCM_SM3 | Explicit CNet client/server profile with dual SM2 server certificates | Independent GoTLCP bidirectional handshake/data/close, CA/DNS/IP/time/signature/KU negatives, local dual-identity admission and signature-extension/cipher rejection; cross-platform CI required |
| TLS 1.3 ShangMi | Explicit CNet client/server RFC 8998 SM4-GCM profile with SM2 server authentication and REQUIRED-mTLS | Independent server-authenticated handshake/data/close, certificate/CertificateVerify/Finished negatives, exact profile rejection, fragmentation and abnormal EOF; native/native mTLS with independent certificates/digests and independent mTLS in both native directions; cross-platform CI required |
| DTLS1.2 | Finite opaque client/server, GmSSL AES128-GCM/P256/EMS/cookies, ordinary/external CNet datagrams and bounded SCTPDTLS bridge | Independent Python/Pion, actual Windows IOCP, supplied-chain PKIX and up to eight concurrent SCTP peers; general policies/path building and wider platform qualification pending |
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

### Direct-issuer OCSP and transport admission

`crypto/sm2_ocsp.h` verifies the finite direct-issuer SM2/SM3 profile of
[RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html). Certificate/path trust
must already be established; status checking alone cannot authenticate a
certificate signature. SHA1 (identifier only), SHA256 and SM3 CertID hashes and
both responder Name/key-hash forms bind the configured issuer. Embedded
certificates never establish trust: if present, the collection must contain
exactly the configured issuer. Direct-checking functions reject delegation.
Separate explicit delegated-checking functions require a caller-selected responder
certificate directly signed by the same CA, digitalSignature KU, OCSPSigning EKU,
current validity and validity at producedAt. A noncritical exact DER NULL
id-pkix-ocsp-nocheck is mandatory: this is the issuer's authorization to trust the
responder for that certificate's lifetime under RFC 6960 section 4.2.2.2.1.
No-check is never inferred from missing revocation data. The existing pinned-path
validator enforces the complete responder path/signature/purpose rules with a
separate explicit certificate-signing ID. Response signature IDs remain independent.
Optional embedded certificates contain exactly that responder and optionally the
exact issuer; they supply neither a new anchor nor a discovered responder. Other
responder revocation/discovery workflows fail outside this finite profile.

The synchronous primitive owns no memory or I/O. Its inputs are immutable
borrows, with explicit UTC validation seconds, SM2 response ID, maximum age,
clock skew and authenticated rollback floor. It parses every entry, including
entries after the target. A target must have exactly one matching good status;
revoked, unknown, absent or multiple matches fail. A separately named snapshot
validation operation authenticates a collection without claiming any target is
good. Collections are at most 64 KiB and 16 distinct DER CertIDs. Unsupported
single-response extensions and unknown/duplicate response extensions fail.

All entries require thisUpdate <= producedAt < nextUpdate. Each thisUpdate and
producedAt must be no later than validation time plus explicit skew (0..3600
seconds); validation time minus skew must be before nextUpdate. Age is bounded
from thisUpdate, and thisUpdate cannot precede the caller-maintained floor.
No request, retry, clock, cache or floor persistence is hidden in the primitive.
Optional exact nonces use nested OCTET STRING encoding and 32..128 bytes per
[RFC 9654](https://www.rfc-editor.org/rfc/rfc9654.html); NULL/0 requires nonce-free
responses. The caller owns secure nonce generation and rollback-floor updates.

`crypto/tls_sm2_ocsp_policy.h` and the matching CNet factories copy one immutable
nonce-free snapshot (<100 KiB including metadata). Creation authenticates the
whole snapshot against host UTC before publication. Handshakes recheck current
time, issuer signatures with a separately configured certificate SM2 ID, and
every actual leaf's good status after mandatory TLS authentication and before
application readiness. ShangMi accepts one leaf and an optional exact issuer;
TLCP server authentication accepts two distinct signing/encryption leaves and
an optional exact common issuer. Both TLCP leaves must pass. Unsupported
profiles/roles fail before trust loading or retain. No new thread, receive owner,
network fetch, allocation in checks, mutable cache, wire stapling or established
connection revalidation is introduced. Caller buffers can be erased on return;
release the caller's policy reference after context creation. Each context keeps
its own reference until its streams are destroyed.

For example, set `cnet_tls_sm2_ocsp_config` with an authenticated issuer DER,
response DER, explicit certificate/response IDs, maximum age and rollback floor;
call `cnet_tls_sm2_ocsp_peer_policy_create`, then set the client/server context's
`peer_policy` before construction. TLCP clients use
`cnet_tlcp_sm2_ocsp_peer_policy_create` with `peer_is_server=true`. Any factory
failure publishes no reference. See the public header for exact error and alias
contracts. A fresh context selects a fresh snapshot; this does not add hot reload.

Formal Crypto tests cover the three hashes, both responder forms, explicit IDs,
nonce/time/age/floor boundaries, full-entry parsing, status/signature/DER failures
and pinned-trust callback ordering. Formal CNet tests use actual authenticated
ShangMi endpoints in both roles, a separately implemented OCSP library and TLCP
dual-certificate handshakes, including independent revocations and missing status,
same-name issuer substitution, explicit delegated responders and no-check/
KU/EKU/certificate signature/time/identity negatives, profile/role rejection, erased source buffers,
early context/reference release, application data and orderly close. Functional
passing tests do not establish side-channel resistance or general PKIX support.

### CMS authenticated encryption design

The local completion also adds a finite RFC 5083 AuthEnvelopedData schema:
one issuer/serial SM2 key-transport recipient, SM4-GCM, a freshly generated
16-byte content key and 12-byte nonce, and a separate 16-byte mac. The explicit
SM4-GCM algorithm OID is 1.2.156.10197.1.104.8 with GCM nonce/tag parameters.
The RFC describes the CMS container; this SM4 profile does not assert AES-only
RFC 5084 algorithm conformance or full national CMS certification.

Keep the existing Salts ASN1 owner for canonical DER, public Core SM2 key
transport and SM4-GCM for cryptography, and the pinned-chain owner for recipient
trust. Do not use unauthenticated CBC decryption or infer authentication from
provider CMS parsing. A distinct EMAIL_ENCRYPTION purpose reuses the same chain,
anchor, identity, validity, KU/EKU and revocation contract, requiring
keyEncipherment and emailProtection rather than signing usage. SignedData never
accepts this encryption-only purpose. This avoids parallel path-validation rules.

One synchronous operation owns bounded temporary storage; it securely erases
content keys and all decrypted workspace on every admitted exit. No plaintext
escapes before the complete GCM tag succeeds. Authenticated encryption provides
ciphertext integrity for the recovered key; anyone knowing the public recipient
key can create a new envelope, so it does not identify a sender. Applications
requiring sender identity compose an attached SignedData inside the envelope and
verify that signed payload with its own authenticated signer path before use.
There is no key/password retention, new dependency, worker or progress owner.

Only id-data content, exactly one key-transport recipient, and no originator,
authenticated or unauthenticated attributes are admitted in this finite profile.
Other CMS encodings/algorithms fail; no trial decryption or format fallback.
Changing this profile requires rebuilding consumers, and rollback removes the
new interface and its encryption-purpose branch together. Existing signing and
TLS purpose behavior stays stable. Formal independent Go ASN1/SM2/SM4 tests cover both directions, empty/binary/maximum
payloads, fresh key/nonce generation, complete signed-payload composition,
key/recipient/tag/DER corruption, output erasure, long issuer Names, explicit
certificate signing IDs and trust callback gating. These local results do not
establish cross-platform or side-channel qualification.

### CMS signed data and explicit application purposes

`crypto/sm2_cms.h` owns one bounded SM2/SM3 signer for attached or detached
SignedData. It explicitly selects RFC 5652 content OIDs or the national SM2 CMS
content-OID family. This qualifies a finite signed-data profile, not every CMS
message/algorithm combination or national standards certification. It composes
canonical Salts::ASN1 with existing GmSSL-backed SM2/SM3 primitives. No native
provider pointer, alternate provider, filesystem, network worker or retained
application storage is introduced.

The native provider's CMS facade uses national content OIDs and its own digest
construction. Core needs explicit format admission, exact signed attributes,
per-signature SM2 IDs, bounded output and mandatory application trust. Therefore
Core owns this format composition instead of exposing the native CMS facade as
an already-qualified generic workflow. Wrapping native parsing alone would also
leave signature verification and certificate trust with different publication
boundaries. Duplicating SM2 arithmetic or implementing a second DER parser is
rejected; existing public primitives and the canonical ASN1 owner remain the
only cryptographic/parser authorities.

Signatures cover the exact canonical signed-attribute SET with SM2's explicit
identity binding. Mandatory contentType/messageDigest attributes bind the selected
format and SM3 of the raw content. A single signingTime is accepted as signed
metadata; it never changes validation time. Unknown/duplicate attributes, unsigned
attributes, absent attributes, extra signers/certificates, CRLs and BER fail.
Digest and signature AlgorithmIdentifiers are finite and require absent/NULL
parameters. Certificates and signed attributes enforce DER SET ordering, including
IMPLICIT sets. Signer issuer/serial and the embedded certificate set must match
the caller's explicit path exactly. Embedded data never supplies trust anchors.

Verification first parses the complete envelope and authenticates its content
and signature, then applies `salts_crypto_sm2_validate_pinned_chain`: authenticated
leaf pin, explicit anchor/time/purpose, independent issuer SM2 IDs, CA/pathLen,
KU/EKU and the selected revocation policy. Only full success copies content to
the caller. Rejected signatures/malformed envelopes cannot invoke revocation.
This remains the restricted pinned profile; general PKIX discovery and hostname
verification are not inferred from CMS parsing.

The same trust policy now admits exact CodeSigning, EmailProtection, TimeStamping
and OCSPSigning EKUs in addition to server/client signing. These are application
purpose constraints, not protocol-specific timestamp/OCSP/S-MIME qualifications.
The leaf must contain the exact EKU and every CA EKU, when present, must permit it.
Existing path, key-usage, critical-extension, time and revocation rules remain.
No anyEKU or unavailable-revocation fallback is added.

Every input is a synchronous immutable borrow. Sign output requires MAX_DER;
verify output requires MAX_CONTENT (64 KiB). Caller owns exclusive output/written
storage, disjoint from inputs. Invalid admission preserves output. An admitted
failure erases the corresponding full bound and sets written=0. Signing uses a
single bounded temporary allocation (at most 2*MAX_DER+MAX_CONTENT+8), erases it
before release, and publishes only complete DER. Verification allocates no heap
and exposes no borrowed/partially authenticated plaintext. API examples:

```c
salts_crypto_sm2_cms_sign_config signing = {
    .format = SALTS_CRYPTO_SM2_CMS_SHANGMI,
    .detached = true,
    .private_key = signer_private_key,
    .signer_identity = signer_id,
    .signer_identity_size = signer_id_size,
    .certificates = certificate_spans, /* leaf first, excludes trust anchor */
    .certificate_count = certificate_count
};
int status = salts_crypto_sm2_cms_sign(&signing, message, message_size,
    envelope, SALTS_CRYPTO_SM2_CMS_MAX_DER, &envelope_size);
/* Use the complete envelope only when status == SALTS_CRYPTO_OK. */

salts_crypto_sm2_cms_verify_config checking = {
    .format = SALTS_CRYPTO_SM2_CMS_SHANGMI,
    .detached = true,
    .signer_identity = signer_id,
    .signer_identity_size = signer_id_size,
    .chain = chain_entries, /* each entry has its certificate issuer's ID */
    .chain_count = chain_count,
    .trust = &authenticated_policy
};
status = salts_crypto_sm2_cms_verify(&checking, envelope, envelope_size,
    message, message_size, verified, SALTS_CRYPTO_SM2_CMS_MAX_CONTENT, &verified_size);
/* Consume verified[0..verified_size) only on full success. */
```

Formal module-owned tests use the existing independent gmsm/PKCS7 dependency for
both directions, both content-OID profiles, attached/detached empty/binary/maximum
content, explicit binary/maximum signer IDs and separately signed certificate IDs.
Native tests cover admission/alias/boundary and exact erasure behavior. Additional
path/purpose/clock/pin/revocation/signature/attribute/signer-count/DER negatives
check that no content or premature revocation callback escapes. Functional tests
do not establish constant-time arithmetic or other-platform qualification.

References: [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652.html),
[gmsm v0.41.1 PKCS7 source](https://github.com/emmansun/gmsm/tree/v0.41.1/pkcs7),
[official GB/T 35275 metadata](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=A7B91213CC4862B31BE2C84665CB8F7E).

### Immutable identity objects and authenticated PFX

`crypto_tls_credential_object_create` normalizes a bounded raw identity once,
checks each key/certificate binding, and owns an immutable DER allocation.
`crypto_tls_credential_object_from_pkcs12` imports authenticated DER PFX v3
using the same object. CNet exposes the corresponding `cnet_tls_credential_object_*`
functions and maps errors to SALTS codes. Configurations use a credentials
value with only `size` and `object` set. Mixing raw input and an object fails.

The creator owns one reference. Retain/release may run concurrently while each
caller holds a live reference; context construction borrows a held reference.
Each context imports independent provider key state synchronously. The source
bytes/password may be erased after object creation, and the object may be released
after context construction. Final release clears the allocation before freeing it.
Output slots must own no reference and remain disjoint from every input
span/descriptor. Alias rejection preserves all input/output storage; other
failures publish NULL. This prevents early publication clearing from overwriting
borrowed keys, passwords or descriptor fields. Formal admission tests cover those
aliases through both raw and PFX constructors.
There is no mutable global key registry, unbounded cache or new I/O owner.
The DER object avoids repeating PEM/password work while retaining the provider's
existing per-context mutable-key lifetime. Sharing mutable provider keys directly
would couple stream teardown and native state; copying caller descriptors alone
would retain unauthenticated or short-lived input. Both alternatives are rejected.

PFX import follows [RFC 7292](https://www.rfc-editor.org/rfc/rfc7292.html).
It verifies the MAC before processing encrypted safes or keys. SHA2/SM3 MAC and the
existing finite PBES2 PRF/cipher pairs are admitted; legacy PBE, SHA1 MAC,
unauthenticated import and nested safe contents fail. The caller supplies UTF-8
BMP text, including empty or embedded-NUL passwords; integrity uses BMPString
plus its terminator while PBES2 uses the original bytes. Invalid UTF-8 and
non-BMP characters fail. No alternate password encoding or trial decryption runs.

Limits are 64 KiB PFX, 8 safes, 32 bags, 16 certificates, 2 keys, and 2,000,000
total KDF iterations. Each KDF uses 10,000..1,000,000 iterations and 8..64-byte
salts; chain/key limits below still apply. Certificate and key bags may be unordered.
Actual public-key binding selects the leaf, and unique issuer names plus verified
signatures order the supplied chain. TLCP roles select both SM2 keys together.
SM2 issuer signatures use the standard default ID. Unrelated/ambiguous/duplicate
certificates fail; metadata attributes never select or authorize an identity.
Import verifies container integrity and local binding; it does not establish
peer trust or certificate validity. Those checks remain with TLS verification.

The independent Python suite covers RSA/P256, plaintext/shrouded key bags,
encrypted/plain safes, all six SHA2 MACs and SM3, empty/binary/BMP passwords, bad MACs,
wrong passwords, DER/work/input limits, mismatched keys and ambiguous identity
sets. It also preserves cryptography-produced encrypted contents while raising
that producer's fixed 2048-round MAC to the admitted minimum, and checks the
result with both implementations. Original low-round producer output is rejected.
CNet standard TLS, ShangMi mTLS and TLCP tests perform authenticated application
I/O after PFX/password erasure and object release. Concurrent native context
construction and final-reference release are covered separately; these checks
do not qualify private-key side channels or every platform.

These public struct additions require rebuilding Core and consumers together.
Existing raw-input initialization remains available. Rollback removes the object
and group fields/functions together; applications then use raw credentials and
profile-default groups. No parallel versioned API or automatic compatibility path
is introduced.

### Explicit key-exchange groups

Client/server `supported_groups` lists are copied during initialization. STANDARD
implements P-256 and SHANGMI_TLS13 implements SM2. The list controls key exchange,
not certificate signature curves. Unknown/profile-incompatible groups fail with
ENOTSUP before trust I/O; pointer/count conflicts, duplicate entries and excess
counts fail with EINVAL. NULL/0 preserves the profile default. Static ECC TLCP
has no negotiated group choice and rejects an explicit list. Formal tests cover
pre-I/O rejection and real standard/ShangMi handshakes after list erasure.

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
PBKDF2-HMAC-SHA2 with AES-128/192/256-CBC. The explicit SHA2 PRF may be SHA224,
SHA256, SHA384, SHA512, SHA512/224 or SHA512/256. Salt is 8..64 bytes, IV is 16 bytes, optional
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

GmSSL #41 also decodes the explicit HMAC-SHA384 and HMAC-SHA512 PRF identifiers
defined by [RFC 8018 Appendix B.1.2](https://www.rfc-editor.org/rfc/rfc8018.html#appendix-B.1.2).
Crypto selects the corresponding existing GmSSL digest only for AES-CBC memory
credential import. The three AES key sizes remain independent of the digest
size. The SM3/SM4 combination retains its separate admission rule; SHA384/512
with SM4, omitted/unknown PRFs and malformed parameters still fail. No generic
digest lookup, inferred algorithm, default PRF or trial decryption is introduced.

This extends the existing credential format whitelist without changing public
structs or adding configuration, dependencies, storage or runtime threads.
The initialization owner borrows the inputs/password only for the call, validates
the work/output limits before derivation, and commits an identity only after
private-key parsing and certificate binding. Failure clears derived keys, cipher
state and output, then returns the existing error without publishing a context.
All existing trust, verification and immutable-context lifetimes remain intact.
Revert the import dispatch and provider pin together to roll back the extension;
SHA384/512 inputs then fail rather than selecting another scheme.

Formal registered tests add 184 independent RSA/P256 admission scenarios, each
checking both context roles; 48 standard TLS1.2/1.3 encrypted-client-identity
handshakes; 36 native/native and independent ShangMi mTLS paths; and 12 TLCP
server paths with independently protected signing/encryption keys. They cover
all AES key sizes and PEM/DER, empty/binary passwords, exact PRF selection,
unchanged work bounds, malformed envelopes and failed key/certificate binding.
Input/password erasure precedes handshake progress. Existing SHA256 and SM3/SM4
tests remain in the same formal entries. File-password loaders, standalone SM2
key export, PKCS12/PFX and additional PRFs are not qualified by this extension.

GmSSL #43 completes the six explicit SHA-2 PRFs listed by
[RFC 8018 Appendix B.1.2](https://www.rfc-editor.org/rfc/rfc8018.html#appendix-B.1.2)
by decoding HMAC-SHA224, HMAC-SHA512/224 and HMAC-SHA512/256. Crypto dispatches
each exact OID to its existing GmSSL digest. The SHA512 truncated variants have
their own initialization and are neither SHA224/SHA256 aliases nor truncations
of ordinary SHA512 output. AES-256 needs two PBKDF2 output blocks with the
28-byte SHA224 and SHA512/224 PRFs; AES-128/192 stay within one block. Independent
Go fixtures cover both paths. No new cryptographic implementation is introduced.

The initialization owner and all input/work/output limits remain unchanged.
Passwords and decoded keys retain their existing erasure paths; a context is
published only after exact private-key parsing and certificate binding. Empty
or wrong passwords, altered PRF labels, malformed parameters, excess work and
incompatible SM4 combinations use the existing failure contract, without trial
decryption or default-PRF selection. Public structs, dependencies, allocations
and threads are unchanged. Rollback reverts the explicit dispatch and matching
provider pin together; newly unsupported OIDs fail rather than selecting a
different digest.

The registered entries add 276 RSA/P256 PEM/DER admission scenarios (each checks
both context roles), 72 standard TLS1.2/1.3 identity handshakes, 54 native/native
and independent ShangMi mTLS paths, and 18 TLCP dual-key paths. The three new
PRFs cover every AES key size, empty/binary passwords and input erasure before
progress. Previously supported SHA256/384/512 and SM3/SM4 cases remain selected.
The shared AES fixture table is the hash/OID fact source; named selectors use
an explicit separator so SHA512/224 and SHA512/256 cannot match SHA512 by prefix.
Implicit/explicit SHA1, other KDF/cipher schemes, PKCS12 and standalone key
exports remain separate work.

The local completion adds authenticated PKCS#12/PFX and retained identity objects
as described above. Other unsupported encrypted PKCS#8 algorithms and standalone
export variants remain separate from those finite profiles. SDF/SKF hardware
integration is deferred by user decision.

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

The list constrains handshake signatures and, by default, certificate-chain
signatures. The independent certificate list below can override the latter.
GmSSL #26
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
claimed. General path building remains separate work.

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
that sends nonempty application records can reset it. Time/byte minimum spacing
is described below; session resumption, DTLS and hardware-backed keys remain separate work.
Supported post-handshake fragmentation is described below; additional peer
admission follows here.

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
qualify KeyUpdate flood limits. Supported message fragmentation is qualified
separately in the bounded post-handshake framing section below.

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

EncryptedPrivateKeyInfo uses PBES2. Existing `salts_crypto_sm2_pkcs8_encrypt`
and `salts_crypto_sm2_pkcs8_decrypt` select PBKDF2-HMAC-SM3/SM4-CBC exclusively.
The separate `salts_crypto_sm2_pkcs8_aes256_encrypt` and
`salts_crypto_sm2_pkcs8_aes256_decrypt` select PBKDF2-HMAC-SHA256/AES-256-CBC.
No algorithm inference or retry crosses those two profiles. AES256 export
encodes explicit keyLength=32 and NULL HMAC-SHA256 parameters; import permits
omitted keyLength or PRF parameters, but requires the explicit SHA256 PRF OID
and the AES256-CBC cipher OID. Both accept salt 16..64 and exactly 16-byte IVs.
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

The AES256 addition fills the standalone key-container gap independently of
the broader TLS memory loader. Reuse the installed GmSSL #44 digest/PBKDF2/AES
primitives and the existing ASN1 owner: no provider revision or dependency is
needed. Two explicit entrypoints preserve the established SM3/SM4 contract;
widening its implicit whitelist would change format admission for current
callers, while a general algorithm registry would expose unqualified choices.
Common private helpers own DER admission, padding and cleanup. Work is linear
in the configured PBKDF2 iterations with fixed bounded stack storage, no heap
or retained caller data. Derived keys, AES schedules and decrypted PKCS#8 are
cleared on every admitted exit. This does not establish constant-time SM2/AES
or authenticated storage. Reverting the two new declarations/entrypoints and
their finite profile branches restores the previous API; existing formats and
stored SM3/SM4 keys require no migration.

For example, with caller-owned `key[32]`, nonempty `password` and
`der[SALTS_CRYPTO_SM2_ENCRYPTED_PKCS8_MAX_SIZE]`:

```c
size_t written = 0;
int status = salts_crypto_sm2_pkcs8_aes256_encrypt(key, password, password_size,
    10000, der, sizeof(der), &written);
/* Check status == SALTS_CRYPTO_OK before using der[0..written). */
/* With disjoint imported_key[32], cap KDF work explicitly on import: */
if (status == SALTS_CRYPTO_OK)
    status = salts_crypto_sm2_pkcs8_aes256_decrypt(der, written, password,
        password_size, 10000, imported_key);
```

10000 is the admission minimum in this example, not password-strength advice.
The existing formal `crypto.asn1.sm2_keys` and independent Python entry cover
binary/maximum passwords, invalid keys, both random-draw failures, fixed output
guards, iteration budgets, optional inner/algorithm fields, salt boundaries,
wrong passwords, padding/algorithm/DER/key-binding rejection and strict
cross-profile refusal. `crypto.asn1.header_cpp17` calls the new C ABI directly.
Cross-platform/sanitizer qualification of this addition remains separate from
local Windows Release results and from the earlier #273 matrix.

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

## Separate certificate signature policy (TLS 1.2/1.3)

Crypto and CNet client/server configurations accept an immutable
`certificate_signature_algorithms` / `certificate_signature_algorithm_count`
list. NULL/0 retains the shared handshake/certificate policy. An explicit list
is copied before publication, contains at most four unique supported schemes,
and independently controls CertificateRequest/ClientHello certificate offers,
local identity selection and remote chain signature admission. Trust, hostname,
purpose and revocation checks remain mandatory.

STANDARD accepts TLS1.2-only, TLS1.3-only and TLS1.2..1.3 bounds, including the
default range. SHANGMI_TLS13 accepts SM2/SM3. TLCP rejects explicit certificate
lists with ENOTSUP before trust/credential I/O. RSA-PSS certificate signatures are not supported by this
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

GmSSL #42 applies the same immutable certificate policy when TLS1.2 is selected,
including a range context negotiating down to TLS1.2. ClientHello extension 50
contains the certificate list independently of extension 13's handshake list.
Server identity selection intersects local certificate policy with the peer's
extension 50, or the peer's signature_algorithms when extension 50 is absent.
Received server and client chains, including the top certificate's signature
against its local issuer, use certificate policy rather than handshake policy.

TLS1.2 CertificateRequest has one shared signature list and no independent
extension vector. The server continues to advertise its handshake list, without
adding certificate-only schemes that it does not allow for CertificateVerify.
The client intersects this peer list separately with its own handshake and
certificate policies before selecting an identity. All CA/type constraints still
apply; no matching identity sends an empty Certificate as before. Thus a server
requesting a P256 handshake key with a P384-signed chain must permit both schemes
in its TLS1.2 request, while its independent certificate policy can restrict
chains to P384. A disjoint request is rejected rather than weakening either
policy. See [RFC 8446 section 4.2.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3)
and [RFC 5246 section 7.4.4](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.4).

The existing copied context array remains the only policy owner. Initialization
retains no caller array; connection-local selection uses one bounded 32-int
intersection on the handshake stack. No new allocation, thread, dependency or
public struct field is introduced. Validation, trust, first fatal error and
quiescent context/session destruction retain their existing contracts. Revert
the admission expansion and matching provider pin together to restore TLS1.2
configuration rejection; no automatic version narrowing or fallback is added.

Formal coverage adds six exact TLS1.2 ClientHello wire cases, including disabled
policy, independent single/multiple schemes and one-byte writes; 22 new real
CNet server-authentication cases across exact/range and forced TLS1.2 selection;
45 native mTLS cases with independently signed P256/P384 chains and file/PEM/DER
inputs; and nine independent TLS1.2/1.3 exact/range client-identity handshakes.
Wrong peer chains must fail on the verifying endpoint before its application
readiness; REQUIRED authentication rejects an unavailable client identity.
Input-array erasure precedes progress, and
existing TLS1.3/ShangMi and invalid-configuration tests remain selected.

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
interval above composes with both budgets. Supported KeyUpdate/ticket framing
is described in the bounded post-handshake section below.

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

## Bounded TLS 1.3 post-handshake framing

The exclusive receive owner reassembles supported KeyUpdate/NewSessionTicket
messages across authenticated TLS1.3 records, and processes multiple messages
within a record. It reuses the initial-handshake fragment array after Finished
has consumed that array at a record boundary; one new length scalar owns the
post-handshake assembly. The parser requires the completed-Finished state before
reusing it, so pre-Finished input cannot overwrite initial handshake storage.
Initial-handshake parsing no longer uses that array.
The input record remains in the independent receive buffer and received
application plaintext retains its existing databuf lifetime. No allocation,
queue, thread, second reader or public configuration/API is introduced.

The four-byte handshake header declares a body bounded by
TLS_MAX_HANDSHAKE_DATA_SIZE; larger declarations fail as soon as the header is
complete. Unknown/unsupported handshake types and server-side receipt of tickets
fail rather than buffering arbitrary messages. Empty handshake fragments,
interleaved application/alert records and suffix bytes following KeyUpdate in
the same record are fatal. In particular, a partial update cannot turn a
close_notify into successful shutdown or reset a key/update budget. Peer update
admission and traffic-secret derivation run once, only for a complete valid
KeyUpdate ending exactly at the record boundary. Sending-key budgets remain
independent. This follows
[RFC 8446 section 5.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1).

Ticket parsing rejects empty ticket values and keeps the provider's existing
bounded session encoding. Before
derivation or serialization, a length-only encoding must fit its 512-byte local
buffer (53 bytes of fixed encoding plus at most 459 ticket bytes). This closes
an unchecked network-length write into that buffer; oversized tickets fail
instead of overflowing it. Secret derivation and file completion failures
propagate, ticket-count overflow is rejected, and temporary derived material is
cleared on all admitted exits. Receiving these messages alone does not qualify
restoration; the finite client cache below has separate qualification. 0-RTT
remains unsupported.

Applications rebuild against the matching pinned provider ABI. No Core/CNet
configuration changes are required. Rolling back requires reverting the port
pin and corresponding provider source together. Formal tests cover split
headers/bodies, coalesced tickets and ticket/update ordering, exact size/count
bounds, wrong roles, interruption and key-boundary failures, partial transport
I/O, peer-update limits and real independent authenticated data/close traffic.

## Peer KeyUpdate minimum spacing

Immutable SHANGMI_TLS13 client/server `peer_key_update_min_interval_ms` and
`peer_key_update_min_bytes` add receive-side admission limits. Each uint32 scalar
defaults to zero (disabled). Nonzero STANDARD/TLCP configurations fail with
ENOTSUP before trust/identity loading or retained-policy callbacks. The first
complete, valid peer update is admitted without spacing credit; every later
one must satisfy every enabled minimum. Both request kinds count, including
responses to local requests. Violations fail permanently with EPROTO before
another receiving traffic-secret derivation, without delivering new plaintext.

Time uses the existing stateless monotonic clock adapter. The provider initializes
that clock once at Finished when either local age or peer spacing needs it.
It samples only when preparing local timed records or admitting complete peer
updates. A backward/failed clock is fatal. Compare `now >= last` before
subtracting; no deadline addition, periodic timer or worker is required.
The last admitted peer timestamp changes only after successful peer derivation.
Local key changes, including mandatory replies, never reset receive-side spacing.

Byte credit counts authenticated received application plaintext after the last
admitted peer update, once per decrypted record rather than per read callback.
It explicitly caps at the configured minimum; surplus cannot be banked for
multiple updates. Data before the first update is discarded from this credit
when that first update commits. Empty records, control messages, padding and
outgoing application data earn no credit. Bounded remaining-credit subtraction
prevents overflow; impossible credit greater than its limit is rejected.
These are received/authenticated bytes, not application-consumption acknowledgments.

One fixed progress owner owns the seen flag, last peer timestamp and capped
uint32 credit. There is no new buffer, allocation, queue, lock or thread. The
existing consecutive-update burst limit remains independent: nonempty received
data can reset that burst count, but cannot bypass time or byte spacing. All
admission checks precede derivation; failed admission preserves the peer budget.
Existing pending record buffers remain valid until quiescent destruction.

Minimum spacing is deliberately stricter than a token bucket with a configurable
burst or a boundary-sensitive fixed window: it permits one initial update and
requires a full gap thereafter, with constant state and no elapsed-window refill.
It may reject otherwise valid TLS bursts, including crossed KeyUpdate responses
or responses induced by very aggressive local rotation. Applications must choose
compatible sending/receiving policies and accept disconnect on violation. Admitted
requests still receive their mandatory response; request_update=0 has no exemption.
See [RFC 8446 section 4.6.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.6.3).

For example, set `peer_key_update_min_interval_ms = 1000` and
`peer_key_update_min_bytes = 4096` before context creation. This requires both a
second and 4096 new authenticated application bytes between admitted peer updates.
The two scalars are copied at initialization; the caller may then erase them.
Zero restores previous behavior. Core/CNet configuration structs and the matching
provider ABI require rebuilding together; rollback reverts the fields and port
pin together. No hot mutation or parallel versioned API is introduced.

## TLS 1.3 fatal alert direction

Encrypted fatal alerts use the local role's active sending key, IV and sequence
in both handshake and established phases. Client alerts must not use or advance
the server receiving direction. Partial transport writes resume the same pending
ciphertext and consume one sending sequence; pre-key states retain their existing
plaintext-alert behavior. This fixes incorrect client alert authentication without
changing the public configuration or allowing recovery after a fatal TLS error.

Formal provider tests cover both roles and ShangMi AEAD suites, handshake and
established keys, one-byte output, receiving-sequence preservation and pre-key
states. Independent mTLS peers withhold the remaining authentication flight after
a malformed CertificateRequest and authenticate any received fatal decode_error.
An invalid MAC or malformed record cannot qualify early rejection. The matching
pinned provider and Core tests must be updated together when reverting this fix.


## TLCP local certificate signature policy

The local GmSSL #44 candidate and Crypto/CNet enable client-side independent
`certificate_signature_algorithms` for TLCP server authentication. The handshake
continues using SM2/SM3; the explicit certificate list admits SM2/SM3 and
RSA-PKCS1-SHA256 issuers, including mixed allowlists. NULL/0 uses the handshake
list. Unsupported schemes, invalid pointer/count or duplicate lists fail before
trust loading. TLCP server lists remain ENOTSUP while client authentication is
unsupported. Other protocols retain their previous selection contracts.

This is local chain admission. No TLS extension 50 is added to TLCP, and the
native ClientHello still carries TLCP's 0x0704 handshake pair. After complete
native name/time/purpose/signature/depth authentication, policy checks both
sibling leaves against their actual common issuer, then every presented issuer
and the top certificate's signature using the selected local anchor. The anchor's
own signature is outside the allowlist. An encryption leaf is never treated as
its signing sibling's issuer. Incompatible policy rejects before application
readiness and uses the existing fatal latch and diagnostic lifetime.

The first formal test reproduced ENOTSUP against the old Core/#43 combination.
The ordinary single-chain matcher then reproduced false rejection of valid
RSA-issued SM2 dual leaves, motivating the explicit sibling boundary above.
Independent GoTLCP tests cover SM2/RSA issuers, exact/mixed/default lists, source
array erasure before progress, CA file/PEM/DER, optional issuer transmission,
real handshake/data/close and signature-policy rejection. Native admission tests
cover all malformed lists and the unsupported server role. This does not qualify
separate TLCP issuers/IDs, client authentication or another wire profile.

Provider changes are registered as GmSSL 3.2.0#44 in the vcpkg-cache completion
commit `3c9cb8cbcc6b3645d47e02585e987b708406cd98`, with port tree
`29cd5565d2fc85b03b1f555206e4745ca85f55bd`. Released as vcpkg-cache `v0.1.7`,
baseline `47e38f1465f95e9211edcbcfd5e3c8e96289a20c`. The current registry and
CI Actions select binary-cache release `v0.1.1`, baseline
`4ac631f89e07cebfd347848af642f31fe8c4edec`, retaining that same #44 port tree.
The local GmSSL overlay has been removed from the
build configuration. The old registry #43 alone cannot qualify this capability.
No source-tree GmSSL build or extra validation project is introduced.


## Depth failure positions

The local provider #44 candidate records the first presented issuer exceeding
`verification_depth`, with zero-based peer-chain indices. TLS has one leaf and
TLCP has two: a depth of one first rejects issuer index 2 or 3, respectively.
The position comes from the verifier's existing bounded traversal, without
changing error ordering, path admission or the number of accepted certificates.
A local-only anchor never receives a fabricated position. Crypto/CNet keep the
owned diagnostic after failure and teardown; unavailable positions remain SIZE_MAX.

Existing independent mTLS tests reproduced missing positions before the fix, then
passed exact index assertions for TLS1.2/TLS1.3/ShangMi, both failing endpoints,
CA file/PEM/DER and included roots. Independent TLCP tests add valid one-issuer
controls and two/three-issuer failures, checking index 3 even when the native
failure is detected later in traversal. Native buffers, retained policies,
terminal latches and destruction boundaries remain unchanged.


## Context-owned client TLS1.3 session cache

The local completion branch adds optional `session_cache_capacity` (0 disabled, 1..16)
for exact STANDARD TLS1.3 and ShangMi TLS1.3 client contexts. TLS1.2/ranges,
TLCP and implicit iOS system trust reject enabled caches before trust loading.
Server-side ticket issuance has the separate contract below; 0RTT remains unsupported. Cache entries never
cross contexts: the same immutable context owns credentials, roots, signatures,
verification time/depth, ALPN offers and retained peer policy for their lifetime.
Each entry additionally binds the exact verified hostname, negotiated ALPN,
profile/cipher and previously authenticated peer chain. No file sessions, secret
serialization, global registry or context-pointer cache key is introduced.

A context owns one fixed allocation (<=16 entries, each bounded by a 459-byte
opaque ticket, 32-byte PSK, 4096-byte chain and existing name/ALPN limits).
Concurrent stream owners serialize bounded copies under one platform mutex; no
allocation, I/O, cryptography or user callback runs under it. Entries are inserted
in a documented cyclic replacement order, securely clearing overwritten secrets.
The first handshake call consumes the newest matching nonexpired entry once, copying it
to fixed stream-owned storage and erasing the cache slot. Failed connect or
abandoned stream does not restore a consumed ticket. A miss/expired ticket uses
the normal full TLS handshake; server rejection of a PSK uses TLS's specified
full-authentication path, never a weaker trust/profile or application replay.

Ticket age uses the existing monotonic clock adapter, exact milliseconds plus
age_add modulo 2^32 per RFC8446. Cache lookup samples this internal OS clock
after acquiring the mutex, and returns the same sample for ticket-age encoding.
A concurrent later publication therefore cannot make an earlier caller sample
look like clock regression. Actual clock failure or a sample before a published
receipt still fails without consuming a ticket. Lifetime
is at most seven days, and expiry does not extend on selection. Only PSK_DHE is
offered alongside full certificate authentication; pure PSK and early data remain
disabled. On accepted PSK Finished, the original peer chain is revalidated using
the same current native trust/name/time/purpose/signature/depth rules, then the
retained application admission policy runs again before READY. A different ALPN
or cipher rejects before application data. Fresh ticket capture occurs only after
that authenticated readiness boundary. No cached revocation decision is reused.

The context outlives every stream through existing references. Final context
release destroys its quiescent mutex and clears all cache secrets; stream
teardown clears the consumed ticket/PSK snapshot after native work drains. The
change rebuilds Core/CNet against the matching GmSSL #44 ABI, whose bounded
NST callback is synchronous and performs no socket operation. Rollback removes
the cache setting and provider callback together. The provider patch and #44
version tree are registered at the immutable commit above; #43 is not interchangeable.

Formal qualification uses `saltscore.cnet_tls_session_resumption` (independent
Go standard TLS1.3) and `saltscore.cnet_shangmi_session_resumption` (independent
pollux SM2/SM3/SM4-GCM). Both cover first full authentication, two subsequent
PSK_DHE connections, data/close, disabled-cache controls and rejected tickets
after server ticket-key rotation. They release the caller's reusable context
before the last handshake; stream references preserve the cache and policy.
Standard TLS additionally rejects changed ALPN, a freshly denying peer policy
and an original certificate that expires while its ticket remains valid. The
independent peer confirms PSK acceptance and no application byte on rejection.
`crypto.algorithms.tls_session_cache` covers fixed eviction/copying, exact host,
expiry boundaries, clock rollback, repeated identities and concurrent one-entry
consumption. Existing CNet admission tests reject unsupported settings before
loading deliberately absent trust files. These are native Release results;
cross-platform and sanitizer qualification remain separate.

For CNet, set `session_cache_capacity` in the client config passed to
`cnet_tls_client_init`, then use that same client's `tls_client` in each
`cnet_connect_options`. For STANDARD also set both protocol bounds to
`CNET_TLS_PROTOCOL_VERSION_1_3`; for ShangMi choose its explicit profile.
Check initialization/connect errors normally. Query `cnet_tls_session_reused`
on OPEN, and destroy the reusable client when no further connects need its
cache. Per-connect ephemeral contexts do not retain tickets across connections.
Changing trust/identity/policy configuration creates a new context and empty
cache. Cached entries are consumed once; repeated copies still present in the
cache are deduplicated by exact hostname/ticket, without unbounded spent-ticket
history or any promise about a server reissuing an already consumed identity.

## Context-owned TLS1.3 server tickets (local implementation contract)

Server contexts accept an explicit fixed ticket capacity (1..16) and
lifetime (1..604800 seconds), both zero to disable. Exact STANDARD TLS1.3 and
ShangMi TLS1.3 are admitted; TLS1.2/ranges/TLCP fail before identity/trust I/O.
Each authenticated handshake issues at most one random 32-byte opaque identity,
only if the client advertised PSK_DHE. There is no persistent/encrypted ticket
payload, global key, shared cluster state or new provider dependency. The
server's immutable retained context owns the sole fixed PSK/state table.

Entries own original authenticated client chains (when REQUIRED), exact SNI,
selected local leaf digest, ALPN, cipher and monotonic issuance/lifetime/age_add.
Shared stream owners serialize bounded table copies; no crypto, allocation,
I/O or callbacks run under the lock. Full capacity securely evicts the cyclic
oldest slot; expired/evicted/unknown/binding-mismatched tickets decline PSK and
perform full certificate authentication. Clock/invariant failures are fatal.
Failed binder validation never becomes full-auth success. Lookups do not consume
server entries before proof: unauthenticated ClientHello replay must not erase
another client's entry. Fresh ECDHE and both Finished messages remain required;
no 0RTT/pure PSK/automatic application replay is admitted.

The provider derives the PSK and emits the NST through the same stream-owned
record path. Core holds the new ticket secret in bounded pending storage and
publishes the entry only after Core's mandatory verification and peer policy
admit READY. A rejected/abandoned handshake's emitted identity remains unusable.
Resumed REQUIRED-mTLS restores and revalidates the original client chain and
reruns current peer policy before OPEN. New contexts have empty stores; closing
the last reference clears all pending/consumed/cached secrets after native work
drains. Provider partial NST output must drain before handshake completion,
including after its issuance count reaches zero. Qualification must include
independent client PSK_DHE/mTLS, binding/expiry/corrupt-binder/capacity failures,
context release/concurrent owners and bounded partial record output. This
contract alone does not claim production qualification. The local implementation
now passes independent Go TLS client server-authentication and REQUIRED-mTLS
resumption, SNI/ALPN/capacity changes, disabled-client/server controls, peer policy
and original client-certificate expiry. Independent pollux clients qualify the
ShangMi server-authenticated path, bad binder without consuming a valid entry,
unknown tickets, expired tickets and invalid ages. Native formal cases cover
byte-at-a-time NST output, callback/size/lifetime failure and matching received
PSKs for both AEAD suites. Go interoperation also exposed and corrected an
extra length prefix in the native RFC6066 status_request encoder/parser.

## Configured-anchor name constraints

The native verifier already checks intermediate CA name constraints. A local
regression with an independent Go x509 oracle reproduced a narrower HIGH defect:
configured-anchor constraints checked only the nearest issuer, allowing a leaf
outside the permitted DNS subtree through an unconstrained intermediate.
The local provider patch applies configured-anchor constraints to every
subordinate certificate and excludes an identical presented anchor itself.
Standard TLS tests cover accepted/rejected intermediate and anchor constraints,
with/without a presented anchor. TLCP covers direct and intermediate dual-leaf
paths, preserving the required equal-entity/SAN checks before name constraints.
CONSTRAINTS positions remain SIZE_MAX; no fabricated index is added.
This does not establish general path discovery, policy trees, self-issued
rollover exceptions, all name forms or cross-signing qualification.

## DTLS1.2 private record foundation

The first internal profile uses the registered DTLS-capable
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 record construction (RFC5288/6347), with
GmSSL AES-GCM. It does not repurpose RFC8998 TLS1.3 cipher IDs as DTLS profiles.
This record primitive stays private. The finite opaque client and CNet datagram
composition described below build on its verified handshake/trust path. The
server listener extension is also described below; SCTP remains separate.
No additional production provider.

A stream owner will exclusively own separate sending/receiving key epochs.
The private record primitive has fixed key state, a 48-bit sending sequence and
a 64-record receiving replay window. It allocates nothing and retains no input
or output pointer. Parse views borrow one complete record within a datagram;
the caller retains that datagram while consuming any coalesced records. The
primitive never turns UDP into a byte stream. Payloads are bounded to 16384
bytes, AES-GCM overhead to 37 bytes including the DTLS header; MTU reservation
and handshake fragmentation belong to the eventual datagram owner.

Seal requires already reserved output storage and advances the nonce exactly
once on success, before external I/O can publish it. Capacity/alias rejection
changes no key/sequence; encryption failure latches sending failure. Exhausted
48-bit sequences never wrap. Receiving checks the admitted epoch and replay
window before decryption but commits the window only after tag authentication.
Bad tags, stale/replayed or wrong-epoch records publish no plaintext and cannot
advance receiving state. Per RFC6347 these unauthenticated packet failures are
discard outcomes, not permission to reset keys or authenticate an application.
Private cookie, fragment assembly, timer and key-schedule helpers are described
below. Authenticated record dispatch, complete flight storage/retransmission and
close still need the full handshake owner. Clear/destruction requires quiescence
and erases keys/state. These internals cannot qualify production DTLS or #188.

## DTLS1.2 handshake preparation (private contract)

Before exposing a DTLS handshake, private preparation now provides a stateless
cookie gate, bounded message assembly and an owner-driven retransmission timer.
These are protocol components, not certificate authentication or network READY.

The immutable listener cookie context owns one OS-random 32-byte secret.
Cookie lifetime is explicit (1..60000 monotonic milliseconds); the 32-byte
cookie contains an eight-byte issuance time and a 24-byte truncated HMAC-SHA256.
GmSSL computes the MAC. It binds a domain label, canonical binary peer address
(including port, 1..32 bytes), issuance time and the complete ClientHello with
its cookie vector normalized to empty. There are no retained per-peer cookies,
previous keys or automatic key-source changes. Verification checks the MAC
before treating an authenticated future timestamp as clock failure. Cookie
age must be strictly below the configured limit; failed MAC/age/address/parameter
binding gets another stateless challenge, never an allocated handshake.

The gate accepts one unfragmented epoch-zero ClientHello per datagram, <=4096
body bytes. Body protocol is exactly DTLS1.2; legacy DTLS1.0 outer record format
is accepted solely for this initial framing, with no protocol downgrade.
Header/vector/extension lengths, duplicate extension types and complete input
consumption are checked. At most 32 extensions are scanned. It mirrors the
incoming record sequence in HelloVerifyRequest, uses server handshake sequence
zero, and emits a 60-byte response no larger than the received datagram. Valid
cookies produce only an address-verified, borrowed ClientHello view. The actual
owner must copy/retain it before reusing input storage and still perform all
certificate, key-exchange, transcript and Finished checks.

After cookie admission, one progress owner reserves the fixed assembler.
Eight message slots each own <=16384 body bytes plus a per-byte bitmap.
Expected message sequence and a bounded future window are authoritative;
old/far-future fragments do not mutate it. Identical overlaps are accepted,
conflicting overlaps/type/length fail transactionally, and completion requires
all bytes. Views last until explicit consume/clear; consume erases one slot and
advances the 16-bit sequence without wrap. Transcript normalization uses the
unfragmented 12-byte DTLS handshake header once per consumed message, never once
per fragment. Stateless pre-cookie fragments are discarded, not reassembled.

The timer owns no transport, payload or worker. Its caller provides monotonic
time and explicitly marks a whole flight sent only after actual NativeIO send
terminals. A due timer authorizes one retransmission, doubles its interval up
to the configured ceiling and waits for another sent notification. Repeated
polls while output is pending cannot authorize more retries. Acknowledged
flights stop; retry exhaustion is terminal; clock rollback/deadline overflow
fails rather than saturating or retrying. The future owner must retain old
epoch material for retransmissions, reserve output before sealing records with
new record sequences and drain real native terminals before teardown. Default
timers will follow RFC6347's 1-second initial / 60-second ceiling guidance;
private tests use explicit fake time. No public API or completed DTLS claim is
made by these components.

The private key schedule requires Extended Master Secret (RFC7627) for this
DTLS1.2 profile, with no legacy master-secret branch. A bounded SHA256 transcript
hashes normalized complete DTLS messages once; the cookie-less ClientHello and
HelloVerifyRequest are excluded. The handshake owner validates message order,
syntax and proof before committing transcript changes. Per-sender sequence
checks reject duplicate/wrapped additions; the owner supplies the admitted
post-cookie starting sequences, including a ClientHello after a renewed cookie
challenge. Hash snapshots do not consume state.
No public noncopyable SHA256 context is cloned: private native SHA256 state is
pointer-free, as used by the provider's HMAC implementation.

After validated P256 ECDH, a 32-byte shared secret and the transcript through
ClientKeyExchange derive the 48-byte EMS master secret. The SHA256 TLS PRF key
expansion uses server_random || client_random and splits 40 bytes into two
16-byte AES keys and two four-byte fixed IVs. The owner retains distinct client/
server epoch-one record states and erases temporary key blocks. Finished uses
the role-specific label and current transcript hash to compute exactly 12 bytes.
An authenticated wrong Finished is terminal and erases both traffic directions
and master secret; it cannot turn into cookie/retransmission recovery. The
private exchange helper below supplies P256 point and key-exchange proof checks;
certificate chain/purpose/hostname/revocation admission, EMS extension negotiation,
flight storage and authenticated record dispatch still need the full handshake
owner. The PRF itself must propagate every native HMAC failure,
clear failed output and erase all secret working state on every admitted exit.

`crypto.algorithms.dtls_handshake` is the formal TinyTest/Python entry for these
components. Python independently verifies the cookie HMAC and canonical message
bytes. Its SHA256/HMAC key schedule computes the EMS master, both directional
keys/IVs, role-specific Finished and a 65-byte multi-block PRF; Python-generated
Finished proofs are checked natively and native AES-GCM records are decrypted
with the independently derived keys. Synthetic transcript bodies are explicitly
not valid certificates, signed ECDHE parameters or a network handshake.
Native digest callbacks inject failure at every init/update/finish call,
including after partial PRF output, and require full output erasure with intact
guards. Other cases cover malformed/aliased input, transactional overlap,
bounded transcript/message/sequence space, stable hash snapshots, clock/retry
boundaries and permanent key erasure after an invalid authenticated Finished.
No exported API, transport dependency or alternate crypto provider is added.
Protocol references: [DTLS1.2 framing/cookies/flights](https://www.rfc-editor.org/rfc/rfc6347.html),
[Extended Master Secret](https://www.rfc-editor.org/rfc/rfc7627.html) and
[AES-GCM TLS key/nonce layout](https://www.rfc-editor.org/rfc/rfc5288.html).

The private `crypto_dtls_exchange` helper exclusively owns a fresh GmSSL P256
ephemeral key per handshake. Public bytes are copied into future flight storage,
never borrowed from native key memory. Exchange accepts exactly one canonical
uncompressed P256 point, with coordinate range/on-curve checks supplied by
GmSSL. Both successful exchange and admitted malformed-point/crypto failure erase
the private scalar and make that ephemeral terminal. Neither reinitialization
nor a repeated exchange can reuse it without explicit clear and a new handshake.
Shared output remains caller-owned and must be erased after derivation; neither
the ephemeral nor the key schedule retains its pointer.

ServerKeyExchange verification takes one already trust-admitted DER leaf and
the complete handshake body. It does not replace chain, hostname, expiry,
purpose or revocation checks. The finite private profile supports P256 with
ECDHE-ECDSA/AES128-GCM/SHA256 and ECDSA-SHA256, or ECDHE-RSA/AES128-GCM/SHA256
and RSA-PKCS1-SHA256. Scheme/cipher/key-type mismatch fails, without another
signature trial. The signature binds client_random || server_random || exact
encoded named-curve parameters. Exact body/certificate consumption, signature
length <=512, P256 point validation and native signature verification precede
publication of any peer point. This helper does not sign a server flight or
implement client authentication, negotiation or a public DTLS profile.

The same formal CTest driver independently creates ECDSA/RSA certificates and
signed key-exchange bodies. Native negative cases cover every short prefix,
mutated randoms/parameters/scheme/signature, wrong key type, malformed points,
truncated/trailing vectors and signature-internal trailing junk. Native fresh
ECDH keys are checked against Python P256 ECDH, then their EMS master and encrypted
record are checked independently through AES-GCM. These checks compose the real
cryptographic primitives, but still are not a DTLS network handshake. No new
production dependency or side-channel qualification is implied.

## Private DTLS client owner work

The private owner now composes these primitives into a server-authenticated
DTLS1.2 client, with mandatory cookie exchange and EMS, explicit DER roots and
ASCII DNS reference identity. It offers the two existing AES128-GCM P256 suites,
with exact ECDSA-SHA256/RSA-PKCS1-SHA256 schemes, optional one-protocol ALPN and
optional one imported client identity, and no resumption or renegotiation. Unsupported negotiation
fails; no verification-disable or legacy-master branch is introduced. This
private structure remains internal; the opaque client facade described below
exposes this finite profile. This scope does not qualify all of #188/#219.

One progress owner exclusively owns fixed root/peer-chain buffers (4096 bytes,
at most five certificates each), the existing eight-slot assembler, transcript,
ephemeral/traffic secrets, at most five immutable flight bodies of 4114 bytes,
one stable native-send buffer and one bounded decrypted-record scratch buffer.
Config data is copied at initialization; optional existing peer policy is
retained once until quiescent clear. Application callbacks borrow one complete
authenticated record only for the callback, with no reentry. Certificate path,
time, purpose, name/constraints and proof verification precede READY; peer policy
runs once after Finished, with certificate verification repeated before READY.

Output prepare reserves a new record sequence and lends one immutable datagram
until the caller reports its actual send terminal. While output is pending or a
flight remains unsent, input returns BUSY without consumption; the future native
adapter must retain that input and route all actual terminals first. Retries
rebuild records from retained flight plaintext using fresh record sequences;
logical handshake messages hash once. A repeated current HelloVerifyRequest or
complete previous ServerHelloDone also requests retransmission before timeout,
sharing the same six-retry budget and exponential backoff. Partial old messages
never reset a timer. Timers arm only after whole-flight send terminals. Abort
erases secrets but preserves a pending wire buffer; clear
rejects outstanding native borrows. Native integration/drain remains separate.
Malformed records/bad tags/wrong epochs/replays are discard outcomes; invalid
authenticated Finished/policy/alert, retry exhaustion and clock rollback are
terminal. One queued application send is bounded by the 1200-byte datagram;
there is no application replay or hidden worker. Close uses an authenticated
close_notify and waits for its actual local send terminal before erasing keys.

`crypto.algorithms.dtls_client_independent` exercises the whole private client
against an independent Python wire oracle. It computes ECDHE signatures and
the complete EMS/Finished transcript independently, exercises ECDSA and RSA
leaf identities, mandatory EMS/ALPN negotiation, DER certificate path/time/
DNS/usage/critical-extension/name-constraint failures, real intermediate chains,
optional ALPN, renewed cookies, reordered/overlapping certificate and Finished
fragments and final-flight loss. Authenticated Finished can arrive before CCS,
but READY and peer policy still wait for both. Epoch-zero Finished fragments
cannot occupy authenticated message slots. A bad tag cannot poison replay
state. Application data stays behind READY, preserves individual record/empty
message boundaries and honors one-send backpressure. Abort during an encrypted
send erases keys while retaining the immutable wire until its terminal.

`crypto.algorithms.dtls_client_pion` additionally runs real UDP loopback against
[Pion DTLS v3.1.15](https://github.com/pion/dtls/tree/v3.1.15). Twelve cases cover
ECDSA/RSA servers, absent/P256/RSA client credentials, with/without loss of the
first native Finished, MTU-512 peer handshake
fragmentation, native client certificate fragmentation, mutual Finished proof, bidirectional application data and
authenticated close. The Go adapter reports local UDP send returns to the
private owner; it does not exercise NativeIO, CNet/SCTP or their cancellation
and whole-batch routing contracts. Current execution is native Windows x64
Release; no sanitizer, other OS or production-readiness claim follows.

Dependency decision: the existing scripted oracle cannot detect every shared
interpretation mistake, and this repository had no independent DTLS stack.
Pion reuses the existing Go test toolchain and module/cache mechanism, uses MIT
licensing and pure Go (`CGO_ENABLED=0`), and introduces no SDK ABI, vcpkg package
or production crypto provider. OpenSSL/BoringSSL are excluded by project scope;
adding another native test executable dependency would add platform setup while
leaving the existing Go peer infrastructure unused. The module is exact-pinned
with checksums and no local upstream modifications; removing the Pion test and
its isolated module reverses the test-only dependency. License provenance is
recorded in the root `THIRD_PARTY_NOTICES.md`.

The selected version follows the upstream fixes for
[signature-scheme confusion (3.1.13)](https://github.com/pion/dtls/security/advisories/GHSA-7c2r-jhm9-43vf)
and [premature session caching (3.1.14)](https://github.com/pion/dtls/security/advisories/GHSA-hhpj-h56m-9f2p).
This check is not a claim that the library has no other security defects. The
test peer has no session store, requires verified client authentication in its
mTLS cases, uses bounded
connection deadlines and joins/cleans its processes/connections. The server
contract below extends this client-only evidence to server authentication and
required mTLS. General signature/group policies, SCTP admission and broader
PKIX/DTLS qualification remain open. The finite public client/server and their
actual NativeIO evidence are described below.

## Private DTLS server owner contract

The server implementation uses an immutable listener context: existing memory
credentials import/binding owns one GmSSL signing key and certificate chain,
the stateless cookie context, optional exact DNS/SNI and optional ALPN, and optional
mandatory client-certificate roots/peer policy. Raw DER/PEM, bounded encrypted
PKCS8 and immutable credential objects use the established credentials entry.
Context lifecycle/admission is exclusive; stream leases are atomic so separate
stream owners can drain concurrently. Context clear returns BUSY while a stream
lease remains; streams return their lease only at quiescent clear. No password,
configuration byte pointer or borrowed credential-object storage survives init.

Cookie validation precedes stream admission, ephemeral key generation and a
listener lease. The stream copies a verified ClientHello into its canonical
transcript and owns eight bounded assembly slots, at most five handshake flight
bodies (each <=4096 DER chain bytes plus vector framing), one 1200-byte pending
wire and one bounded scratch record. Certificate messages fragment under this
MTU. The server uses GmSSL signing/ECDH/AEAD and strict P256/SHA256 RSA/ECDSA
negotiation with mandatory EMS; unsupported identity/scheme combinations fail.
Unknown well-formed ClientHello extensions are ignored as required by TLS;
duplicate/malformed or incompatible mandatory extensions are rejected.

Required mTLS sends CertificateRequest, verifies the client path/time/usage,
verifies CertificateVerify over the canonical DTLS transcript, derives EMS
through ClientKeyExchange, then verifies client Finished before peer policy.
Server Finished is sent only after all admission checks; server READY waits
for its actual send terminal. The final proof bytes remain bounded for reacting
to retransmitted authenticated client Finished throughout the active connection,
including the RFC6347 last-flight retention interval; no master secret is needed
for resealing. Application callbacks, pending-send/abort/drain/close and timer
failure follow the existing exclusive owner contracts. The opaque server facade
and CNet admission below retain those same leases and wire borrows.

SNI configuration is explicit. NULL/0 selects the sole fixed identity without
using SNI for routing or admission; a nonempty configured DNS name requires a
matching ClientHello name and the empty ServerHello acknowledgment required by
[RFC6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).
There is no peer detection, retry with another policy, or automatic disabling of
configured SNI checks. Pion v3.1.15's shared
[ServerName parser](https://github.com/pion/dtls/blob/v3.1.15/pkg/protocol/extension/server_name.go)
requires a nonempty name list even in ServerHello and drops this valid empty
acknowledgment. Pion UDP tests therefore explicitly configure the fixed-identity
context; Pion still verifies the server's root/chain and DNS certificate identity.
The independent Python client oracle tests configured SNI: it verifies the
acknowledgment, actual ECDHE signature and complete EMS/Finished transcript for
both ECDSA and RSA, rejects the wrong name without a different-policy retry,
and checks authenticated bad Finished, bad tags/replay, final-flight resealing
and abort while encrypted output is pending. No upstream module is modified.

`crypto.algorithms.dtls_server_pion` covers 16 positive UDP combinations:
two server identities, server authentication or P256/RSA mTLS (including
CertificateVerify/Finished reordering), with/without loss of the first server
Finished. A noncritical padding extension makes the server certificate cross
the actual 1200-byte fragmentation boundary; the peer uses MTU 512. Nine
negative cases cover a missing client identity, untrusted CA, wrong EKU,
corrupted CertificateVerify/signature-scheme mismatch, peer policy rejection,
missing EMS, incompatible ALPN and unsupported group. Policy runs once per
admitted authenticated client and does not rerun when the final flight repeats.
Raw credentials and predecoded credential objects both complete handshakes.

TinyTest adds proof-of-address rejection before any stream lease, independent
fresh server randoms under a shared listener, two outstanding leases, context
clear rejection during stream ownership, stable pending wire through abort,
actual terminal drain, mismatched private-key rejection and policy-reference
balance. DNS, exact chain metadata and outer datagram framing have one shared
private implementation in `crypto_dtls_wire`, used by both roles. Fragmented
flight storage remains server-owned; received plaintext never occupies an
authenticated Finished slot. Future-epoch records before ECDH key derivation
are discarded; after derivation a reordered authenticated Finished waits for
CertificateVerify/CCS rather than bypassing proof or publishing READY.

Both protocol structures stay internal; the client now has the opaque facade
below. General credential-list/signature/group policies, SCTP admission and
broader platform/PKIX qualification remain open.

## Private DTLS client certificate authentication

The optional `crypto_dtls_client_config.credentials` is one existing
`crypto_tls_credentials` input, consumed exclusively during client initialization.
The established memory importer validates key/chain binding and owns independent
decoded key state; raw buffers, password bytes and credential-object storage are
not retained. DER/PEM/encrypted PKCS8 and objects follow that existing import
contract. This private profile admits one RSA or P256 key and at most five
certificates totaling 4096 DER bytes, with ECDSA-SHA256/RSA-PKCS1-SHA256 certificate
signatures. Invalid identity configuration fails before ClientHello or peer-policy
retention. No alternate provider, file lookup or handshake credential callback is
introduced.

CertificateRequest is accepted exactly once, between ServerKeyExchange and
ServerHelloDone. It is part of the canonical transcript, with the shifted peer
Finished sequence tracked from the actual Done message. Types, nonempty even
signature vector and the complete CA-name vector must parse before selection;
every DER name's RDN contents are checked even after an earlier matching name.
Selection requires the key's signing type/scheme and each chain signature in the
request's shared list. A nonempty CA list must match an issuer in the configured
chain using the native DER-name comparison (no general name normalization or
path discovery). CA hints do not supply trust. If no suitable identity exists,
the protocol requires an empty Certificate and no CertificateVerify; only an
explicit optional-auth server can then complete the handshake. No certificate is
sent without a request. See [RFC5246 sections 7.4.4/7.4.6/7.4.8](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.4).

The final flight owns Certificate, ClientKeyExchange, CertificateVerify, CCS and
Finished (at most five messages). The certificate body bound is 4096 DER bytes
plus five three-byte lengths and one three-byte list length, i.e. 4114 bytes.
It is fragmented at the existing 1200-byte wire MTU; the same one-owner pending
send/actual-terminal/BUSY contract applies to every fragment. EMS snapshots the
transcript through ClientKeyExchange, including Certificate; CertificateVerify
signs that digest with GmSSL's ECDSA/RSA primitives, then Finished uses the
transcript including CertificateVerify. The canonical DTLS headers are included
once, regardless of fragmentation or retransmission, as required by
[RFC6347 section 4.2.6](https://www.rfc-editor.org/rfc/rfc6347.html#section-4.2.6).
The imported identity/key is erased after final-flight construction or on failure;
cached messages permit retransmission with fresh record sequences and the exact
same proof, without a signing key. Abort erases all secrets while preserving an
outstanding native wire borrow through its actual terminal.

The formal Python client oracle independently checks client certificate bytes,
ECDSA/RSA CertificateVerify, EMS and both Finished values. It covers raw/object
identities, renewed/reordered peer messages, root/intermediate hints, request
type/scheme/chain-signature mismatch, no identity, malformed/trailing names,
duplicate requests, no-request identity privacy, retransmission and abort with a
pending Certificate. The Pion client suite additionally requires actual mTLS,
validates certificate trust/purpose/proof, and forces native certificate
fragmentation with a legitimate noncritical padding extension. TinyTest checks
initialization rejection before retain, input independence and key erasure during
abort with a borrowed wire. These extend private-owner evidence only; they do not
qualify public DTLS, NativeIO/CNet transport, every credential encoding on this
wire, general PKIX, sanitizers or other operating systems.

## Private DTLS exporter and master retention

Both private owners accept an explicit `enable_exporter` at initialization
(on the listener context for the server). It defaults to false. Export only
succeeds on the exclusive progress owner in authenticated READY, outside any
callback. Client READY still requires peer Finished, CCS, certificate admission
and policy; server READY additionally requires its final Finished's actual send
terminal. Pending application/retransmission sends do not invalidate READY; an
export never mutates their wire, timer, transcript or sequence state.

**HIGH — security/lifetime tradeoff:** the TLS1.2 exporter requires the original
48-byte EMS master. Default sessions continue erasing that master on admission.
An enabled session retains the same owned master in its existing secrets state,
without a second copy or global cache, until close is accepted (including a
peer-initiated close), abort, failure or clear. Close admission erases it before
the pending close_notify's actual terminal, while record keys remain valid until
that terminal. The `master_live` fact prevents derivation/Finished use after
erasure. Callers own and must erase exported material independently.

Alternatives considered: predeclared labels with cached outputs would preserve
early master erasure but could not accept application context selected after
handshake; unconditional retention would extend every session's secret lifetime.
The explicit opt-in allows dynamic exporter requests while preserving the default
erasure contract. This is a private API change only; disable the option to restore
the default lifecycle. It adds no provider/dependency or session persistence.

The primitive follows [RFC5705 section 4](https://www.rfc-editor.org/rfc/rfc5705.html#section-4):
SHA256 TLS PRF over master, label, client_random then server_random, and, when
requested, uint16 context length plus exact context bytes. Absent context and a
present empty context produce distinct values. EMS remains mandatory. This finite
profile admits 1..255 printable ASCII label bytes, 0..1024 context bytes and
1..1024 output bytes; no output is published for bounds/state/alias errors.
Output is caller-owned and fixed-size; inputs are call-scoped borrows. PRF failure
propagates ECRYPTO and clears output through the native PRF failure contract.
No automatic retry or alternate derivation is introduced.

Reserved handshake labels, their prefixes/extensions (including `extended master
secret`) and embedded NUL/nonprintable labels are rejected, preventing use as a
handshake PRF oracle. The application chooses registered labels or private
EXPERIMENTAL labels and must agree with its peer on purpose/context; the helper
does not perform upper-layer negotiation or enforce all registry prefix rules.
Owner/listener storage and inputs/output cannot overlap. The primitive itself is
private and does not grant authenticated READY; only the owner wrapper does.

Formal Python peers independently derive and compare both roles with absent,
empty and binary/maximal context, multi-block/maximal output, invalid labels and
sizes, pre-READY/default-off/closing/failure refusal, retained-wire export and
post-retransmission stability. Go/Pion UDP tests compare both endpoint roles,
including required mTLS and Finished loss. Pion v3.1.15 explicitly rejects
nonempty context and treats empty as absent, so its qualification covers absent
context only; the independent Python oracle covers context semantics without
modifying Pion. TinyTest covers bounds/aliases, callback admission and master
erasure without damaging traffic epochs. Test adapters clear exported bytes after
delivery and during error cleanup, and report mismatches without printing keys.
No SRTP/SCTP negotiation, public DTLS API, sanitizer or cross-platform production
qualification follows from exporter agreement.

## Private DTLS fatal alert delivery

The two private owners distinguish protocol rejection, peer alerts and local
abort/I/O/clock failures. A rejected post-cookie handshake or authenticated
protocol message can prepare one fatal alert. This never grants READY or accepts
application data. Bad outer framing, wrong epoch, replay and bad AEAD tags retain
their discard behavior; an authenticated bad Finished remains terminal. Cookie
validation still precedes server stream admission; no fatal response is prepared
for an unverified address or a client without its admitted cookie.

The alert uses the local **current write epoch**, which advances only when the
CCS datagram has an actual successful local send terminal. Having derived traffic
keys is insufficient. For example, a server rejecting the client's encrypted
Finished before sending its own CCS emits an epoch-zero plaintext alert; a client
rejecting server Finished after sending its CCS emits an epoch-one AES-GCM alert.
The existing GmSSL-backed record primitive reserves that record's sequence/nonce.
If encryption or sequence admission fails, the owner records the alert error and
does not substitute plaintext. See [RFC6347 record epochs](https://www.rfc-editor.org/rfc/rfc6347.html#section-4.1)
and [TLS error alerts](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.2.2).

**HIGH — failure/drain contract:** alert preparation occurs before write-key
erasure. Finished has a private pure check so the owner can seal a failure alert,
then immediately erase both traffic epochs, master, ephemeral key, transcript,
scratch and outstanding logical flight. The existing destructive Finished verifier
still erases on failed proof. Only the sealed alert (15 bytes plaintext or 39 bytes
encrypted) survives; no signing/record key is retained to service a failed session.
The first protocol error remains the owner failure, while a separate alert error
records construction/send failure. No recovery or alternate implementation runs.

The owner remains FAILED. After a negative receive result, callers may drain the
single prepared alert through `next` and report exactly one actual `sent` terminal.
`next` returns OK with that datagram; further preparation returns BUSY until its
terminal. `sent` returns the original failure even if the alert's local send
succeeds. After that, `next` returns the original failure, with no automatic
retry/timer or re-admission. This follows the non-retransmitted-alert rule in
[RFC6347 section 4.2.7](https://www.rfc-editor.org/rfc/rfc6347.html#section-4.2.7).
The terminated association does not retain keys to generate fresh alerts for later
repeats; this is an explicit bounded shutdown choice, not a retransmission service.

Abort discards an alert that has not been handed to native I/O. Once output is
borrowed, abort preserves those exact bytes and clear returns BUSY until the real
terminal, just as for normal output. Clear may discard an unprepared alert. Server
context leases still release only when the stream clears; sibling contexts and
owners remain live. Both CNet roles below drain this error output and all
previously prepared operations before reclaim.

The finite description mapping includes handshake_failure for negotiation,
decode_error for malformed request/CCS/alert encodings, certificate_unknown for
path rejection, decrypt_error for signed parameters, CertificateVerify and
Finished proof failures, access_denied for peer policy, and internal_error for
an application callback failure. This is not a full per-X509-error alert taxonomy.
An incoming well-formed fatal alert records its peer description, terminates and
erases secrets without echo. Once peer CCS or authenticated epoch-one traffic has
been observed, epoch-zero alerts are ignored; unauthenticated alerts cannot kill
an established connection. Malformed authenticated alerts remain terminal.
After READY (or the server's verified client Finished while its final flight is
pending), all epoch-zero records are discarded before handshake parsing. A
malformed or unknown plaintext handshake cannot erase established traffic keys;
the same malformed handshake in an authenticated epoch-one record remains fatal.

Python formal peers verify plaintext/encrypted alert bytes in both directions,
actual write epoch, post-READY forged Finished, immediate secret erasure, stable
pending output, failed send preserving the original error, no retries, peer fatal
without echo and bad-tag/late-plaintext rejection. TinyTest additionally forces
nonce exhaustion to verify a missing encrypted alert cannot turn into plaintext,
and covers borrow/abort/clear plus pure-versus-destructive Finished checks.

Pion UDP tests receive real native alerts: nine server-side admission rejects and
four native-client policy rejects after peer Finished. Pion exposes handshake
alerts as errors but returns EOF from Read for a post-handshake fatal. The latter
test therefore requires its independently decoded AccessDenied classification,
observed through the existing logger interface, as well as EOF; EOF alone cannot
pass. The observer keeps one atomic boolean, discards other logger output and
retains/prints no packets, keys or session data. `pion/logging` v0.2.4 was already
pinned transitively and is now an explicit test import; its version/license and
all dependency checksums remain unchanged. No upstream patches or wire rewrite.

Remaining DTLS work includes general negotiation/identity policies and wider
PKIX/platform/sanitizer qualification. SCTP composition and bounded supplied-chain
PKIX evidence are extended below. Fatal delivery does not close
#188/#219 or qualify production DTLS by itself.

## Opaque DTLS client and CNet datagram composition

`<crypto/dtls_stream.h>` exposes a complete finite client profile: DTLS1.2,
mandatory cookie exchange and EMS, P256 ECDHE, AES128-GCM, ECDSA/RSA SHA256,
required explicit DER/PEM roots and ASCII DNS identity, optional single ALPN,
one imported client identity and retained peer policy. It introduces no new
provider, verification bypass, resumption or renegotiation. The listener/accept
entry below separately supports the finite server profile.
The private client/server structures and all GmSSL types stay internal.

Creation copies configuration, roots and credentials; their byte/object/password
borrows end on return. Roots and each peer chain have a 4096-byte/five-certificate
bound. The peer policy retains once until successful destroy. One exclusive
owner drives the stream; the application callback borrows one authenticated
record only until return and cannot mutate the stream recursively. Destroy
also refuses recursion from the policy release callback. Invalid input fails
before publication; failed creation leaves a nonaliasing output slot NULL.

`next` borrows one immutable wire datagram until exactly one `sent` terminal.
`CRYPTO_DTLS_BUSY` consumes no new input and preserves that borrow; IDLE means no
output, DROP means an unauthenticated record discard. Negative Crypto status
terminates or rejects according to the public operation contract; allocation
failure is `CRYPTO_DTLS_ENOMEM`. Accepted asynchronous output must await its real
terminal even after abort. FAILED can still publish one sealed fatal, with the
first failure preserved. Destroy returns BUSY with a prepared wire; it performs
no I/O or waiting. These are the same verified owner/erasure semantics described
above, accessed without exposing its layout.

`<cnet/dtls.h>` borrows an already bound CNet datagram and fixed numeric peer.
The host owns raw observation, receive credits, callback routing and any shared
NativeIO backend. The bridge owns the Crypto client, 1..64 preallocated input
slots (each at most 16421 wire bytes), one application tag and one prepared wire.
Application datagrams are copied, including empty messages, with a 1163-byte
limit under the 1200-byte output MTU. Input ENOBUFS consumes nothing; the host
must retain/retry the borrowed packet before its raw receive view expires.
No worker, second poll owner, backend ownership or raw observer replacement is
introduced. See [CNet ownership and architecture](../../docs/CNET-POLICY-HIERARCHY.md#dtls-client-composition-with-a-borrowed-datagram).

A successful application admission is pending before wire preparation. Its one
callback reports the actual local send outcome, not peer acknowledgment. Abort
before native admission reports cancellation once; abort after native admission
keeps the borrow and reports the real terminal. A first bridge failure rejects
new admission immediately while advance/send routing still drains a fatal or
previously submitted output. Application callback errors retain their original
negative Salts status, separately from Crypto diagnostics. Close only queues
authenticated shutdown; the host drives to CLOSED to deliver it. The host retires
input routing after failure/abort, routes the whole observed batch even on error,
and destroys only after its own routing and native borrows are quiescent.

Formal `saltscore.cnet_dtls_native` runs actual NativeIO UDP against the existing
independent Pion v3.1.15 peer: fourteen ordinary/external client scenarios cover
ECDSA/RSA, required mTLS, policy/callback failure with decoded fatal alerts,
maximum/oversize/empty application messages, exporter agreement, copied/full
input admission, foreign-source filtering, exact tagged send settlement and
abort before/after native application submission. Three more cases cover pending
handshake output drain, including backend-capacity nonadmission. Shared-backend
neighbors progress during failure and after bridge destroy. Wrong/duplicate send
tags, callback mutation reentry and retained policy release are checked. The
existing Pion version/licenses are reused in CNet's formal Go test module; CGO
is disabled. `saltscore.cnet_dtls_cpp17` checks public C++17 declarations and
linked C symbols. The Crypto handshake test also checks opaque creation,
independent root storage, pending-wire destroy and recursive policy release.

The complete native-release-user graph and the affected tests passed locally
on Windows x64 LLVM-MinGW Release with IOCP. This does not qualify Linux/macOS
runtime branches, sanitizers, SCTP, general PKIX/negotiation policy or the
remaining #219 software scope. The server extension follows below. Export stays
explicitly opt-in, and callers own/erase exported bytes as documented above.

## Opaque DTLS server listener and native admission

`crypto_dtls_listener_create` imports one RSA/P256 identity and optional explicit
required-mTLS roots/peer policy into an immutable context. Configuration bytes,
credential objects and passwords are borrowed only through create; imported
keys/roots have independent storage. The listener retains policy once, not once
per stream. Its random cookie key has an explicit 1..60000-ms lifetime bound for
issued proofs; replacing that key requires draining/destroying the listener,
not hot reload. Destroy is BUSY with any stream lease and rejects recursive
policy-release destruction. Create/admission/destroy require lifecycle exclusion;
separate admitted stream owners can progress independently. Gates may borrow
the immutable context concurrently while lifecycle operations are excluded.

`crypto_dtls_listener_gate` borrows explicit canonical peer bytes including
family/IP/port, at most 32 bytes. It allocates no peer/stream state and acquires
no lease. A valid first ClientHello without current proof yields one 60-byte
HelloVerifyRequest, never larger than its triggering packet. Malformed packets
return DROP, with no reply/address proof. Argument/state/crypto errors remain
negative; overlapping outputs/inputs/context are rejected without overwriting
them. A future timestamp with valid MAC remains a clock error. Cookie validity
establishes return routability only, not peer authentication or protocol READY.

`crypto_dtls_stream_accept` independently rechecks that cookie before allocating
the opaque stream or taking its listener lease. DROP/negative publishes no
stream. OK publishes an admitted owner: if post-cookie negotiation already
failed, get_info reports FAILED/the original error, and next/sent still drains
its one sealed fatal. This is explicit ownership admission, not successful
authentication or warning-and-continue. READY still requires trust/proof/policy
and the actual server Finished send terminal. Both roles then share next/sent,
receive/write, close, exporter, abort and destroy, with no parallel versioned API.
Destroying the stream releases its lease; it never destroys the shared listener.
The host owns bounded peer admission, duplicate association rejection and rate
limits, and must not create two live routed owners for the same association.

CNet consumers use `cnet_dtls_listener_create`/`cnet_dtls_listener_destroy` so the
opaque listener is created by the same physical Crypto instance inside the
existing CNet DSO. They return Salts statuses, including EBUSY for live leases.
Do not additionally link a static Crypto archive into that consumer. CNet's
`cnet_dtls_cookie_gate` encodes family, address, network-order port and IPv6 scope
without native sockaddr padding; malformed input maps to OK/no proof/no reply.
`cnet_dtls_accept` requires a verified cookie-bearing datagram and returns EPROTO
without publishing an owner on invalid proof. Successful admission consumes the
borrowed packet and uses the same bounded ring/send bridge as the client.

The host sends cookie replies through raw datagram send under a separate tag
namespace, retains its reply reservation through the real terminal and budgets
receive credits accordingly. The formal host uses one reservation and one peer
slot. Accepted streams use their own tag domains; no retry/resubmission of an
accepted native send is introduced. A first failure on a newly admitted FAILED
stream is latched at its next advance, before fatal submission; get_info already
reports the security failure immediately after accept. No extra post-observe
advance is needed. Stop admissions, drain cookie sends and all stream I/O,
destroy streams, then listener and raw transport. Neighboring users remain live.

The initial module-owned `saltscore.cnet_dtls_native` slice includes 24 server
scenarios (12 ordinary and 12 external): ECDSA/RSA server identity, mTLS, missing
or untrusted client identity, policy rejection, strict SNI mismatch, unsupported
ALPN/EMS, callback failure with encrypted fatal, and abort before/after actual
application submission. Positive paths verify maximum/oversize/empty datagrams,
exporter agreement, authenticated close and exact tagged local terminals.
Malformed real UDP input before cookie exchange creates no stream/reply. Every
case requires an actual cookie send terminal; live-stream listener destroy is
BUSY, policy survives bridge teardown until listener destroy, and shared IOCP
neighbors progress through failure and final teardown. Together with the client,
that slice has 41 NativeIO scenarios. Crypto TinyTest checks two shared opaque leases,
wrong-address proof, malformed/aliased gate rejection, pending wire stability,
abort/drain and recursive policy release. C++17 links the CNet listener entry.

Pion positive server cases explicitly use the documented fixed-identity mode:
v3.1.15 cannot decode a valid empty SNI acknowledgment. It still verifies CA/DNS
and signed key exchange. The native strict mismatch test requires an actual
decoded rejection; strict positive SNI's existing independent Python oracle
continues to qualify its complete cryptographic wire behavior. No automatic
policy change, wire rewrite, upstream patch or additional provider is used.

For that slice, the full native-release-user graph built and 13 affected/adjacent CTests passed
on Windows x64 LLVM-MinGW Release, including the sole-Crypto-owner audit and
existing owner regressions. Native runtime evidence remains IOCP/IPv4; concurrent
multi-peer native load, IPv6 runtime, Linux/macOS, sanitizers, SCTP and general
negotiation/PKIX qualification are not established by those initial tests. The
subsequent evidence below extends SCTP, supplied-chain PKIX and multi-peer load.
#188/#219 and the overall local software pass remain open.

## SCTP composition and authenticated delivery backpressure

`Salts::SCTPDTLS`, owned by the SCTP module, now connects the existing bounded
C11 Session to `<cnet/dtls.h>`. It borrows both owners and provides no second
SCTP engine, observer/backend or crypto provider. `Salts::SCTP` remains
provider-independent. CNet assigns an immutable nonzero association binding;
Session must match it before initialization and every bridge reservation/
advance. Replacement at the same public wrapper address cannot authorize old
Session DATA under new keys. Identity/tag exhaustion fails rather than wraps.

The bridge copies 1..64 SCTP input packets (<=1280 bytes), reserves a single
1163-byte output slot before Session output can commit and forwards real
tagged local sends. SCTP cumulative ACKs, DCEP readiness, local terminals and
business delivery remain separate. Abort never destroys borrowed DTLS or the
shared backend; drain continues through actual callbacks before bridge destroy.
See the [host contract and example](../../sctp/README.md#cnet-dtls-bridge).

Actual 24 KiB SCTP traffic exposed a correctness gap: a full application queue
previously became a fatal callback error. CNet `on_receive` now treats only
`SALTS_ENOBUFS` as non-consuming delivery backpressure; it maps to Crypto
`CRYPTO_DTLS_BUSY`. Crypto owns one authenticated plaintext record (16384-byte
capacity, including a distinct pending flag for zero-length input) plus the
remaining encrypted datagram tail (16421-byte capacity). Whole-datagram framing
is preflighted before admission; later progress retries delivery without
decrypting the same record or consuming replay state twice. New raw input is
refused while these bounded obligations remain. Output storage remains separate.
`pending_receive` exposes retained work; close waits, and failure/abort erases
it. Invalid output descriptors fail before callbacks, and mutation reentry is
refused. A terminal error during deferred delivery seals fatal80 and preserves
the concrete CNet error. It is never changed into success or a capacity increase.

The new `crypto_dtls_stream_hmac` / `cnet_dtls_hmac` helper derives 32 bytes
using an opt-in READY exporter request, computes GmSSL HMAC-SHA256 on <=4096
bytes, then erases temporary key/context. Invalid arguments/state leave output
unchanged. CNet consumers call through its existing sole Crypto owner. Exporters
are shared with the peer: authenticating a server-private cookie also requires
an independent private secret. The formal SCTP provider supplies an OS-random
32-byte private per-association exporter context, keeps it off the wire and
erases it at cleanup. The independent peer verifies an ordinary exporter HMAC
and separately confirms the private-context MAC differs; no key/proof logs.

The module-owned `saltscore.sctp_dtls_native` has ten scenarios: eight native
server cases (ordinary/external, 1/4/8 mixed or 8 healthy peers) and two native
client cases. Across 44 actual DTLS attempts there are four untrusted peers,
four canceled after DCEP and 36 healthy peers. Each healthy peer exchanges four
messages (1 byte, 1024 bytes, 24576 bytes, logical-empty binary PPID57), and
native receipt accounting requires exactly four cumulative ACKs. The bridge
uses one ingress slot. The independent peer coalesces two already encrypted
application records into one real UDP datagram to exercise retained wire tails.
No packet/key rewriting or alternate protocol implementation is introduced.

Negative cases cover wrong binding/Owner, reservation/capacity, wrong/duplicate
send tags and same-address DTLS replacement. Failed/canceled peers do not stop
siblings. Healthy peer workers remain connected until cumulative ACK/drain;
closing them early produced actual Winsock ICMP10054 and was fixed at fixture
lifetime ownership rather than ignored. External tests use one four-request,
two-endpoint NativeIO backend and a live neighboring raw datagram through full
association/listener teardown. This is functional concurrent load, not a
throughput benchmark, encrypted packet-loss or browser qualification.

The existing CNet CTest also adds nonempty/empty deferred delivery and deferred
fatal cases in both roles/modes: 53 base scenarios plus the 60 PKIX cases below,
113 total. Empty records must be delivered once despite repeated backpressure.
The existing opaque Crypto TinyTest rejects pre-READY HMAC, oversized/aliased
input and checks unchanged output. Session TinyTest checks query clearing and
Owner/closed refusal without changing the established Session ABI version.

## Broader PKIX supplied-chain qualification

The existing formal `saltscore.cnet_dtls_native` now independently qualifies
15 certificate profiles in each native DTLS role and ordinary/external mode,
60 real handshake cases. Go generates, signs and parses fixtures independently
and checks their expected x509 result before native execution. Go's verifier
does not enforce the leaf TLS signing KU, so that one fixture explicitly
documents its native protocol-specific rejection expectation.

Profiles are: valid leaf plus two intermediates; same-name anchors with the
wrong root first; expired/future certificates; path length; non-CA issuer;
CA signing KU; CA EKU restriction; intermediate and configured-root DNS
constraints; leaf signing KU; wrong leaf EKU; unknown critical extension;
bad signature; and required explicit policy without a certificate policy.
Positive cases require READY and exactly one peer-policy callback. Negative
cases require an independently decoded CertificateUnknown fatal, no READY and
no peer-policy admission; EOF alone is insufficient. Actual fatal output is
drained before teardown. The existing provider passed these cases without
adding a new production dependency or modifying its sources in this step.

This is evidence for the bounded supplied-chain/anchor profile, not arbitrary
path discovery, AIA fetching, WebPKI or a general positive policy-tree engine.
Existing chain limits (five certificates, 4096 DER bytes) remain unchanged.
Rejecting required explicit policy does not prove positive policy mapping or
the complete [RFC 5280 validation algorithm](https://www.rfc-editor.org/rfc/rfc5280#section-6.1).
SCTP transport composition follows the bounded ownership profile documented
above; full [RFC 8261](https://www.rfc-editor.org/rfc/rfc8261) interoperability
and browser/platform acceptance remain separate gates.

The complete `native-release-user` build graph and 31 affected/adjacent CTests
passed on Windows x64 LLVM-MinGW Release in 28.13 seconds. This includes all
Crypto DTLS tests, C++17 headers, both native DTLS suites, existing SCTP tests
and sole-Crypto-owner/original-owner audits. Subsequent empty-delivery and
Session-query edges passed their two CTests in 8.65 seconds after a complete
graph build. Executables run only through CTest, with `PYTHONOPTIMIZE=1`.
No Linux/macOS/IPv6 runtime, sanitizer, hardware or performance result is claimed.

## TLS1.3 cached-chain expiry qualification (2026-11-10)

The existing module-owned `saltscore.cnet_tls_session_resumption` now covers
expiry of the cached leaf, an intermediate CA and the configured trust anchor.
Each profile first completes an authenticated full handshake, exchanges data
and closes with the same immutable client context/server ticket keys retained.
Only the selected certificate has a short validity window. Go independently
verifies the supplied chain before expiry and verifies that the selected
certificate fails with `x509.Expired` after the boundary. The second handshake
starts after that boundary and must actually select resumption.

Native rejection requires the EXPIRED diagnostic at the exact supplied-chain
index (0 for leaf, 1 for the intermediate, SIZE_MAX for the local trust anchor),
one FAILED terminal, no CONNECTED or application send/receive, and no second
terminal or READY after another nonblocking poll. The retained peer policy is
called only for the first authenticated connection. Existing positive reuse,
disabled cache, ticket refusal, changed policy and changed ALPN controls remain.
No timeout, trust policy, public API, provider or production implementation is
changed. The formal Go timeout remains 60 seconds and its CTest timeout remains
90 seconds; these are distinct expiry inputs, not retries of the original fault.

This extends the supplied-chain session qualification in #219. It does not
reproduce or repair #276's original Windows x64 terminal-counter failure, whose
cause remains unproven. A successful matrix alone must not close that issue.

In an isolated checkout based on merged `abbcb02`, both Windows x64 user
presets (`native-release-user` LLVM-MinGW and `msvc-release-user`) built the
existing `saltscore_cnet_tls_ca_san_test` target against released SaltsBase
v0.1.1 and vcpkg-cache v0.1.2. The three selected formal CTests (standard
resumption, ShangMi resumption and TLS CA/SAN) passed on each compiler. After
the final expiry-gate/terminal-state assertions, the two affected resumption
CTests passed in 29.78 seconds and 29.99 seconds respectively. Reproduce with
the corresponding build preset and `ctest --preset <preset> -R
'session_resumption$' --output-on-failure`. Hosted cross-platform/sanitizer
qualification is separate from these local results.

## GmSSL validity diagnostic qualification (2026-11-10)

The matching SaltsBase 0.1.2 TSan SDK exposes the foundation's atomic handoffs.
With that SDK, the retained release-input CI
[42730173176](https://github.com/qigao/salts-core/actions/runs/42730173176)
isolated a separate `x509_validity_print` race in libc `ctime` storage.
The new module-owned ABI cases compare exact serialized libc text, exercise
16 workers with independent date pairs and files, reject truncated DER, and
on Windows reject dates outside the CRT range. The old-provider baseline
[42734464725](https://github.com/qigao/salts-core/actions/runs/42734464725)
reported five TSan races directly from the diagnostic workers.

The repair belongs to [vcpkg-cache #315](https://github.com/qigao/vcpkg-cache/pull/315),
GmSSL 3.2.0 port revision 45. Caller-owned `ctime_r`/`ctime_s` text preserves
local-time formatting, labels and newlines; conversion errors propagate.
It changes neither public ABI nor TLS verification policy. Candidate full
CTest suites passed on Linux TSan/macOS ARM64 (104/104 each,
[42735560584](https://github.com/qigao/salts-core/actions/runs/42735560584))
and Windows MSVC/LLVM-MinGW (103/103 each,
[42736716536](https://github.com/qigao/salts-core/actions/runs/42736716536)),
including a second-timezone ABI run per platform.

[vcpkg-cache v0.1.3](https://github.com/qigao/vcpkg-cache/releases/tag/v0.1.3)
publishes that repair from `b1febdf10867f0e2cfcd3751bf83acaba3073280` after
[producer 42745308567](https://github.com/qigao/vcpkg-cache/actions/runs/42745308567)
passed all nine platforms. All 283 release assets were checked against their
original SHA-256 and size. Consumer CI selects `VCPKG_CACHE_VERSION` and
`SALTS_BASE_VERSION`; TSan requires `linux-clang-x64-tsan` rather than an
uninstrumented foundation. Public-release consumption still requires the
final exact-head consumer CI; the candidate runs do not establish that result.

Other OCSP/CRL/TLS-trace `ctime` callers remain outside this bounded repair.
Neither this diagnostic qualification nor a successful matrix resolves #276's
original intermittent terminal-counter failure or the remaining #219 gates.

## DTLS issuer validity and DNS constraint qualification (2026-11-10)

The module-owned `saltscore.cnet_dtls_native` extends its supplied-chain PKIX
matrix from 15 to 33 profiles: 33 profiles x two native roles x ordinary/external
progress = 132 actual handshake cases, including 72 new cases. The additional
profiles cover expired/not-yet-valid certificates at both intermediate levels
and the configured local anchor, unknown critical extensions at both
intermediate levels, and permitted/excluded DNS subtrees at an intermediate CA
or the local anchor. Anchor validity/constraints follow this repository's
existing explicit-anchor policy; they are not a claim about every PKIX policy.

Positive constraint cases admit `localhost` alone and together with
`preview.localhost`. Negative cases reject an excluded requested name, an
excluded second SAN, and a second SAN outside a permitted subtree even though
the requested `localhost` identity is allowed. This exercises constraints on
all presented names rather than hostname matching alone; see
[RFC 5280 section 4.2.1.10](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10).
Go independently signs/parses/verifies each fixture. New negative oracles check
the specific time, DNS-constraint or unknown-critical-extension error category,
so an unrelated fixture failure cannot satisfy the intended rejection case.

Existing native assertions remain: positives require READY and exactly one
peer-policy admission; negatives require no READY or peer-policy admission,
the actual CertificateUnknown fatal at the independent peer, drained native
output and successful association/listener teardown. No verification bypass,
timeout change, new public API, provider patch or TinyTest change was needed.
This is bounded supplied-chain qualification, not path discovery, policy-tree
processing, full RFC 8261/browser interoperability or resolution of #276.

With released SaltsBase/vcpkg-cache 0.1.3, the complete `native-release-user`
graph built successfully on Windows x64 LLVM-MinGW. Its three existing DTLS
CTests (C++17 headers, CNet native DTLS and SCTP/DTLS native composition) passed
in 23.73 seconds; the adjacent TLS PKIX name-constraint CTest passed in 1.17
seconds. Reproduce with `cmake/WithVs.cmd cmake --build --preset
native-release-user`, then the same test preset with `-R
'^saltscore[.].*dtls'` and separately `-R 'name_constraints$'`. Hosted CI and
Android device execution are separate evidence; #188/#219 remain open.
