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
| SM9 key exchange | Pending implementation/review; pinned upstream header marks it unfinished | No production claim |
| SM2 full authenticated key exchange | Pending; ordinary ECDH must not be advertised as this protocol | No production claim |
| CMS / SM2 certificate and protected key workflows | CMS enabled in provider; public workflow qualification pending | Generic ASN1 parsing and existing X509 inspection alone do not qualify signing/trust/key protection |
| TLS 1.3 ShangMi / TLCP | Existing explicit stream profiles; complete independent handshake/authentication matrix remains separate | Existing provider settings/KATs do not replace protocol interoperation |
| DTLS | Issue #188 resumed; implementation and CNet/SCTP qualification pending | Existing TLS tests do not qualify DTLS |
| SDF / SKF hardware | Requires selected vendor runtime/device and its integration tests | No software fallback for non-exportable keys |

GmSSL 3.2.0 port revision 20 enables SM9, ZUC and CMS and exports the enabled
algorithm feature definitions. It also clears the PBKDF2 password-derived
template and rejects invalid/infinity uncompressed SM2 points. These changes
belong to the external package, not a duplicate in-tree GmSSL build. Revision 20
preserves the original digest/pairing base and recipient point across SM9
retries, bounds attempts, rejects zero KEM nonces/infinity and cleans up
extraction scalars and KEM/signing working state on error paths.

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
