# Crypto-specific ASN.1 formats

This module tests X9.62 ECDSA DER signatures, RFC 8410 X25519/Ed25519
SPKI/PKCS#8 structures and SM2 SPKI/private/encrypted PKCS#8 workflows.

General-purpose ASN.1 Reader/Validator/Encoder, borrowed TLVs, OID and owned
Value Tree live **in the same repository** under `asn1/`, not `crypto/`.
Crypto imports its one static `Salts::ASN1` target and maintains no local
generic BER/DER source, shared legacy ASN.1 facade or second parser.

The root CMake project builds both modules in dependency order. A standalone
`cmake -S crypto` build requires an independently installed
`Salts::ASN1` CMake package. Its `Salts::Crypto` static archive only
contains key-format and cryptographic/TLS code; the ASN1 sibling is linked
and exported as a package dependency. The installed C11/C++17 consumers
must use the real `CryptoConfig`/ `ASN1Config` imports.

`crypto.asn1.sm2_keys` tests public API key binding, canonical DER, bounds,
failure erasure, provider RNG failure and native GmSSL key-file interoperation.
Its RNG override exists only in that executable. `crypto.asn1.sm2_keys_independent`
uses the normal production RNG and a binary pipe peer in the same formal graph;
Python hashlib PBKDF2-HMAC-SM3 and cryptography SM4-CBC independently encrypt
and decrypt the containers. Python dependencies match the existing CI fixtures.
There is no project OpenSSL link or separate consumer verification project.
