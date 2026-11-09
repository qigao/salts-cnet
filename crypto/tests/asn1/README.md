# Crypto-specific ASN.1 formats

This module tests **only** X9.62 ECDSA DER signature encoding/decoding and
RFC 8410 X25519/Ed25519 SPKI/PKCS#8 structures.

General-purpose ASN.1 Reader/Validator/Encoder and Value Tree belong to
`Salts::ASN1`, imported from the separately installed `SaltsBase` package.
Crypto contains only cryptographic key formats and links that single owner.
The network SDK remains available through `find_package(SaltsCore CONFIG REQUIRED)`.

`crypto.asn1.sm2_keys` tests public API key binding, canonical DER, bounds,
failure erasure, provider RNG failure and native GmSSL key-file interoperation.
Its RNG override exists only in that executable. `crypto.asn1.sm2_keys_independent`
uses the normal production RNG and a binary pipe peer in the same formal graph;
Python hashlib PBKDF2-HMAC-SM3 and cryptography SM4-CBC independently encrypt
and decrypt the containers. Python dependencies match the existing CI fixtures.
There is no project OpenSSL link or separate consumer verification project.
