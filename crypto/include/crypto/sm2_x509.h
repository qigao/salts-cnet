#ifndef SALTS_CRYPTO_SM2_X509_H
#define SALTS_CRYPTO_SM2_X509_H
#include <crypto/status.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define SALTS_CRYPTO_SM2_X509_MAX_CERT_SIZE 4096u

/* Certificate primitives, NOT certificate/path authentication. Each call
 * consumes one complete canonical DER certificate (1..4096 bytes), borrowing
 * inputs only for the call. No allocation, I/O, clock, network or mutable state.
 * NULL/size/overlap admission errors return EINVAL; malformed/unsupported
 * certificates, invalid keys, mismatches and bad signatures return EVERIFY.
 * OK says ONLY that the named operation succeeded. These calls do not enforce
 * validity time, issuer names, CA/basicConstraints/pathLen, KU/EKU, critical
 * extensions, SAN/hostname, policy, revocation or trust-anchor selection.
 * Their results must never substitute for a TLS or application trust decision.
 */

/* Extract and validate a finite curveSM2 public key into caller-owned 65-byte
 * uncompressed storage. The supported SPKI profile is id-ecPublicKey with
 * curveSM2 parameters. Signature algorithm need not be SM2. Output must not
 * overlap certificate bytes. After admission, failure clears exactly 65 bytes;
 * admission errors preserve output. Extracting a key does NOT verify a signature.
 */
int salts_crypto_sm2_x509_public_key(const void *certificate, size_t size,
    uint8_t public_key[65]);

/* Check that the raw private scalar derives the SM2 public key in the
 * certificate. No certificate signature or proof of remote possession is
 * checked. The private scalar [1,N-1] is borrowed and never retained; signing
 * still cannot use N-1. Temporary private material is cleared by its owner.
 */
int salts_crypto_sm2_x509_matches_private_key(const void *certificate, size_t size,
    const uint8_t private_key[32]);

/* Verify the signature over the EXACT encoded TBSCertificate using an
 * explicitly supplied issuer public key and issuer SM2 signing identity
 * (1..8191 bytes, binary, no implicit default or fallback identity).
 * sm2sign-with-sm3 (1.2.156.10197.1.501) AlgorithmIdentifier parameters may be
 * absent or NULL; inner/outer identifiers must match byte-for-byte. Signature
 * is a canonical DER SEQUENCE of two positive in-range integers. The subject
 * key need not be SM2: this operation checks the issuer's signature only.
 * Supplying a key extracted from this same certificate verifies self-signature
 * only; it does not turn the certificate into a trust anchor. Caller must
 * authenticate the issuer key and apply all enclosing certificate policies.
 */
int salts_crypto_sm2_x509_verify_signature(const void *certificate, size_t size,
    const uint8_t issuer_public_key[65], const void *issuer_identity,
    size_t issuer_identity_size);

#ifdef __cplusplus
}
#endif
#endif
