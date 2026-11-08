#ifndef SALTS_CRYPTO_SM2_CMS_ENVELOPE_H
#define SALTS_CRYPTO_SM2_CMS_ENVELOPE_H
#include <crypto/sm2_cms.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
  /* Fits a complete attached SignedData with 64 KiB of application content. */
  SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_CONTENT = SALTS_CRYPTO_SM2_CMS_MAX_DER,
  SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_DER = SALTS_CRYPTO_SM2_CMS_ENVELOPE_MAX_CONTENT + 8192
};
typedef struct salts_crypto_sm2_cms_envelope_recipient {
  const salts_crypto_sm2_chain_entry *chain;
  size_t chain_count;
  /* EMAIL_ENCRYPTION only: explicit pin/anchor/time, emailProtection EKU,
   * keyEncipherment KU and explicit revocation policy. */
  const salts_crypto_sm2_trust_policy *trust;
} salts_crypto_sm2_cms_envelope_recipient;
typedef struct salts_crypto_sm2_cms_envelope_key {
  salts_crypto_sm2_cert_span certificate; /* own recipient certificate DER */
  const uint8_t *private_key; /* 32-byte SM2 key, must match certificate */
} salts_crypto_sm2_cms_envelope_key;

/** Finite RFC5083 AuthEnvelopedData container, one SM2 key-transport recipient
 * identified by issuer/serial, id-data content and SM4-GCM. Uses SM2-encrypt
 * OID 1.2.156.10197.1.301.3, canonical DER SM2 ciphertext, SM4-GCM OID
 * 1.2.156.10197.1.104.8, 12-byte nonce, explicit 16-byte GCM tag parameters
 * and a separate 16-byte mac. No originator/attributes, other algorithms,
 * recipient forms, additional recipients, BER or implicit format selection.
 * This is a finite SM4 CMS profile, not an AES RFC5084 conformance claim.
 *
 * Encrypt authenticates the entire configured recipient path before generating
 * a fresh random 16-byte content key and nonce or publishing ciphertext.
 * EXTERNAL revocation is synchronous, leaf-first, after all path checks, and
 * must not mutate any input or output. Decrypt binds the issuer/serial and
 * private key to the caller's own certificate; it establishes no sender trust.
 * GCM integrity succeeds before any plaintext is published. Anyone with the
 * recipient public key can generate an envelope: sender authentication requires
 * an inner attached SignedData verified with a separate authenticated signer
 * policy before application use. No replay protection is implied.
 *
 * Immutable borrowed inputs until return, no retention/files/clocks/network.
 * Operations allocate <=2*MAX_DER+MAX_CONTENT bytes, securely cleared on every
 * exit. Output capacity must be >=MAX_DER for encrypt, >=MAX_CONTENT for decrypt;
 * output's required bound and written must be disjoint from each other and all
 * input descriptors/bytes. EINVAL preserves output/written. After admission,
 * failure clears exactly that required bound and sets written=0. Encrypt returns
 * EVERIFY for recipient authentication failure, ECRYPTO for allocation/RNG/crypto;
 * decrypt returns EVERIFY for malformed/unsupported/wrong-key/bad-tag inputs,
 * ECRYPTO for allocation failure. No size-query or partially verified output.
 * Success writes only the complete result and updates written, preserving tail.
 */
int salts_crypto_sm2_cms_envelope_encrypt(const salts_crypto_sm2_cms_envelope_recipient *recipient,
    const void *content, size_t content_size, void *output, size_t capacity, size_t *written);
int salts_crypto_sm2_cms_envelope_decrypt(const salts_crypto_sm2_cms_envelope_key *key,
    const void *der, size_t der_size, void *output, size_t capacity, size_t *written);
#ifdef __cplusplus
}
#endif
#endif
