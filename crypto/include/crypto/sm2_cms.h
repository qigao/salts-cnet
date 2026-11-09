#ifndef SALTS_CRYPTO_SM2_CMS_H
#define SALTS_CRYPTO_SM2_CMS_H
#include <crypto/sm2_trust.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
  SALTS_CRYPTO_SM2_CMS_MAX_CONTENT = 64 * 1024,
  SALTS_CRYPTO_SM2_CMS_MAX_DER = SALTS_CRYPTO_SM2_CMS_MAX_CONTENT +
      (SALTS_CRYPTO_SM2_TRUST_MAX_CHAIN + 1) * SALTS_CRYPTO_SM2_TRUST_MAX_CERT_SIZE + 2048
};
typedef enum salts_crypto_sm2_cms_format {
  SALTS_CRYPTO_SM2_CMS_RFC5652 = 1,
  /* National SM2 CMS content-OID family, as used by gmsm/PKCS7. This API
   * qualifies the signed-data profile below, not every message/algorithm
   * combination or a standards certification. */
  SALTS_CRYPTO_SM2_CMS_SHANGMI = 2
} salts_crypto_sm2_cms_format;

typedef struct salts_crypto_sm2_cms_sign_config {
  salts_crypto_sm2_cms_format format;
  bool detached;
  const uint8_t *private_key; /* 32-byte signing scalar; never retained */
  const void *signer_identity; /* explicit SM2 ID, 1..8191 binary bytes */
  size_t signer_identity_size;
  const salts_crypto_sm2_cert_span *certificates; /* leaf first, 1..4, no anchor */
  size_t certificate_count;
} salts_crypto_sm2_cms_sign_config;

typedef struct salts_crypto_sm2_cms_verify_config {
  salts_crypto_sm2_cms_format format;
  bool detached;
  const void *signer_identity; /* signature ID, independent of certificate issuer IDs */
  size_t signer_identity_size;
  const salts_crypto_sm2_chain_entry *chain; /* explicit leaf-first authenticated path */
  size_t chain_count;
  const salts_crypto_sm2_trust_policy *trust;
} salts_crypto_sm2_cms_verify_config;

/** One SM2/SM3 SignedData signer, attached or detached, canonical DER. Formats
 * explicitly select RFC content OIDs or ShangMi content OIDs; no fallback.
 * Signature identifiers are SM2-1 (1.2.156.10197.1.301.1), or SM2-with-SM3
 * (1.2.156.10197.1.501), always with an explicit SM3 digest. No other algorithm
 * alias is admitted. SM3 digest, issuer/serial signer ID and signed contentType +
 * messageDigest attributes are mandatory. Verification also admits a single
 * signed signingTime as metadata, without using it as the validation clock.
 * Other attributes, unsigned attributes, CRLs, extra signers, omitted/extra/
 * duplicate certificates, BER and unsupported algorithms fail. Certificates
 * are encoded in DER SET order; the signing certificate must match the key.
 * Signing checks format/binding, not certificate trust/time/usage.
 *
 * Inputs are immutable borrows until return; no files, clocks, network, retained
 * state or threads. Output and written must be disjoint from each other and
 * all input descriptors/bytes. sign requires capacity >= MAX_DER; it allocates
 * at most 2*MAX_DER+MAX_CONTENT+8 temporary bytes, cleared before freeing.
 * Invalid admission returns EINVAL and preserves output/written. After admission,
 * rejection returns EVERIFY (format/binding), or ECRYPTO (allocation/signing),
 * clears exactly MAX_DER output bytes and sets written=0. Success publishes only
 * the complete DER; bytes beyond written are unchanged. No size-query signing.
 */
int salts_crypto_sm2_cms_sign(const salts_crypto_sm2_cms_sign_config *config,
    const void *content, size_t content_size, void *output, size_t capacity,
    size_t *written);

/** Authenticate the configured signer/path before releasing content. The
 * embedded certificate SET must exactly match config.chain (unordered on wire);
 * it supplies no trust anchors. Mandatory pinned-chain verification enforces
 * explicit validation time, CA/pathLen, signing KU/EKU, per-certificate SM2 issuer IDs,
 * expected signer key and revocation policy. EMAIL_ENCRYPTION is rejected at
 * admission; encryption-only trust cannot authorize a CMS signer. This is the restricted pinned
 * profile in sm2_trust.h, not general WebPKI/path discovery or TLS verification.
 * Only complete signature + content digest + path + revocation success publishes
 * content; malformed CMS never invokes revocation. The callback runs at most
 * once per non-anchor certificate, synchronously, and must not mutate inputs,
 * output or written. A rejected signature never invokes it.
 *
 * Detached content is supplied explicitly, including NULL/0 for empty content;
 * attached mode requires detached_content=NULL and detached_size=0. No mode
 * inference. MAX_CONTENT is 64 KiB. Output requires capacity >= MAX_CONTENT;
 * admission/ownership rules match sign. Admitted failure clears exactly
 * MAX_CONTENT output bytes and written=0. No borrowed or partially verified
 * content escapes. Operational failures return EVERIFY; malformed caller policy
 * returns EINVAL before touching output or invoking callbacks.
 */
int salts_crypto_sm2_cms_verify(const salts_crypto_sm2_cms_verify_config *config,
    const void *der, size_t der_size, const void *detached_content,
    size_t detached_size, void *output, size_t capacity, size_t *written);
#ifdef __cplusplus
}
#endif
#endif
