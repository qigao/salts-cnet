#include <crypto/tls_sm2_crl_policy.h>
#include <crypto/tls_stream.h>
#include <crypto/sm2_crl.h>
#include <crypto/sm2_x509.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct crl_snapshot {
  atomic_size_t references;
  salts_crypto_sm2_cert_span issuer;
  salts_crypto_sm2_crl_policy crl;
  const uint8_t *certificate_identity;
  size_t certificate_identity_size;
  uint8_t issuer_key[65];
  bool peer_is_server;
  crypto_tls_stream_security_profile profile;
  uint8_t bytes[];
} crl_snapshot;

static int64_t current_time(void) {
  int64_t now = (int64_t)time(NULL);
  return now >= 0 && now <= INT64_C(253402300799) ? now : -1;
}
static void retain_snapshot(void *context) {
  crl_snapshot *snapshot = context;
  (void)atomic_fetch_add_explicit(&snapshot->references, 1u, memory_order_relaxed);
}
static void release_snapshot(void *context) {
  crl_snapshot *snapshot = context;
  if (atomic_fetch_sub_explicit(&snapshot->references, 1u, memory_order_acq_rel) == 1u)
    free(snapshot); /* Public certificates/CRLs/identities only; no private material. */
}
static int check_snapshot(void *context, const crypto_tls_stream_peer_certificate_chain *chain,
    bool peer_is_server, crypto_tls_stream_security_profile profile) {
  const crl_snapshot *snapshot = context;
  const size_t leaves = snapshot->profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 ? 2u : 1u;
  if (profile != snapshot->profile ||
      peer_is_server != snapshot->peer_is_server || chain == NULL ||
      chain->count < leaves || chain->count > leaves + 1u)
    return CRYPTO_TLS_STREAM_ECONNABORTED;
  if (chain->count == leaves + 1u && (chain->certificates[leaves].data == NULL ||
      chain->certificates[leaves].size != snapshot->issuer.size ||
      memcmp(chain->certificates[leaves].data, snapshot->issuer.der, snapshot->issuer.size) != 0))
    return CRYPTO_TLS_STREAM_ECONNABORTED;
  for (size_t i = 0u; i < leaves; ++i)
    if (chain->certificates[i].data == NULL || chain->certificates[i].size == 0u ||
        chain->certificates[i].size > SALTS_CRYPTO_SM2_X509_MAX_CERT_SIZE)
      return CRYPTO_TLS_STREAM_ECONNABORTED;
  if (leaves == 2u && chain->certificates[0].size == chain->certificates[1].size &&
      memcmp(chain->certificates[0].data, chain->certificates[1].data, chain->certificates[0].size) == 0)
    return CRYPTO_TLS_STREAM_ECONNABORTED;
  int64_t now = current_time();
  if (now < 0) return CRYPTO_TLS_STREAM_ECONNABORTED;
  for (size_t i = 0u; i < leaves; ++i) {
    const salts_crypto_sm2_cert_span leaf = {chain->certificates[i].data, chain->certificates[i].size};
    if (salts_crypto_sm2_x509_verify_signature(leaf.der, leaf.size,
        snapshot->issuer_key, snapshot->certificate_identity, snapshot->certificate_identity_size) != SALTS_CRYPTO_OK ||
        salts_crypto_sm2_check_crl(&leaf, &snapshot->issuer, now, &snapshot->crl) != SALTS_CRYPTO_OK)
      return CRYPTO_TLS_STREAM_ECONNABORTED;
  }
  return CRYPTO_TLS_STREAM_OK;
}

static int create_policy(const crypto_tls_sm2_crl_config *config,
    crypto_tls_stream_security_profile profile, crypto_tls_stream_peer_policy *out_policy) {
  if (out_policy == NULL) return CRYPTO_TLS_STREAM_EINVAL;
  memset(out_policy, 0, sizeof(*out_policy));
  if (config == NULL || config->size != sizeof(*config) ||
      config->issuer_certificate == NULL || config->issuer_certificate_size == 0u || config->issuer_certificate_size > 4096u ||
      config->crl == NULL || config->crl_size == 0u || config->crl_size > 65536u ||
      config->certificate_signing_identity == NULL || config->certificate_signing_identity_size == 0u || config->certificate_signing_identity_size > 8191u ||
      config->crl_signing_identity == NULL || config->crl_signing_identity_size == 0u || config->crl_signing_identity_size > 8191u ||
      config->maximum_age_seconds == 0u)
    return CRYPTO_TLS_STREAM_EINVAL;
  if (profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 && !config->peer_is_server)
    return CRYPTO_TLS_STREAM_ENOTSUP;
  const salts_crypto_sm2_cert_span issuer = {config->issuer_certificate, config->issuer_certificate_size};
  const salts_crypto_sm2_crl_policy crl = {config->crl, config->crl_size,
      config->crl_signing_identity, config->crl_signing_identity_size,
      config->minimum_crl_number, config->maximum_age_seconds};
  int64_t now = current_time();
  uint8_t key[65];
  if (now < 0) return CRYPTO_TLS_STREAM_EIO;
  if (salts_crypto_sm2_validate_crl(&issuer, now, &crl) != SALTS_CRYPTO_OK ||
      salts_crypto_sm2_x509_public_key(issuer.der, issuer.size, key) != SALTS_CRYPTO_OK)
    return CRYPTO_TLS_STREAM_ECONNABORTED;
  /* Every term is independently bounded above; sum <= 86014, even on 32-bit. */
  size_t bytes = config->issuer_certificate_size + config->crl_size +
      config->certificate_signing_identity_size + config->crl_signing_identity_size;
  crl_snapshot *snapshot = calloc(1u, sizeof(*snapshot) + bytes);
  if (snapshot == NULL) return CRYPTO_TLS_STREAM_ENOMEM;
  atomic_init(&snapshot->references, 1u);
  snapshot->peer_is_server = config->peer_is_server;
  snapshot->profile = profile;
  memcpy(snapshot->issuer_key, key, sizeof(key));
  uint8_t *cursor = snapshot->bytes;
  memcpy(cursor, issuer.der, issuer.size);
  snapshot->issuer = (salts_crypto_sm2_cert_span){cursor, issuer.size};
  cursor += issuer.size;
  memcpy(cursor, crl.der, crl.size);
  snapshot->crl = crl;
  snapshot->crl.der = cursor;
  cursor += crl.size;
  memcpy(cursor, crl.issuer_identity, crl.issuer_identity_size);
  snapshot->crl.issuer_identity = cursor;
  cursor += crl.issuer_identity_size;
  memcpy(cursor, config->certificate_signing_identity, config->certificate_signing_identity_size);
  snapshot->certificate_identity = cursor;
  snapshot->certificate_identity_size = config->certificate_signing_identity_size;
  *out_policy = (crypto_tls_stream_peer_policy){
      .check = check_snapshot, .retain = retain_snapshot, .release = release_snapshot,
      .context = snapshot, .supported_profiles = 1u << profile,
      .supported_peer_roles = config->peer_is_server ? CRYPTO_TLS_PEER_POLICY_SERVER : CRYPTO_TLS_PEER_POLICY_CLIENT};
  return CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_sm2_crl_peer_policy_create(const crypto_tls_sm2_crl_config *config,
    crypto_tls_stream_peer_policy *out_policy) {
  return create_policy(config, CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13, out_policy);
}

int crypto_tlcp_sm2_crl_peer_policy_create(const crypto_tls_sm2_crl_config *config,
    crypto_tls_stream_peer_policy *out_policy) {
  return create_policy(config, CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11, out_policy);
}
