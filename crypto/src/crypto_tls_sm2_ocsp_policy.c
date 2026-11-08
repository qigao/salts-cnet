#include <crypto/tls_sm2_ocsp_policy.h>
#include <crypto/tls_stream.h>
#include <crypto/sm2_ocsp.h>
#include <crypto/sm2_x509.h>
#include "crypto_internal.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct ocsp_snapshot {
  atomic_size_t references;
  salts_crypto_sm2_cert_span issuer;
  salts_crypto_sm2_delegated_ocsp_policy policy;
  const void *certificate_identity;
  size_t certificate_identity_size;
  uint8_t issuer_key[65];
  bool peer_is_server;
  crypto_tls_stream_security_profile profile;
  uint8_t bytes[];
} ocsp_snapshot;
static int64_t current_time(void) {
  time_t sample = time(NULL);
  int64_t now = (int64_t)sample;
  return now >= 0 && now <= INT64_C(253402300799) ? now : -1;
}
static void retain(void *context) {
  ocsp_snapshot *s = context;
  size_t count = atomic_load_explicit(&s->references,memory_order_relaxed);
  do {
    if (count == SIZE_MAX) abort(); /* Infallible retained-policy ownership contract. */
  } while (!atomic_compare_exchange_weak_explicit(&s->references,&count,count+1u,memory_order_relaxed,memory_order_relaxed));
}
static void release(void *context) {
  ocsp_snapshot *s = context;
  if (atomic_fetch_sub_explicit(&s->references,1u,memory_order_acq_rel) == 1u) free(s);
}
static int check(void *context, const crypto_tls_stream_peer_certificate_chain *chain,
    bool peer_is_server, crypto_tls_stream_security_profile profile) {
  const ocsp_snapshot *s = context;
  const size_t leaves = s->profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 ? 2u : 1u;
  if (!chain || profile != s->profile || peer_is_server != s->peer_is_server ||
      chain->count < leaves || chain->count > leaves+1u) return CRYPTO_TLS_STREAM_ECONNABORTED;
  size_t total = 0u;
  for (size_t i = 0u; i < chain->count; ++i) {
    const crypto_tls_stream_peer_certificate *v = chain->certificates+i;
    if (!v->data || !v->size || v->size > CRYPTO_TLS_STREAM_PEER_CHAIN_MAX_BYTES-total) return CRYPTO_TLS_STREAM_ECONNABORTED;
    total += v->size;
  }
  if (chain->total_bytes != total) return CRYPTO_TLS_STREAM_ECONNABORTED;
  if (chain->count == leaves+1u && (chain->certificates[leaves].size != s->issuer.size ||
      memcmp(chain->certificates[leaves].data,s->issuer.der,s->issuer.size))) return CRYPTO_TLS_STREAM_ECONNABORTED;
  if (leaves == 2u && chain->certificates[0].size == chain->certificates[1].size &&
      !memcmp(chain->certificates[0].data,chain->certificates[1].data,chain->certificates[0].size)) return CRYPTO_TLS_STREAM_ECONNABORTED;
  int64_t now = current_time();
  if (now < 0) return CRYPTO_TLS_STREAM_ECONNABORTED;
  for (size_t i = 0u; i < leaves; ++i) {
    salts_crypto_sm2_cert_span leaf = {chain->certificates[i].data,chain->certificates[i].size};
    if (salts_crypto_sm2_x509_verify_signature(leaf.der,leaf.size,s->issuer_key,
        s->certificate_identity,s->certificate_identity_size) != SALTS_CRYPTO_OK ||
        (s->policy.responder_certificate.der ? salts_crypto_sm2_check_delegated_ocsp(&leaf,&s->issuer,now,&s->policy) :
         salts_crypto_sm2_check_direct_ocsp(&leaf,&s->issuer,now,&s->policy.response)) != SALTS_CRYPTO_OK) return CRYPTO_TLS_STREAM_ECONNABORTED;
  }
  return CRYPTO_TLS_STREAM_OK;
}
static int create(const crypto_tls_sm2_ocsp_config *c, crypto_tls_stream_security_profile profile,
    crypto_tls_stream_peer_policy *out) {
  if (!out) return CRYPTO_TLS_STREAM_EINVAL;
  if (c && salts_crypto_overlap(out,sizeof(*out),c,sizeof(*c))) return CRYPTO_TLS_STREAM_EINVAL;
  if (c && (salts_crypto_overlap(out,sizeof(*out),c->issuer_certificate,c->issuer_certificate_size) ||
      salts_crypto_overlap(out,sizeof(*out),c->response,c->response_size) ||
      salts_crypto_overlap(out,sizeof(*out),c->certificate_signing_identity,c->certificate_signing_identity_size) ||
      salts_crypto_overlap(out,sizeof(*out),c->response_signing_identity,c->response_signing_identity_size) ||
      salts_crypto_overlap(out,sizeof(*out),c->responder_certificate,c->responder_certificate_size) ||
      salts_crypto_overlap(out,sizeof(*out),c->responder_issuer_identity,c->responder_issuer_identity_size))) return CRYPTO_TLS_STREAM_EINVAL;

  if (!c || c->size != sizeof(*c) || !c->issuer_certificate || !c->issuer_certificate_size || c->issuer_certificate_size > 4096u ||
      !c->response || !c->response_size || c->response_size > SALTS_CRYPTO_SM2_OCSP_MAX_BYTES ||
      !c->certificate_signing_identity || !c->certificate_signing_identity_size || c->certificate_signing_identity_size > 8191u ||
      !c->response_signing_identity || !c->response_signing_identity_size || c->response_signing_identity_size > 8191u ||
      !c->maximum_age_seconds || c->maximum_clock_skew_seconds > SALTS_CRYPTO_SM2_OCSP_MAX_CLOCK_SKEW ||
      c->minimum_this_update < 0 || c->minimum_this_update > INT64_C(253402300799) ||
      ((c->responder_certificate || c->responder_certificate_size || c->responder_issuer_identity || c->responder_issuer_identity_size) &&
       (!c->responder_certificate || !c->responder_certificate_size || c->responder_certificate_size > 4096u ||
        !c->responder_issuer_identity || !c->responder_issuer_identity_size || c->responder_issuer_identity_size > 8191u))) {
    memset(out,0,sizeof(*out)); return CRYPTO_TLS_STREAM_EINVAL;
  }
  memset(out,0,sizeof(*out));
  if (profile == CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 && !c->peer_is_server) return CRYPTO_TLS_STREAM_ENOTSUP;
  salts_crypto_sm2_cert_span issuer = {c->issuer_certificate,c->issuer_certificate_size};
  salts_crypto_sm2_ocsp_policy p = {c->response,c->response_size,c->response_signing_identity,c->response_signing_identity_size,
      c->maximum_age_seconds,c->maximum_clock_skew_seconds,c->minimum_this_update,NULL,0u};
  int64_t now = current_time(); uint8_t key[65];
  if (now < 0) return CRYPTO_TLS_STREAM_EIO;
  salts_crypto_sm2_delegated_ocsp_policy delegated = {p,{c->responder_certificate,c->responder_certificate_size},
      c->responder_issuer_identity,c->responder_issuer_identity_size};
  if ((c->responder_certificate ? salts_crypto_sm2_validate_delegated_ocsp(&issuer,now,&delegated) :
       salts_crypto_sm2_validate_direct_ocsp(&issuer,now,&p)) != SALTS_CRYPTO_OK ||
      salts_crypto_sm2_x509_public_key(issuer.der,issuer.size,key) != SALTS_CRYPTO_OK) return CRYPTO_TLS_STREAM_ECONNABORTED;
  /* Independently bounded terms sum to <=98301, including on 32-bit targets. */
  size_t bytes = c->issuer_certificate_size+c->response_size+c->certificate_signing_identity_size+c->response_signing_identity_size+c->responder_certificate_size+c->responder_issuer_identity_size;
  ocsp_snapshot *s = calloc(1u,sizeof(*s)+bytes);
  if (!s) return CRYPTO_TLS_STREAM_ENOMEM;
  atomic_init(&s->references,1u); s->peer_is_server = c->peer_is_server; s->profile = profile;
  memcpy(s->issuer_key,key,sizeof(key));
  uint8_t *cursor = s->bytes;
  memcpy(cursor,issuer.der,issuer.size); s->issuer = (salts_crypto_sm2_cert_span){cursor,issuer.size}; cursor += issuer.size;
  memcpy(cursor,p.der,p.size); s->policy.response = p; s->policy.response.der = cursor; cursor += p.size;
  memcpy(cursor,p.signer_identity,p.signer_identity_size); s->policy.response.signer_identity = cursor; cursor += p.signer_identity_size;
  memcpy(cursor,c->certificate_signing_identity,c->certificate_signing_identity_size);
  s->certificate_identity = cursor; s->certificate_identity_size = c->certificate_signing_identity_size;
  cursor += c->certificate_signing_identity_size;
  if (c->responder_certificate) {
    memcpy(cursor,c->responder_certificate,c->responder_certificate_size);
    s->policy.responder_certificate = (salts_crypto_sm2_cert_span){cursor,c->responder_certificate_size};
    cursor += c->responder_certificate_size;
    memcpy(cursor,c->responder_issuer_identity,c->responder_issuer_identity_size);
    s->policy.responder_issuer_identity = cursor;
    s->policy.responder_issuer_identity_size = c->responder_issuer_identity_size;
  }
  *out = (crypto_tls_stream_peer_policy){check,retain,release,s,1u << profile,
      c->peer_is_server ? CRYPTO_TLS_PEER_POLICY_SERVER : CRYPTO_TLS_PEER_POLICY_CLIENT};
  return CRYPTO_TLS_STREAM_OK;
}
int crypto_tls_sm2_ocsp_peer_policy_create(const crypto_tls_sm2_ocsp_config *config,
    crypto_tls_stream_peer_policy *out_policy) {
  return create(config,CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13,out_policy);
}
int crypto_tlcp_sm2_ocsp_peer_policy_create(const crypto_tls_sm2_ocsp_config *config,
    crypto_tls_stream_peer_policy *out_policy) {
  return create(config,CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11,out_policy);
}
