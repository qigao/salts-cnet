#include "crypto_dtls_exchange.h"
#include "crypto_dtls_handshake.h"
#include "crypto_internal.h"
#include <gmssl/x509.h>
#include <gmssl/oid.h>
#include <crypto/tls_cipher.h>
#include <crypto/tls_signature.h>
#include <string.h>

enum { DTLS_P256_PARAMS_BYTES=4+CRYPTO_DTLS_P256_PUBLIC_BYTES,
       DTLS_SIGNED_PARAMS_PREFIX=DTLS_P256_PARAMS_BYTES+4 };
void crypto_dtls_ephemeral_clear(crypto_dtls_ephemeral *s) {
  if (s) salts_crypto_secure_zero(s,sizeof(*s));
}
int crypto_dtls_ephemeral_init(crypto_dtls_ephemeral *s) {
  if (!s) return SALTS_CRYPTO_EINVAL;
  if (s->ready || s->consumed || s->failed) return SALTS_CRYPTO_ESTATE;
  memset(s,0,sizeof(*s));
  if (secp256r1_key_generate(&s->key)!=1) {
    crypto_dtls_ephemeral_clear(s); s->failed=true; return SALTS_CRYPTO_ERANDOM;
  }
  s->ready=true; return SALTS_CRYPTO_OK;
}
int crypto_dtls_ephemeral_public(const crypto_dtls_ephemeral *s,uint8_t out[65]) {
  if (!s || !out || salts_crypto_overlap(s,sizeof(*s),out,65u)) return SALTS_CRYPTO_EINVAL;
  memset(out,0,65u);
  if (!s->ready || s->consumed || s->failed) return SALTS_CRYPTO_ESTATE;
  if (secp256r1_point_to_uncompressed_octets(&s->key.public_key,out)!=1) {
    memset(out,0,65u); return SALTS_CRYPTO_ECRYPTO;
  }
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_ephemeral_exchange(crypto_dtls_ephemeral *s,const void *peer,size_t size,uint8_t out[32]) {
  if (!s || !out || (!peer && size) || salts_crypto_overlap(s,sizeof(*s),peer,size) ||
      salts_crypto_overlap(s,sizeof(*s),out,32u) || salts_crypto_overlap(peer,size,out,32u)) return SALTS_CRYPTO_EINVAL;
  memset(out,0,32u);
  if (!s->ready || s->consumed || s->failed) return SALTS_CRYPTO_ESTATE;
  SECP256R1_KEY public_key={0}; int status=SALTS_CRYPTO_EVERIFY;
  const uint8_t *p=peer; size_t remaining=size;
  if (size!=65u || secp256r1_public_key_from_bytes(&public_key,&p,&remaining)!=1 || remaining) goto end;
  if (secp256r1_do_ecdh(&s->key,&public_key,out)!=1) { status=SALTS_CRYPTO_ECRYPTO; goto end; }
  status=SALTS_CRYPTO_OK;
end:
  secp256r1_key_cleanup(&public_key); crypto_dtls_ephemeral_clear(s);
  if (status==SALTS_CRYPTO_OK) s->consumed=true;
  else { memset(out,0,32u); s->failed=true; }
  return status;
}
int crypto_dtls_server_exchange_verify(const void *leaf,size_t leaf_size,uint16_t cipher,
    const uint8_t client[32],const uint8_t server[32],const void *body,size_t size,uint8_t peer[65]) {
  if (!leaf || !leaf_size || !client || !server || !body || !peer ||
      leaf_size>CRYPTO_DTLS_HANDSHAKE_MAX_BODY || size>CRYPTO_DTLS_HANDSHAKE_MAX_BODY || salts_crypto_overlap(peer,65u,leaf,leaf_size) ||
      salts_crypto_overlap(peer,65u,body,size) || salts_crypto_overlap(peer,65u,client,32u) ||
      salts_crypto_overlap(peer,65u,server,32u)) return SALTS_CRYPTO_EINVAL;
  memset(peer,0,65u);
  int expected,algor;
  if (cipher==CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256) { expected=CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256; algor=OID_ecdsa_with_sha256; }
  else if (cipher==CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256) { expected=CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256; algor=OID_rsasign_with_sha256; }
  else return SALTS_CRYPTO_EINVAL;
  const uint8_t *wire=body;
  if (size<DTLS_SIGNED_PARAMS_PREFIX || wire[0]!=3u || wire[1]!=0u || wire[2]!=23u || wire[3]!=65u ||
      ((unsigned)wire[DTLS_P256_PARAMS_BYTES]*256u+wire[DTLS_P256_PARAMS_BYTES+1u])!=(unsigned)expected) return SALTS_CRYPTO_EVERIFY;
  const size_t signature_size=(size_t)wire[DTLS_P256_PARAMS_BYTES+2u]*256u+wire[DTLS_P256_PARAMS_BYTES+3u];
  if (!signature_size || signature_size>CRYPTO_DTLS_EXCHANGE_MAX_SIGNATURE || signature_size!=size-DTLS_SIGNED_PARAMS_PREFIX)
    return SALTS_CRYPTO_EVERIFY;
  SECP256R1_KEY ephemeral={0}; X509_KEY key={0}; X509_SIGN_CTX verify={0};
  const uint8_t *p=wire+4u; size_t remaining=65u; int status=SALTS_CRYPTO_EVERIFY;
  if (secp256r1_public_key_from_bytes(&ephemeral,&p,&remaining)!=1 || remaining) goto end;
  const uint8_t *certificate,*der=leaf; size_t certificate_size,der_size=leaf_size;
  if (x509_cert_from_der(&certificate,&certificate_size,&der,&der_size)!=1 || der_size ||
      x509_cert_get_subject_public_key(certificate,certificate_size,&key)!=1) goto end;
  if ((expected==CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 && (key.algor!=OID_ec_public_key || key.algor_param!=OID_secp256r1)) ||
      (expected==CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256 && key.algor!=OID_rsa_encryption)) goto end;
  if (x509_verify_init_ex(&verify,&key,algor,NULL,0u,wire+DTLS_SIGNED_PARAMS_PREFIX,signature_size)!=1 ||
      x509_verify_update(&verify,client,32u)!=1 || x509_verify_update(&verify,server,32u)!=1 ||
      x509_verify_update(&verify,wire,DTLS_P256_PARAMS_BYTES)!=1 || x509_verify_finish(&verify)!=1) goto end;
  memcpy(peer,wire+4u,65u); status=SALTS_CRYPTO_OK;
end:
  x509_sign_ctx_cleanup(&verify); x509_key_cleanup(&key); secp256r1_key_cleanup(&ephemeral);
  return status;
}
