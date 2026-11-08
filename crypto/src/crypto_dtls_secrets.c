#include "crypto_dtls_secrets.h"
#include "crypto_internal.h"
#include <gmssl/tls.h>
#include <gmssl/mem.h>
#include <string.h>

static int sender_valid(crypto_dtls_sender sender) { return sender==CRYPTO_DTLS_CLIENT || sender==CRYPTO_DTLS_SERVER; }
int crypto_dtls_transcript_init(crypto_dtls_transcript *s,uint16_t client,uint16_t server) {
  if (!s || !client || !server) return SALTS_CRYPTO_EINVAL;
  if (s->ready) return SALTS_CRYPTO_ESTATE;
  memset(s,0,sizeof(*s)); sha256_init(&s->hash); s->next[0]=client; s->next[1]=server; s->ready=true;
  return SALTS_CRYPTO_OK;
}
void crypto_dtls_transcript_clear(crypto_dtls_transcript *s) { if (s) salts_crypto_secure_zero(s,sizeof(*s)); }
int crypto_dtls_transcript_append(crypto_dtls_transcript *s,crypto_dtls_sender sender,const crypto_dtls_message *m) {
  if (!s || !m || !sender_valid(sender) || salts_crypto_overlap(s,sizeof(*s),m,sizeof(*m))) return SALTS_CRYPTO_EINVAL;
  if ((!m->body && m->size) || m->size>CRYPTO_DTLS_HANDSHAKE_MAX_BODY || salts_crypto_overlap(s,sizeof(*s),m->body,m->size))
    return SALTS_CRYPTO_EINVAL;
  if (!s->ready || s->next[sender]>UINT16_MAX || s->bytes>CRYPTO_DTLS_TRANSCRIPT_MAX_BYTES) return SALTS_CRYPTO_ESTATE;
  if (m->sequence!=s->next[sender] || m->type==3u ||
      (!s->started && (sender!=CRYPTO_DTLS_CLIENT || m->type!=1u)) ||
      (s->started && m->type==1u)) return SALTS_CRYPTO_EVERIFY;
  if (m->size+12u>CRYPTO_DTLS_TRANSCRIPT_MAX_BYTES-s->bytes) return SALTS_CRYPTO_ESTATE;
  uint8_t header[12];
  int status=crypto_dtls_handshake_header(m->type,m->sequence,m->size,0u,m->size,header);
  if (status!=SALTS_CRYPTO_OK) return status;
  sha256_update(&s->hash,header,sizeof(header));
  if (m->size) sha256_update(&s->hash,m->body,m->size);
  s->bytes+=sizeof(header)+m->size; ++s->next[sender]; s->started=true;
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_transcript_hash(const crypto_dtls_transcript *s,uint8_t out[32]) {
  if (!s || !out || salts_crypto_overlap(s,sizeof(*s),out,32u)) return SALTS_CRYPTO_EINVAL;
  if (!s->ready || !s->started) { memset(out,0,32u); return SALTS_CRYPTO_ESTATE; }
  /* Native SHA256_CTX contains no pointers. This does not clone the public
   * Crypto context whose lifecycle explicitly forbids copying. */
  SHA256_CTX copy=s->hash; sha256_finish(&copy,out); salts_crypto_secure_zero(&copy,sizeof(copy));
  return SALTS_CRYPTO_OK;
}
void crypto_dtls_secrets_clear(crypto_dtls_secrets *s) { if (s) salts_crypto_secure_zero(s,sizeof(*s)); }
void crypto_dtls_secrets_forget_master(crypto_dtls_secrets *s) {
  salts_crypto_secure_zero(s->master,sizeof(s->master)); s->master_live=false;
}
int crypto_dtls_exporter(const crypto_dtls_secrets *s,const uint8_t client[32],const uint8_t server[32],
    const crypto_dtls_export_request *r,void *out,size_t size) {
  if (!s || !client || !server || !r || !out || !size || size>CRYPTO_DTLS_EXPORT_OUTPUT_BYTES ||
      !r->label || !r->label_size || r->label_size>CRYPTO_DTLS_EXPORT_LABEL_BYTES ||
      r->context_size>CRYPTO_DTLS_EXPORT_CONTEXT_BYTES || (!r->context && r->context_size) ||
      (!r->use_context && r->context_size) ||
      salts_crypto_overlap(s,sizeof(*s),out,size) || salts_crypto_overlap(s,sizeof(*s),r,sizeof(*r)) ||
      salts_crypto_overlap(s,sizeof(*s),client,32u) || salts_crypto_overlap(s,sizeof(*s),server,32u) ||
      salts_crypto_overlap(s,sizeof(*s),r->label,r->label_size) || salts_crypto_overlap(s,sizeof(*s),r->context,r->context_size) ||
      salts_crypto_overlap(out,size,r,sizeof(*r)) || salts_crypto_overlap(out,size,client,32u) ||
      salts_crypto_overlap(out,size,server,32u) || salts_crypto_overlap(out,size,r->label,r->label_size) ||
      salts_crypto_overlap(out,size,r->context,r->context_size)) return SALTS_CRYPTO_EINVAL;
  const uint8_t *label=r->label;
  for (size_t i=0;i<r->label_size;++i) if (label[i]<32u || label[i]>126u) return SALTS_CRYPTO_EINVAL;
  static const char *const reserved[]={"client finished","server finished","master secret","key expansion","extended master secret"};
  for (size_t i=0;i<sizeof(reserved)/sizeof(reserved[0]);++i) {
    size_t n=strlen(reserved[i]); if (n>r->label_size) n=r->label_size;
    if (!memcmp(label,reserved[i],n)) return SALTS_CRYPTO_EINVAL;
  }
  if (!s->ready || s->failed || !s->master_live) return SALTS_CRYPTO_ESTATE;
  char text[CRYPTO_DTLS_EXPORT_LABEL_BYTES+1]; uint8_t seed[66+CRYPTO_DTLS_EXPORT_CONTEXT_BYTES];
  memcpy(text,label,r->label_size); text[r->label_size]=0;
  memcpy(seed,client,32u); memcpy(seed+32u,server,32u); size_t n=64u;
  if (r->use_context) {
    seed[n++]=(uint8_t)(r->context_size>>8u); seed[n++]=(uint8_t)r->context_size;
    if (r->context_size) memcpy(seed+n,r->context,r->context_size); n+=r->context_size;
  }
  const int result=tls_prf(DIGEST_sha256(),s->master,sizeof(s->master),text,seed,n,NULL,0u,size,out);
  salts_crypto_secure_zero(seed,sizeof(seed)); salts_crypto_secure_zero(text,sizeof(text));
  return result==1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
}
int crypto_dtls_secrets_derive(crypto_dtls_secrets *s,const uint8_t shared[32],const uint8_t hash[32],
    const uint8_t client[32],const uint8_t server[32]) {
  if (!s || !shared || !hash || !client || !server || salts_crypto_overlap(s,sizeof(*s),shared,32u) ||
      salts_crypto_overlap(s,sizeof(*s),hash,32u) || salts_crypto_overlap(s,sizeof(*s),client,32u) ||
      salts_crypto_overlap(s,sizeof(*s),server,32u)) return SALTS_CRYPTO_EINVAL;
  if (s->ready || s->failed) return SALTS_CRYPTO_ESTATE;
  crypto_dtls_secrets candidate={0}; uint8_t key_block[40]={0}; int status=SALTS_CRYPTO_ECRYPTO;
  if (tls_prf(DIGEST_sha256(),shared,32u,"extended master secret",hash,32u,NULL,0u,48u,candidate.master)!=1 ||
      tls_prf(DIGEST_sha256(),candidate.master,48u,"key expansion",server,32u,client,32u,sizeof(key_block),key_block)!=1) goto end;
  status=crypto_dtls_record_init(&candidate.client_write,1u,key_block,key_block+32u);
  if (status!=SALTS_CRYPTO_OK) goto end;
  status=crypto_dtls_record_init(&candidate.server_write,1u,key_block+16u,key_block+36u);
  if (status!=SALTS_CRYPTO_OK) goto end;
  candidate.ready=candidate.master_live=true; *s=candidate;
end:
  salts_crypto_secure_zero(key_block,sizeof(key_block)); crypto_dtls_secrets_clear(&candidate);
  if (status!=SALTS_CRYPTO_OK) { crypto_dtls_secrets_clear(s); s->failed=true; }
  return status;
}
int crypto_dtls_finished(const crypto_dtls_secrets *s,crypto_dtls_sender sender,const uint8_t hash[32],uint8_t out[12]) {
  if (!s || !hash || !out || !sender_valid(sender) || salts_crypto_overlap(s,sizeof(*s),hash,32u) ||
      salts_crypto_overlap(s,sizeof(*s),out,12u) || salts_crypto_overlap(hash,32u,out,12u)) return SALTS_CRYPTO_EINVAL;
  memset(out,0,12u);
  if (!s->ready || s->failed || !s->master_live) return SALTS_CRYPTO_ESTATE;
  return tls_prf(DIGEST_sha256(),s->master,48u,sender==CRYPTO_DTLS_SERVER ? "server finished" : "client finished",
      hash,32u,NULL,0u,12u,out)==1 ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
}
int crypto_dtls_finished_check(const crypto_dtls_secrets *s,crypto_dtls_sender sender,const uint8_t hash[32],
    const void *claimed,size_t size) {
  if (!s || !hash || (!claimed && size) || !sender_valid(sender) || salts_crypto_overlap(s,sizeof(*s),hash,32u) ||
      salts_crypto_overlap(s,sizeof(*s),claimed,size)) return SALTS_CRYPTO_EINVAL;
  if (!s->ready || s->failed || !s->master_live) return SALTS_CRYPTO_ESTATE;
  uint8_t expected[12]={0};
  int status=crypto_dtls_finished(s,sender,hash,expected);
  if (status==SALTS_CRYPTO_OK && (size!=sizeof(expected) || gmssl_secure_memcmp(expected,claimed,sizeof(expected))))
    status=SALTS_CRYPTO_EVERIFY;
  salts_crypto_secure_zero(expected,sizeof(expected));
  return status;
}
int crypto_dtls_finished_verify(crypto_dtls_secrets *s,crypto_dtls_sender sender,const uint8_t hash[32],const void *claimed,size_t size) {
  const int status=crypto_dtls_finished_check(s,sender,hash,claimed,size);
  if (status==SALTS_CRYPTO_EVERIFY || status==SALTS_CRYPTO_ECRYPTO) { crypto_dtls_secrets_clear(s); s->failed=true; }
  return status;
}
