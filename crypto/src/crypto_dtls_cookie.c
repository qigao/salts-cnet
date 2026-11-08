#include "crypto_dtls_cookie.h"
#include "crypto_dtls_handshake.h"
#include "crypto_internal.h"
#include <gmssl/sha2.h>
#include <gmssl/mem.h>
#include <string.h>

typedef struct hello_view {
  const uint8_t *body,*cookie,*suffix;
  size_t size,prefix_size,cookie_size,suffix_size;
  uint16_t sequence;
} hello_view;
static size_t get16(const uint8_t *p) { return ((size_t)p[0]<<8)|p[1]; }
static size_t get24(const uint8_t *p) { return ((size_t)p[0]<<16)|((size_t)p[1]<<8)|p[2]; }
static void put64(uint8_t *p,uint64_t value) { for (size_t i=8u; i;) { p[--i]=(uint8_t)value; value>>=8; } }
static uint64_t get64(const uint8_t *p) { uint64_t v=0u; for (size_t i=0u; i<8u; ++i) v=(v<<8)|p[i]; return v; }
static int client_hello(const uint8_t *wire,size_t size,hello_view *v) {
  if (size<25u || size>25u+CRYPTO_DTLS_COOKIE_MAX_HELLO || wire[0]!=22u || wire[1]!=0xfe ||
      (wire[2]!=0xfd && wire[2]!=0xff) || wire[3] || wire[4] || get16(wire+11)!=size-13u) return SALTS_CRYPTO_EVERIFY;
  const uint8_t *hs=wire+13,*p=hs+12; const size_t n=size-25u;
  if (hs[0]!=1u || get24(hs+1)!=n || get24(hs+6)!=0u || get24(hs+9)!=n ||
      n<42u || p[0]!=0xfe || p[1]!=0xfd || p[34]>32u) return SALTS_CRYPTO_EVERIFY;
  const size_t cookie_offset=35u+p[34];
  if (cookie_offset>=n || (size_t)p[cookie_offset]>n-cookie_offset-1u) return SALTS_CRYPTO_EVERIFY;
  const size_t cookie_size=p[cookie_offset];
  size_t at=cookie_offset+1u+cookie_size;
  if (n-at<2u) return SALTS_CRYPTO_EVERIFY;
  size_t ciphers=get16(p+at); at+=2u;
  if (ciphers<2u || (ciphers&1u) || ciphers>n-at) return SALTS_CRYPTO_EVERIFY;
  at+=ciphers;
  if (at==n) return SALTS_CRYPTO_EVERIFY;
  const size_t compression=p[at++];
  if (!compression || compression>n-at) return SALTS_CRYPTO_EVERIFY;
  bool null_compression=false;
  for (size_t i=0u; i<compression; ++i) if (!p[at+i]) null_compression=true;
  if (!null_compression) return SALTS_CRYPTO_EVERIFY;
  at+=compression;
  if (at<n) {
    if (n-at<2u || get16(p+at)!=n-at-2u) return SALTS_CRYPTO_EVERIFY;
    at+=2u; uint16_t types[CRYPTO_DTLS_COOKIE_MAX_EXTENSIONS]; size_t count=0u;
    while (at<n) {
      if (n-at<4u || count==CRYPTO_DTLS_COOKIE_MAX_EXTENSIONS) return SALTS_CRYPTO_EVERIFY;
      const uint16_t type=(uint16_t)get16(p+at); const size_t length=get16(p+at+2u); at+=4u;
      if (length>n-at) return SALTS_CRYPTO_EVERIFY;
      for (size_t i=0u; i<count; ++i) if (types[i]==type) return SALTS_CRYPTO_EVERIFY;
      types[count++]=type; at+=length;
    }
  }
  *v=(hello_view){p,p+cookie_offset+1u,p+cookie_offset+1u+cookie_size,n,cookie_offset,cookie_size,
      n-cookie_offset-1u-cookie_size,(uint16_t)get16(hs+4)};
  return SALTS_CRYPTO_OK;
}
static void cookie_mac(const crypto_dtls_cookie_context *ctx,const uint8_t issued[8],
    const void *address,size_t address_size,const hello_view *v,uint8_t tag[32]) {
  static const uint8_t label[]="Salts DTLS1.2 cookie";
  const size_t canonical=v->prefix_size+1u+v->suffix_size;
  const uint8_t length[4]={(uint8_t)address_size,(uint8_t)(canonical>>16),(uint8_t)(canonical>>8),(uint8_t)canonical};
  const uint8_t empty=0;
  SHA256_HMAC_CTX h={0};
  sha256_hmac_init(&h,ctx->key,sizeof(ctx->key));
  sha256_hmac_update(&h,label,sizeof(label)-1u);
  sha256_hmac_update(&h,issued,8u); sha256_hmac_update(&h,length,sizeof(length));
  sha256_hmac_update(&h,address,address_size);
  sha256_hmac_update(&h,v->body,v->prefix_size); sha256_hmac_update(&h,&empty,1u);
  sha256_hmac_update(&h,v->suffix,v->suffix_size);
  sha256_hmac_finish(&h,tag); salts_crypto_secure_zero(&h,sizeof(h));
}
int crypto_dtls_cookie_init(crypto_dtls_cookie_context *ctx,uint32_t lifetime) {
  if (!ctx || !lifetime || lifetime>CRYPTO_DTLS_COOKIE_MAX_AGE_MS) return SALTS_CRYPTO_EINVAL;
  if (ctx->ready) return SALTS_CRYPTO_ESTATE;
  uint8_t key[32]={0};
  if (salts_crypto_random_bytes(key,sizeof(key))!=0) { salts_crypto_secure_zero(key,sizeof(key)); return SALTS_CRYPTO_ERANDOM; }
  memset(ctx,0,sizeof(*ctx)); memcpy(ctx->key,key,sizeof(key)); ctx->lifetime_ms=lifetime; ctx->ready=true;
  salts_crypto_secure_zero(key,sizeof(key)); return SALTS_CRYPTO_OK;
}
void crypto_dtls_cookie_clear(crypto_dtls_cookie_context *ctx) { if (ctx) salts_crypto_secure_zero(ctx,sizeof(*ctx)); }
static int overlap_outputs(const void *a,size_t an,const void *b,size_t bn,const void *c,size_t cn,
    const void *input,size_t size) {
  return salts_crypto_overlap(a,an,input,size) || salts_crypto_overlap(b,bn,input,size) || salts_crypto_overlap(c,cn,input,size);
}
int crypto_dtls_cookie_gate(const crypto_dtls_cookie_context *ctx,const void *address,size_t address_size,
    const void *data,size_t size,uint64_t now,void *reply,size_t capacity,size_t *reply_size,
    crypto_dtls_cookie_result *out) {
  if (!ctx || !address || !address_size || address_size>CRYPTO_DTLS_COOKIE_MAX_ADDRESS || !data || !reply || !reply_size || !out ||
      overlap_outputs(reply,capacity,reply_size,sizeof(*reply_size),out,sizeof(*out),ctx,sizeof(*ctx)) ||
      overlap_outputs(reply,capacity,reply_size,sizeof(*reply_size),out,sizeof(*out),address,address_size) ||
      overlap_outputs(reply,capacity,reply_size,sizeof(*reply_size),out,sizeof(*out),data,size) ||
      salts_crypto_overlap(reply,capacity,reply_size,sizeof(*reply_size)) || salts_crypto_overlap(reply,capacity,out,sizeof(*out)) ||
      salts_crypto_overlap(reply_size,sizeof(*reply_size),out,sizeof(*out)) ||
      salts_crypto_overlap(ctx,sizeof(*ctx),address,address_size) || salts_crypto_overlap(ctx,sizeof(*ctx),data,size)) return SALTS_CRYPTO_EINVAL;
  *reply_size=0u; *out=(crypto_dtls_cookie_result){0};
  if (!ctx->ready || !ctx->lifetime_ms || ctx->lifetime_ms>CRYPTO_DTLS_COOKIE_MAX_AGE_MS) return SALTS_CRYPTO_ESTATE;
  hello_view v;
  int status=client_hello(data,size,&v); if (status!=SALTS_CRYPTO_OK) return status;
  uint8_t tag[32]={0},cookie[32]={0};
  if (v.cookie_size==CRYPTO_DTLS_COOKIE_BYTES) {
    cookie_mac(ctx,v.cookie,address,address_size,&v,tag);
    if (gmssl_secure_memcmp(tag,v.cookie+8,CRYPTO_DTLS_COOKIE_TAG_BYTES)==0) {
      const uint64_t issued=get64(v.cookie);
      if (now<issued) { status=SALTS_CRYPTO_ESTATE; goto end; }
      if (now-issued<ctx->lifetime_ms) {
        out->address_verified=true; out->client_hello=v.body; out->client_hello_size=v.size; out->message_sequence=v.sequence;
        const uint8_t *wire=data; for (size_t i=5u; i<11u; ++i) out->record_sequence=(out->record_sequence<<8)|wire[i];
        status=SALTS_CRYPTO_OK; goto end;
      }
    }
  }
  if (capacity<CRYPTO_DTLS_COOKIE_REPLY_BYTES || size<CRYPTO_DTLS_COOKIE_REPLY_BYTES) { status=SALTS_CRYPTO_EINVAL; goto end; }
  put64(cookie,now); cookie_mac(ctx,cookie,address,address_size,&v,tag); memcpy(cookie+8,tag,CRYPTO_DTLS_COOKIE_TAG_BYTES);
  uint8_t *p=reply; const uint8_t *wire=data;
  p[0]=22u; p[1]=0xfe; p[2]=0xfd; p[3]=p[4]=0;
  memcpy(p+5,wire+5,6u); p[11]=0; p[12]=CRYPTO_DTLS_COOKIE_REPLY_BYTES-13u;
  status=crypto_dtls_handshake_header(3u,0u,35u,0u,35u,p+13);
  if (status!=SALTS_CRYPTO_OK) goto end;
  p[25]=0xfe; p[26]=0xfd; p[27]=CRYPTO_DTLS_COOKIE_BYTES; memcpy(p+28,cookie,sizeof(cookie));
  *reply_size=CRYPTO_DTLS_COOKIE_REPLY_BYTES;
end:
  salts_crypto_secure_zero(tag,sizeof(tag)); salts_crypto_secure_zero(cookie,sizeof(cookie)); return status;
}
