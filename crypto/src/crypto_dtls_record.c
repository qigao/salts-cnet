#include "crypto_dtls_record.h"
#include "crypto_internal.h"
#include <string.h>

static void put16(uint8_t *p,uint16_t value) { p[0]=(uint8_t)(value>>8); p[1]=(uint8_t)value; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0]<<8)|p[1]); }
static int record_type(uint8_t type) { return type>=20u && type<=23u; }
static int disjoint(const crypto_dtls_record_epoch *s,const void *input,size_t size,
    const void *output,size_t output_size,const size_t *result,const uint8_t *type) {
  return !salts_crypto_overlap(output,output_size,input,size) &&
    !salts_crypto_overlap(input,size,s,sizeof(*s)) &&
    !salts_crypto_overlap(output,output_size,s,sizeof(*s)) &&
    !salts_crypto_overlap(result,sizeof(*result),s,sizeof(*s)) &&
    !salts_crypto_overlap(result,sizeof(*result),input,size) &&
    !salts_crypto_overlap(result,sizeof(*result),output,output_size) &&
    (!type || (!salts_crypto_overlap(type,1u,s,sizeof(*s)) &&
      !salts_crypto_overlap(type,1u,input,size) && !salts_crypto_overlap(type,1u,output,output_size) &&
      !salts_crypto_overlap(type,1u,result,sizeof(*result))));
}
int crypto_dtls_record_init(crypto_dtls_record_epoch *s,uint16_t epoch,
    const uint8_t key[16],const uint8_t salt[4]) {
  if (!s || !key || !salt || !epoch || salts_crypto_overlap(s,sizeof(*s),key,16u) ||
      salts_crypto_overlap(s,sizeof(*s),salt,4u)) return SALTS_CRYPTO_EINVAL;
  if (s->ready) return SALTS_CRYPTO_ESTATE;
  AES_KEY prepared={0};
  if (aes_set_encrypt_key(&prepared,key,16u)!=1) {
    salts_crypto_secure_zero(&prepared,sizeof(prepared)); return SALTS_CRYPTO_ECRYPTO;
  }
  memset(s,0,sizeof(*s)); s->key=prepared; memcpy(s->salt,salt,4u); s->epoch=epoch; s->ready=true;
  salts_crypto_secure_zero(&prepared,sizeof(prepared));
  return SALTS_CRYPTO_OK;
}
void crypto_dtls_record_clear(crypto_dtls_record_epoch *s) { if (s) salts_crypto_secure_zero(s,sizeof(*s)); }
int crypto_dtls_record_parse(const void *wire,size_t size,crypto_dtls_record_view *out) {
  if (!wire || !out || salts_crypto_overlap(out,sizeof(*out),wire,size)) return SALTS_CRYPTO_EINVAL;
  if (size<CRYPTO_DTLS_HEADER_SIZE) return SALTS_CRYPTO_EVERIFY;
  const uint8_t *p=wire;
  const size_t length=get16(p+11);
  if (!record_type(p[0]) || p[1]!=0xfe || p[2]!=0xfd ||
      length>CRYPTO_DTLS_MAX_PLAINTEXT+CRYPTO_DTLS_AEAD_OVERHEAD || length>size-CRYPTO_DTLS_HEADER_SIZE) return SALTS_CRYPTO_EVERIFY;
  crypto_dtls_record_view v={.payload=p+13,.payload_size=length,.record_size=13u+length,.epoch=get16(p+3),.type=p[0]};
  for (size_t i=5u; i<11u; ++i) v.sequence=(v.sequence<<8)|p[i];
  *out=v; return SALTS_CRYPTO_OK;
}
int crypto_dtls_record_seal(crypto_dtls_record_epoch *s,uint8_t type,const void *plain,size_t size,
    void *wire,size_t capacity,size_t *wire_size) {
  if (!s || !wire || !wire_size || (!plain && size) || size>CRYPTO_DTLS_MAX_PLAINTEXT ||
      !record_type(type) || !disjoint(s,plain,size,wire,capacity,wire_size,NULL)) return SALTS_CRYPTO_EINVAL;
  *wire_size=0u;
  if (!s->ready || s->send_failed || s->next_send>CRYPTO_DTLS_MAX_SEQUENCE) return SALTS_CRYPTO_ESTATE;
  const size_t total=size+CRYPTO_DTLS_RECORD_OVERHEAD;
  if (capacity<total) return SALTS_CRYPTO_EINVAL;
  uint8_t *p=wire,iv[12],aad[13];
  p[0]=type; p[1]=0xfe; p[2]=0xfd; put16(p+3,s->epoch);
  uint64_t seq=s->next_send;
  for (size_t i=11u; i>5u;) { p[--i]=(uint8_t)seq; seq>>=8; }
  put16(p+11,(uint16_t)(size+CRYPTO_DTLS_AEAD_OVERHEAD));
  memcpy(p+13,p+3,8u); memcpy(iv,s->salt,4u); memcpy(iv+4,p+13,8u);
  memcpy(aad,p+3,8u); memcpy(aad+8,p,3u); put16(aad+11,(uint16_t)size);
  const uint8_t empty=0;
  int result=aes_gcm_encrypt(&s->key,iv,sizeof(iv),aad,sizeof(aad),plain ? plain : &empty,size,
      p+21,16u,p+21+size);
  salts_crypto_secure_zero(iv,sizeof(iv));
  if (result!=1) {
    salts_crypto_secure_zero(wire,total); s->send_failed=true; return SALTS_CRYPTO_ECRYPTO;
  }
  ++s->next_send; *wire_size=total;
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_record_open(crypto_dtls_record_epoch *s,const void *wire,size_t size,
    void *plain,size_t capacity,size_t *plain_size,uint8_t *type) {
  if (!s || !wire || !plain || !plain_size || !type ||
      !disjoint(s,wire,size,plain,capacity,plain_size,type)) return SALTS_CRYPTO_EINVAL;
  *plain_size=0u; *type=0u;
  if (!s->ready) return SALTS_CRYPTO_ESTATE;
  crypto_dtls_record_view v;
  int result=crypto_dtls_record_parse(wire,size,&v);
  if (result!=SALTS_CRYPTO_OK) return result;
  if (v.record_size!=size || v.payload_size<CRYPTO_DTLS_AEAD_OVERHEAD) return SALTS_CRYPTO_EVERIFY;
  if (v.epoch!=s->epoch) return CRYPTO_DTLS_RECORD_DROP;
  if (s->received && v.sequence<=s->highest_received) {
    const uint64_t behind=s->highest_received-v.sequence;
    if (behind>=CRYPTO_DTLS_REPLAY_BITS || (s->replay_window & (UINT64_C(1)<<behind))) return CRYPTO_DTLS_RECORD_DROP;
  }
  const size_t length=v.payload_size-CRYPTO_DTLS_AEAD_OVERHEAD;
  if (capacity<length) return SALTS_CRYPTO_EINVAL;
  uint8_t iv[12],aad[13]; const uint8_t *p=wire;
  memcpy(iv,s->salt,4u); memcpy(iv+4,v.payload,8u);
  memcpy(aad,p+3,8u); memcpy(aad+8,p,3u); put16(aad+11,(uint16_t)length);
  result=aes_gcm_decrypt(&s->key,iv,sizeof(iv),aad,sizeof(aad),v.payload+8,length,
      v.payload+8+length,16u,plain);
  salts_crypto_secure_zero(iv,sizeof(iv));
  if (result!=1) { salts_crypto_secure_zero(plain,length); return SALTS_CRYPTO_EVERIFY; }
  if (!s->received) { s->highest_received=v.sequence; s->replay_window=1u; s->received=true; }
  else if (v.sequence>s->highest_received) {
    const uint64_t ahead=v.sequence-s->highest_received;
    s->replay_window=ahead>=CRYPTO_DTLS_REPLAY_BITS ? 1u : (s->replay_window<<ahead)|1u;
    s->highest_received=v.sequence;
  } else s->replay_window |= UINT64_C(1)<<(s->highest_received-v.sequence);
  *plain_size=length; *type=v.type;
  return SALTS_CRYPTO_OK;
}
