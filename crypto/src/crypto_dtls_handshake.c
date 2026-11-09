#include "crypto_dtls_handshake.h"
#include "crypto_dtls_record.h"
#include "crypto_internal.h"
#include <string.h>

static void put24(uint8_t *p,size_t n) { p[0]=(uint8_t)(n>>16); p[1]=(uint8_t)(n>>8); p[2]=(uint8_t)n; }
static size_t get24(const uint8_t *p) { return ((size_t)p[0]<<16)|((size_t)p[1]<<8)|p[2]; }
static int valid_fragment(size_t total,size_t offset,size_t size) {
  return total<=CRYPTO_DTLS_HANDSHAKE_MAX_BODY && offset<=total && size<=total-offset && (size || !total);
}
int crypto_dtls_handshake_header(uint8_t type,uint16_t seq,size_t total,size_t offset,size_t size,uint8_t out[12]) {
  if (!out || !valid_fragment(total,offset,size)) return SALTS_CRYPTO_EINVAL;
  out[0]=type; put24(out+1,total); out[4]=(uint8_t)(seq>>8); out[5]=(uint8_t)seq;
  put24(out+6,offset); put24(out+9,size); return SALTS_CRYPTO_OK;
}
int crypto_dtls_fragment_write(uint8_t type,uint16_t seq,const void *body,size_t total,
    size_t offset,size_t size,void *out,size_t capacity,size_t *written) {
  if (!out || !written || (!body && total) || !valid_fragment(total,offset,size) ||
      size>CRYPTO_DTLS_MAX_PLAINTEXT-CRYPTO_DTLS_HANDSHAKE_HEADER ||
      salts_crypto_overlap(out,capacity,body,total) || salts_crypto_overlap(written,sizeof(*written),body,total) ||
      salts_crypto_overlap(written,sizeof(*written),out,capacity)) return SALTS_CRYPTO_EINVAL;
  *written=0u;
  if (capacity<CRYPTO_DTLS_HANDSHAKE_HEADER+size) return SALTS_CRYPTO_EINVAL;
  int status=crypto_dtls_handshake_header(type,seq,total,offset,size,out);
  if (status!=SALTS_CRYPTO_OK) return status;
  if (size) memcpy((uint8_t *)out+12,(const uint8_t *)body+offset,size);
  *written=12u+size; return SALTS_CRYPTO_OK;
}
int crypto_dtls_fragment_parse(const void *wire,size_t size,crypto_dtls_fragment *out) {
  if (!wire || !out || salts_crypto_overlap(out,sizeof(*out),wire,size)) return SALTS_CRYPTO_EINVAL;
  if (size<CRYPTO_DTLS_HANDSHAKE_HEADER) return SALTS_CRYPTO_EVERIFY;
  const uint8_t *p=wire;
  crypto_dtls_fragment v={0};
  v.type=p[0]; v.total=get24(p+1); v.sequence=(uint16_t)(((uint16_t)p[4]<<8)|p[5]);
  v.offset=get24(p+6); v.size=get24(p+9);
  if (!valid_fragment(v.total,v.offset,v.size) || v.size>size-12u ||
      v.size>CRYPTO_DTLS_MAX_PLAINTEXT-CRYPTO_DTLS_HANDSHAKE_HEADER) return SALTS_CRYPTO_EVERIFY;
  v.body=p+12; v.wire_size=12u+v.size; *out=v; return SALTS_CRYPTO_OK;
}
int crypto_dtls_reassembly_init(crypto_dtls_reassembly *s,uint16_t first,size_t limit) {
  if (!s || !limit || limit>CRYPTO_DTLS_HANDSHAKE_MAX_BODY) return SALTS_CRYPTO_EINVAL;
  if (s->ready) return SALTS_CRYPTO_ESTATE;
  memset(s,0,sizeof(*s)); s->next=first; s->body_limit=limit; s->ready=true; return SALTS_CRYPTO_OK;
}
void crypto_dtls_reassembly_clear(crypto_dtls_reassembly *s) { if (s) salts_crypto_secure_zero(s,sizeof(*s)); }
int crypto_dtls_reassembly_feed(crypto_dtls_reassembly *s,const void *wire,size_t size,size_t *consumed) {
  if (!s || !wire || !consumed || salts_crypto_overlap(s,sizeof(*s),wire,size) ||
      salts_crypto_overlap(consumed,sizeof(*consumed),s,sizeof(*s)) ||
      salts_crypto_overlap(consumed,sizeof(*consumed),wire,size)) return SALTS_CRYPTO_EINVAL;
  *consumed=0u;
  if (!s->ready || s->next>UINT16_MAX) return SALTS_CRYPTO_ESTATE;
  crypto_dtls_fragment v;
  int status=crypto_dtls_fragment_parse(wire,size,&v);
  if (status!=SALTS_CRYPTO_OK) return status;
  if (v.total>s->body_limit) return SALTS_CRYPTO_EVERIFY;
  if (v.sequence<s->next) { *consumed=v.wire_size; return CRYPTO_DTLS_HANDSHAKE_OLD; }
  if ((uint32_t)v.sequence-s->next>=CRYPTO_DTLS_HANDSHAKE_SLOTS) {
    *consumed=v.wire_size; return CRYPTO_DTLS_HANDSHAKE_NEED;
  }
  crypto_dtls_message_slot *slot=&s->slots[v.sequence%CRYPTO_DTLS_HANDSHAKE_SLOTS];
  if (slot->present && slot->sequence!=v.sequence) return SALTS_CRYPTO_ESTATE;
  if (slot->present && (slot->type!=v.type || slot->total!=v.total)) return SALTS_CRYPTO_EVERIFY;
  /* Validate every overlap first; a conflict cannot partially alter the body,
   * bitmap, completion count or the first fragment's authoritative metadata. */
  for (size_t i=0u; i<v.size; ++i) {
    const size_t at=v.offset+i;
    if ((slot->bitmap[at/8u] & (1u<<(at%8u))) && slot->body[at]!=v.body[i]) return SALTS_CRYPTO_EVERIFY;
  }
  if (!slot->present) { slot->present=true; slot->type=v.type; slot->total=v.total; slot->sequence=v.sequence; }
  for (size_t i=0u; i<v.size; ++i) {
    const size_t at=v.offset+i; const uint8_t bit=(uint8_t)(1u<<(at%8u));
    if (!(slot->bitmap[at/8u]&bit)) { slot->bitmap[at/8u]|=bit; ++slot->received; slot->body[at]=v.body[i]; }
  }
  *consumed=v.wire_size; return SALTS_CRYPTO_OK;
}
int crypto_dtls_reassembly_peek(const crypto_dtls_reassembly *s,crypto_dtls_message *out) {
  if (!s || !out || salts_crypto_overlap(out,sizeof(*out),s,sizeof(*s))) return SALTS_CRYPTO_EINVAL;
  *out=(crypto_dtls_message){0};
  if (!s->ready || s->next>UINT16_MAX) return SALTS_CRYPTO_ESTATE;
  const crypto_dtls_message_slot *slot=&s->slots[s->next%CRYPTO_DTLS_HANDSHAKE_SLOTS];
  if (slot->present && slot->sequence!=s->next) return SALTS_CRYPTO_ESTATE;
  if (!slot->present || slot->received!=slot->total) return CRYPTO_DTLS_HANDSHAKE_NEED;
  *out=(crypto_dtls_message){slot->body,slot->total,slot->sequence,slot->type};
  return SALTS_CRYPTO_OK;
}
int crypto_dtls_reassembly_consume(crypto_dtls_reassembly *s) {
  crypto_dtls_message msg;
  int status=crypto_dtls_reassembly_peek(s,&msg);
  if (status!=SALTS_CRYPTO_OK) return status;
  salts_crypto_secure_zero(&s->slots[s->next%CRYPTO_DTLS_HANDSHAKE_SLOTS],sizeof(s->slots[0]));
  ++s->next; return SALTS_CRYPTO_OK;
}

int crypto_dtls_flight_timer_init(crypto_dtls_flight_timer *t,uint32_t initial,uint32_t ceiling,unsigned retries) {
  if (!t || !initial || initial>ceiling || ceiling>CRYPTO_DTLS_TIMER_MAX_MS ||
      !retries || retries>CRYPTO_DTLS_TIMER_MAX_RETRIES) return SALTS_CRYPTO_EINVAL;
  if (t->ready) return SALTS_CRYPTO_ESTATE;
  memset(t,0,sizeof(*t)); t->interval=initial; t->ceiling=ceiling; t->maximum=retries; t->ready=true;
  return SALTS_CRYPTO_OK;
}
void crypto_dtls_flight_timer_clear(crypto_dtls_flight_timer *t) { if (t) memset(t,0,sizeof(*t)); }
static int timer_sample(crypto_dtls_flight_timer *t,uint64_t now) {
  if (t->phase==CRYPTO_DTLS_TIMER_FAILED) return SALTS_CRYPTO_ESTATE;
  if (t->sampled && now<t->last_now) { t->phase=CRYPTO_DTLS_TIMER_FAILED; return SALTS_CRYPTO_ESTATE; }
  t->sampled=true; t->last_now=now; return SALTS_CRYPTO_OK;
}
int crypto_dtls_flight_timer_sent(crypto_dtls_flight_timer *t,uint64_t now) {
  if (!t) return SALTS_CRYPTO_EINVAL;
  if (!t->ready || (t->phase!=CRYPTO_DTLS_TIMER_IDLE && t->phase!=CRYPTO_DTLS_TIMER_SEND)) return SALTS_CRYPTO_ESTATE;
  int status=timer_sample(t,now); if (status!=SALTS_CRYPTO_OK) return status;
  if (now>UINT64_MAX-t->interval) { t->phase=CRYPTO_DTLS_TIMER_FAILED; return SALTS_CRYPTO_ESTATE; }
  t->deadline=now+t->interval; t->phase=CRYPTO_DTLS_TIMER_WAIT; return SALTS_CRYPTO_OK;
}
static int timer_retry(crypto_dtls_flight_timer *t,bool *due) {
  if (t->retries==t->maximum) { t->phase=CRYPTO_DTLS_TIMER_DONE; return CRYPTO_DTLS_TIMER_EXHAUSTED; }
  ++t->retries;
  /* Configured milliseconds are <=60000, so doubling cannot overflow. */
  const uint32_t twice=t->interval*2u;
  t->interval=twice<t->ceiling ? twice : t->ceiling;
  t->phase=CRYPTO_DTLS_TIMER_SEND; *due=true; return SALTS_CRYPTO_OK;
}
int crypto_dtls_flight_timer_poll(crypto_dtls_flight_timer *t,uint64_t now,bool *due) {
  if (!t || !due || salts_crypto_overlap(due,sizeof(*due),t,sizeof(*t))) return SALTS_CRYPTO_EINVAL;
  *due=false;
  if (!t->ready) return SALTS_CRYPTO_ESTATE;
  if (t->phase==CRYPTO_DTLS_TIMER_DONE) return CRYPTO_DTLS_TIMER_EXHAUSTED;
  if (t->phase==CRYPTO_DTLS_TIMER_ACKED) return SALTS_CRYPTO_OK;
  int status=timer_sample(t,now); if (status!=SALTS_CRYPTO_OK) return status;
  if (t->phase!=CRYPTO_DTLS_TIMER_WAIT || now<t->deadline) return SALTS_CRYPTO_OK;
  return timer_retry(t,due);
}
int crypto_dtls_flight_timer_repeat(crypto_dtls_flight_timer *t,uint64_t now,bool *due) {
  if (!t || !due || salts_crypto_overlap(due,sizeof(*due),t,sizeof(*t))) return SALTS_CRYPTO_EINVAL;
  *due=false;
  if (!t->ready) return SALTS_CRYPTO_ESTATE;
  if (t->phase==CRYPTO_DTLS_TIMER_DONE) return CRYPTO_DTLS_TIMER_EXHAUSTED;
  if (t->phase==CRYPTO_DTLS_TIMER_ACKED) return SALTS_CRYPTO_OK;
  int status=timer_sample(t,now); if (status) return status;
  if (t->phase==CRYPTO_DTLS_TIMER_SEND) return SALTS_CRYPTO_OK;
  if (t->phase!=CRYPTO_DTLS_TIMER_WAIT) return SALTS_CRYPTO_ESTATE;
  return timer_retry(t,due);
}
int crypto_dtls_flight_timer_ack(crypto_dtls_flight_timer *t) {
  if (!t) return SALTS_CRYPTO_EINVAL;
  if (!t->ready || (t->phase!=CRYPTO_DTLS_TIMER_WAIT && t->phase!=CRYPTO_DTLS_TIMER_SEND)) return SALTS_CRYPTO_ESTATE;
  t->phase=CRYPTO_DTLS_TIMER_ACKED; return SALTS_CRYPTO_OK;
}
