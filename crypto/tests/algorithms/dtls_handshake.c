#include "../../src/crypto_dtls_handshake.h"
#include "../../src/crypto_dtls_cookie.h"
#include <tinytest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t address[]={4,127,0,0,1,1,0xbb};
static size_t hello(uint8_t *wire,const uint8_t *cookie,size_t cookie_size,const uint8_t *ext,size_t ext_size) {
  const size_t body=42u+cookie_size+ext_size;
  memset(wire,0,25u+body); wire[0]=22; wire[1]=0xfe; wire[2]=0xff; wire[10]=9;
  wire[11]=(uint8_t)((12u+body)>>8); wire[12]=(uint8_t)(12u+body);
  check_equal(crypto_dtls_handshake_header(1u,cookie_size ? 1u : 0u,body,0u,body,wire+13),SALTS_CRYPTO_OK);
  uint8_t *p=wire+25; p[0]=0xfe; p[1]=0xfd;
  for (size_t i=0u; i<32u; ++i) p[2u+i]=(uint8_t)i;
  p[34]=0; p[35]=(uint8_t)cookie_size;
  if (cookie_size) memcpy(p+36,cookie,cookie_size);
  const uint8_t tail[]={0,2,0xc0,0x2b,1,0}; memcpy(p+36+cookie_size,tail,sizeof(tail));
  if (ext_size) memcpy(p+42+cookie_size,ext,ext_size);
  return body+25u;
}
static int zero(const void *data,size_t size) { const uint8_t *p=data; unsigned v=0; while (size--) v|=*p++; return !v; }

spec("Private DTLS stateless cookie admission") {
  static crypto_dtls_cookie_context ctx;
  before_each() { memset(&ctx,0,sizeof(ctx)); check_equal(crypto_dtls_cookie_init(&ctx,1000u),SALTS_CRYPTO_OK); }
  after_each() { crypto_dtls_cookie_clear(&ctx); }
  it("issues a nonamplifying challenge, mirrors record sequence and verifies a stateless second ClientHello") {
    uint8_t first[512],second[512],reply[64]; size_t n,reply_size; crypto_dtls_cookie_result result;
    n=hello(first,NULL,0u,NULL,0u); crypto_dtls_cookie_context before=ctx;
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),first,n,100u,reply,sizeof(reply),&reply_size,&result),SALTS_CRYPTO_OK);
    check_true(!result.address_verified && !result.client_hello); check_equal(reply_size,60u); check_true(reply_size<=n);
    check_equal(reply+5,first+5,6u); check_equal(reply[13],3u); check_equal(reply[27],32u);
    uint8_t cookie[32]; memcpy(cookie,reply+28,32u); n=hello(second,cookie,sizeof(cookie),NULL,0u);
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),second,n,1099u,reply,sizeof(reply),&reply_size,&result),SALTS_CRYPTO_OK);
    check_true(result.address_verified); check_equal(reply_size,0u); check_true(result.client_hello==second+25);
    check_equal(result.client_hello_size,74u); check_equal(result.message_sequence,1u); check_equal(result.record_sequence,9u);
    check_equal(&ctx,&before,sizeof(ctx));
    /* An identical cookie can prove the address again; no per-peer table or
     * record-sequence binding is introduced by the stateless listener gate. */
    second[10]=10u;
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),second,n,1099u,reply,sizeof(reply),&reply_size,&result),SALTS_CRYPTO_OK);
    check_true(result.address_verified); check_equal(result.record_sequence,10u);
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),second,n,1100u,reply,sizeof(reply),&reply_size,&result),SALTS_CRYPTO_OK);
    check_true(!result.address_verified); check_equal(reply_size,60u);
  }
  it("binds peer address and every ClientHello parameter and distinguishes a proven backwards clock") {
    uint8_t first[512],second[512],reply[64],cookie[32],peer[sizeof(address)]; size_t n=hello(first,NULL,0u,NULL,0u),size;
    crypto_dtls_cookie_result result;
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),first,n,100u,reply,sizeof(reply),&size,&result),0);
    memcpy(cookie,reply+28,32u); n=hello(second,cookie,32u,NULL,0u);
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),second,n,99u,reply,sizeof(reply),&size,&result),SALTS_CRYPTO_ESTATE);
    check_equal(size,0u); check_true(!result.address_verified);
    cookie[31]^=1u; n=hello(second,cookie,32u,NULL,0u);
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),second,n,99u,reply,sizeof(reply),&size,&result),0);
    check_true(!result.address_verified); check_equal(size,60u); cookie[31]^=1u;
    n=hello(second,cookie,32u,NULL,0u); memcpy(peer,address,sizeof(peer)); peer[6]^=1u;
    check_equal(crypto_dtls_cookie_gate(&ctx,peer,sizeof(peer),second,n,101u,reply,sizeof(reply),&size,&result),0);
    check_true(!result.address_verified);
    second[27]^=1u; // random byte, well-formed but a different ClientHello
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),second,n,101u,reply,sizeof(reply),&size,&result),0);
    check_true(!result.address_verified);
    second[27]^=1u;
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),second,n,101u,reply,sizeof(reply),&size,&result),0);
    check_true(result.address_verified);
  }
  it("rejects malformed lengths, fragments, duplicate extensions and aliases without allocating peer state") {
    uint8_t wire[512],bad[512],reply[64]; size_t n=hello(wire,NULL,0u,NULL,0u),size; crypto_dtls_cookie_result result;
    const size_t fields[]={0,1,3,12,13,16,19,22,25,59,60,62,65,66};
    crypto_dtls_cookie_context before=ctx;
    for (size_t i=0u; i<sizeof(fields)/sizeof(fields[0]); ++i) {
      memcpy(bad,wire,n); bad[fields[i]]=0xff;
      check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),bad,n,100u,reply,sizeof(reply),&size,&result),SALTS_CRYPTO_EVERIFY);
      check_equal(size,0u); check_true(!result.address_verified); check_equal(&ctx,&before,sizeof(ctx));
    }
    const uint8_t duplicates[]={0,8,0,13,0,0,0,13,0,0};
    n=hello(bad,NULL,0u,duplicates,sizeof(duplicates));
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),bad,n,100u,reply,sizeof(reply),&size,&result),SALTS_CRYPTO_EVERIFY);
    n=hello(wire,NULL,0u,NULL,0u); memcpy(bad,wire,n);
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),wire,n,100u,wire,sizeof(wire),&size,&result),SALTS_CRYPTO_EINVAL);
    check_equal(wire,bad,n);
    check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),wire,n,100u,reply,59u,&size,&result),SALTS_CRYPTO_EINVAL);
    check_equal(size,0u); check_equal(&ctx,&before,sizeof(ctx));
    crypto_dtls_cookie_clear(&ctx); check_true(zero(&ctx,sizeof(ctx)));
  }
}

spec("Private DTLS bounded message assembly") {
  static crypto_dtls_reassembly s,before;
  before_each() { memset(&s,0,sizeof(s)); check_equal(crypto_dtls_reassembly_init(&s,7u,16384u),0); }
  after_each() { crypto_dtls_reassembly_clear(&s); crypto_dtls_reassembly_clear(&before); }
  it("queues future messages, accepts consistent overlapping fragments and exposes each expected message once") {
    const uint8_t body[]="abcdefghij"; uint8_t wire[128]; size_t size,consumed; crypto_dtls_message msg;
    check_equal(crypto_dtls_fragment_write(14u,8u,NULL,0u,0u,0u,wire,sizeof(wire),&size),0);
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),0);
    check_equal(crypto_dtls_reassembly_peek(&s,&msg),CRYPTO_DTLS_HANDSHAKE_NEED); check_true(!msg.body);
    const size_t offsets[]={5u,0u,2u},lengths[]={5u,4u,5u};
    for (size_t i=0u; i<3u; ++i) {
      check_equal(crypto_dtls_fragment_write(11u,7u,body,10u,offsets[i],lengths[i],wire,sizeof(wire),&size),0);
      check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),0); check_equal(consumed,size);
    }
    check_equal(crypto_dtls_reassembly_peek(&s,&msg),0); check_equal(msg.size,10u); check_equal(msg.body,body,10u);
    check_equal(s.slots[7u].received,10u);
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),0); check_equal(s.slots[7u].received,10u);
    check_equal(crypto_dtls_reassembly_consume(&s),0); check_true(zero(&s.slots[7u],sizeof(s.slots[0])));
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),CRYPTO_DTLS_HANDSHAKE_OLD);
    check_equal(crypto_dtls_reassembly_peek(&s,&msg),0); check_equal(msg.type,14u); check_equal(msg.size,0u);
    check_equal(crypto_dtls_reassembly_consume(&s),0); check_equal(s.next,9u);
  }
  it("preserves all owned bytes and counts on conflicting overlap/type/length or out-of-window input") {
    uint8_t wire[128]; size_t size,consumed;
    check_equal(crypto_dtls_fragment_write(11u,7u,"abcdefghij",10u,0u,5u,wire,sizeof(wire),&size),0);
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),0); before=s;
    check_equal(crypto_dtls_fragment_write(11u,7u,"abXdefghij",10u,2u,8u,wire,sizeof(wire),&size),0);
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),SALTS_CRYPTO_EVERIFY);
    check_equal(consumed,0u); check_equal(&s,&before,sizeof(s));
    check_equal(crypto_dtls_fragment_write(12u,7u,"abcdefghij",10u,5u,5u,wire,sizeof(wire),&size),0);
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),SALTS_CRYPTO_EVERIFY); check_equal(&s,&before,sizeof(s));
    check_equal(crypto_dtls_fragment_write(11u,7u,"abcdefghi",9u,5u,4u,wire,sizeof(wire),&size),0);
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),SALTS_CRYPTO_EVERIFY); check_equal(&s,&before,sizeof(s));
    check_equal(crypto_dtls_fragment_write(14u,15u,NULL,0u,0u,0u,wire,sizeof(wire),&size),0);
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),CRYPTO_DTLS_HANDSHAKE_NEED); check_equal(&s,&before,sizeof(s));
    check_equal(crypto_dtls_reassembly_feed(&s,&s,sizeof(s),&consumed),SALTS_CRYPTO_EINVAL); check_equal(&s,&before,sizeof(s));
  }
  it("checks zero-progress fragments and 24-bit arithmetic and never wraps message sequence") {
    uint8_t wire[128]={0}; size_t size,consumed;
    check_equal(crypto_dtls_handshake_header(11u,7u,10u,0u,0u,wire),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_handshake_header(11u,7u,SIZE_MAX,0u,1u,wire),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_fragment_write(11u,7u,"F",1u,1u,1u,wire,sizeof(wire),&size),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_fragment_write(11u,7u,"F",1u,0u,1u,wire,sizeof(wire),&size),0);
    wire[6]=wire[7]=wire[8]=0xff;
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),SALTS_CRYPTO_EVERIFY);
    crypto_dtls_reassembly_clear(&s); check_equal(crypto_dtls_reassembly_init(&s,UINT16_MAX,10u),0);
    check_equal(crypto_dtls_fragment_write(14u,UINT16_MAX,NULL,0u,0u,0u,wire,sizeof(wire),&size),0);
    check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),0); check_equal(crypto_dtls_reassembly_consume(&s),0);
    check_equal(s.next,65536u); check_equal(crypto_dtls_reassembly_feed(&s,wire,size,&consumed),SALTS_CRYPTO_ESTATE);
  }
}

spec("Private DTLS flight timer and actual-send ownership") {
  it("authorizes a recognized peer retransmission once and shares the timeout retry budget") {
    crypto_dtls_flight_timer t={0}; bool due;
    check_equal(crypto_dtls_flight_timer_init(&t,1000u,60000u,1u),0);
    check_equal(crypto_dtls_flight_timer_sent(&t,0u),0);
    check_equal(crypto_dtls_flight_timer_repeat(&t,100u,&due),0); check_true(due);
    check_equal(t.interval,2000u); check_equal(t.retries,1u);
    check_equal(crypto_dtls_flight_timer_repeat(&t,200u,&due),0); check_true(!due);
    check_equal(crypto_dtls_flight_timer_sent(&t,300u),0); check_equal(t.deadline,2300u);
    check_equal(crypto_dtls_flight_timer_repeat(&t,301u,&due),CRYPTO_DTLS_TIMER_EXHAUSTED); check_true(!due);
    check_equal(crypto_dtls_flight_timer_poll(&t,0u,&due),CRYPTO_DTLS_TIMER_EXHAUSTED);
    crypto_dtls_flight_timer_clear(&t);
  }
  it("arms only after sent, authorizes one retry, doubles/caps intervals and terminates exhaustion") {
    crypto_dtls_flight_timer t={0}; bool due=true;
    check_equal(crypto_dtls_flight_timer_init(&t,1000u,3000u,3u),0);
    check_equal(crypto_dtls_flight_timer_poll(&t,100u,&due),0); check_true(!due);
    check_equal(crypto_dtls_flight_timer_sent(&t,100u),0); check_equal(t.deadline,1100u);
    check_equal(crypto_dtls_flight_timer_poll(&t,1099u,&due),0); check_true(!due);
    check_equal(crypto_dtls_flight_timer_poll(&t,1100u,&due),0); check_true(due); check_equal(t.interval,2000u);
    check_equal(crypto_dtls_flight_timer_poll(&t,9000u,&due),0); check_true(!due); check_equal(t.retries,1u);
    check_equal(crypto_dtls_flight_timer_sent(&t,9000u),0); check_equal(t.deadline,11000u);
    check_equal(crypto_dtls_flight_timer_poll(&t,11000u,&due),0); check_true(due); check_equal(t.interval,3000u);
    check_equal(crypto_dtls_flight_timer_sent(&t,11000u),0);
    check_equal(crypto_dtls_flight_timer_poll(&t,14000u,&due),0); check_true(due); check_equal(t.interval,3000u);
    check_equal(crypto_dtls_flight_timer_sent(&t,14000u),0);
    check_equal(crypto_dtls_flight_timer_poll(&t,17000u,&due),CRYPTO_DTLS_TIMER_EXHAUSTED); check_true(!due);
    check_equal(crypto_dtls_flight_timer_poll(&t,17001u,&due),CRYPTO_DTLS_TIMER_EXHAUSTED);
    check_equal(crypto_dtls_flight_timer_poll(&t,0u,&due),CRYPTO_DTLS_TIMER_EXHAUSTED);
    crypto_dtls_flight_timer_clear(&t);
  }
  it("stops acknowledged flights and latches backwards clocks/overflow instead of retrying") {
    crypto_dtls_flight_timer t={0}; bool due;
    check_equal(crypto_dtls_flight_timer_init(&t,1000u,60000u,2u),0);
    check_equal(crypto_dtls_flight_timer_sent(&t,100u),0); check_equal(crypto_dtls_flight_timer_ack(&t),0);
    check_equal(crypto_dtls_flight_timer_poll(&t,90000u,&due),0); check_true(!due);
    check_equal(crypto_dtls_flight_timer_sent(&t,90000u),SALTS_CRYPTO_ESTATE);
    crypto_dtls_flight_timer_clear(&t); check_equal(crypto_dtls_flight_timer_init(&t,1000u,60000u,2u),0);
    check_equal(crypto_dtls_flight_timer_sent(&t,100u),0);
    check_equal(crypto_dtls_flight_timer_poll(&t,99u,&due),SALTS_CRYPTO_ESTATE);
    check_equal(crypto_dtls_flight_timer_poll(&t,1100u,&due),SALTS_CRYPTO_ESTATE); check_true(!due);
    crypto_dtls_flight_timer_clear(&t); check_equal(crypto_dtls_flight_timer_init(&t,1000u,60000u,2u),0);
    check_equal(crypto_dtls_flight_timer_sent(&t,UINT64_MAX-999u),SALTS_CRYPTO_ESTATE);
    check_equal(crypto_dtls_flight_timer_poll(&t,UINT64_MAX,&due),SALTS_CRYPTO_ESTATE);
    crypto_dtls_flight_timer_clear(&t);
  }
}

spec("Independent DTLS cookie and transcript framing oracle") {
  it("verifies a Python cookie and emits an independently verifiable challenge and normalized message") {
    const char *first=getenv("SALTS_DTLS_FIRST"),*second=getenv("SALTS_DTLS_SECOND"),*reply_path=getenv("SALTS_DTLS_REPLY");
    const char *fragments=getenv("SALTS_DTLS_FRAGMENTS"),*canonical=getenv("SALTS_DTLS_CANONICAL");
    check_true(first && second && reply_path && fragments && canonical);
    if (first && second && reply_path && fragments && canonical) {
      crypto_dtls_cookie_context ctx={.lifetime_ms=1000u,.ready=true};
      for (size_t i=0u; i<32u; ++i) ctx.key[i]=(uint8_t)i;
      uint8_t input[8192],reply[64]; size_t size,n; crypto_dtls_cookie_result result;
      FILE *file=fopen(first,"rb"); check_true(file!=NULL); size=0;
      if (file) { size=fread(input,1u,sizeof(input),file); check_true(!ferror(file)); check_equal(fclose(file),0); }
      check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),input,size,200u,reply,sizeof(reply),&n,&result),0);
      check_true(!result.address_verified); check_equal(n,60u);
      file=fopen(reply_path,"wb"); check_true(file!=NULL); if (file) { check_equal(fwrite(reply,1u,n,file),n); check_equal(fclose(file),0); }
      file=fopen(second,"rb"); check_true(file!=NULL); size=0;
      if (file) { size=fread(input,1u,sizeof(input),file); check_true(!ferror(file)); check_equal(fclose(file),0); }
      check_equal(crypto_dtls_cookie_gate(&ctx,address,sizeof(address),input,size,200u,reply,sizeof(reply),&n,&result),0);
      check_true(result.address_verified); check_equal(n,0u); crypto_dtls_cookie_clear(&ctx);
      static crypto_dtls_reassembly s; memset(&s,0,sizeof(s)); check_equal(crypto_dtls_reassembly_init(&s,7u,4096u),0);
      file=fopen(fragments,"rb"); check_true(file!=NULL); size=0;
      if (file) { size=fread(input,1u,sizeof(input),file); check_true(!ferror(file)); check_equal(fclose(file),0); }
      size_t at=0u;
      while (at<size) { size_t consumed=0u; int status=crypto_dtls_reassembly_feed(&s,input+at,size-at,&consumed);
        check_equal(status,0); check_true(consumed>0u && consumed<=size-at); if (status || !consumed || consumed>size-at) break; at+=consumed; }
      check_equal(at,size); crypto_dtls_message msg; check_equal(crypto_dtls_reassembly_peek(&s,&msg),0);
      uint8_t header[12]; check_equal(crypto_dtls_handshake_header(msg.type,msg.sequence,msg.size,0u,msg.size,header),0);
      file=fopen(canonical,"wb"); check_true(file!=NULL); if (file) {
        check_equal(fwrite(header,1u,sizeof(header),file),sizeof(header)); check_equal(fwrite(msg.body,1u,msg.size,file),msg.size); check_equal(fclose(file),0); }
      check_equal(crypto_dtls_reassembly_consume(&s),0); crypto_dtls_reassembly_clear(&s);
    }
  }
}
