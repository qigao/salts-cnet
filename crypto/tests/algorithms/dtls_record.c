#include "../../src/crypto_dtls_record.h"
#include <tinytest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const uint8_t salt[4]={0xa0,0xa1,0xa2,0xa3};
static int all_zero(const void *data,size_t size) {
  const uint8_t *p=data; unsigned bits=0; while (size--) bits|=*p++; return !bits;
}
spec("Private DTLS1.2 AES128-GCM record protocol") {
  static crypto_dtls_record_epoch tx,rx;
  before_each() {
    memset(&tx,0,sizeof(tx)); memset(&rx,0,sizeof(rx));
    check_equal(crypto_dtls_record_init(&tx,1u,key,salt),SALTS_CRYPTO_OK);
    check_equal(crypto_dtls_record_init(&rx,1u,key,salt),SALTS_CRYPTO_OK);
  }
  after_each() { crypto_dtls_record_clear(&tx); crypto_dtls_record_clear(&rx); }
  it("authenticates data and consumes sequence exactly once after reserved output") {
    uint8_t wire[64],plain[32]; size_t n=99u,out=99u; uint8_t type=0;
    check_equal(crypto_dtls_record_seal(&tx,23u,"hello",5u,wire,41u,&n),SALTS_CRYPTO_EINVAL);
    check_equal(n,0u); check_equal(tx.next_send,0u);
    check_equal(crypto_dtls_record_seal(&tx,23u,"hello",5u,wire,sizeof(wire),&n),SALTS_CRYPTO_OK);
    check_equal(n,42u); check_equal(tx.next_send,1u);
    const uint8_t header[]={23,0xfe,0xfd,0,1,0,0,0,0,0,0,0,29};
    check_equal(wire,header,sizeof(header)); check_equal(wire+13,wire+3,8u);
    check_equal(crypto_dtls_record_open(&rx,wire,n,plain,sizeof(plain),&out,&type),SALTS_CRYPTO_OK);
    check_equal(out,5u); check_equal(type,23u); check_equal(plain,"hello",5u);
    check_equal(crypto_dtls_record_open(&rx,wire,n,plain,sizeof(plain),&out,&type),CRYPTO_DTLS_RECORD_DROP);
    check_equal(out,0u); check_equal(type,0u);
  }
  it("commits the 64-record replay window only after authentication, including reordering and large jumps") {
    uint8_t wire[6][64],plain[4],type; size_t size[6],n;
    const uint64_t seq[]={0u,1u,2u,64u,65u,50000u};
    for (size_t i=0u; i<6u; ++i) {
      tx.next_send=seq[i];
      check_equal(crypto_dtls_record_seal(&tx,23u,"F",1u,wire[i],64u,&size[i]),SALTS_CRYPTO_OK);
    }
    const unsigned order[]={3,1,0,1,4,2,4,5,4};
    const int expected[]={0,0,1,1,0,0,1,0,1};
    for (size_t i=0u; i<9u; ++i) {
      check_equal(crypto_dtls_record_open(&rx,wire[order[i]],size[order[i]],plain,sizeof(plain),&n,&type),expected[i]);
      check_equal(n,expected[i] ? 0u : 1u);
    }
    check_equal(rx.highest_received,50000u); check_equal(rx.replay_window,1u);
  }
  it("rejects forged sequence/epoch/type/version/nonce/cipher/tag without advancing replay state") {
    uint8_t wire[64],forged[64],plain[8],type; size_t size,n;
    check_equal(crypto_dtls_record_seal(&tx,23u,"abc",3u,wire,sizeof(wire),&size),SALTS_CRYPTO_OK);
    const unsigned mutations[]={0u,2u,4u,5u,13u,21u,39u};
    for (size_t i=0u; i<7u; ++i) {
      crypto_dtls_record_epoch before=rx; memcpy(forged,wire,size); forged[mutations[i]]^=1u;
      memset(plain,0xa5,sizeof(plain)); n=99u; type=0xff;
      check_not_equal(crypto_dtls_record_open(&rx,forged,size,plain,sizeof(plain),&n,&type),SALTS_CRYPTO_OK);
      check_equal(n,0u); check_equal(type,0u); check_equal(&rx,&before,sizeof(rx));
    }
    /* An unauthenticated enormous sequence must not evict a real low sequence. */
    memcpy(forged,wire,size); memset(forged+5,0xff,6u); memset(plain,0xa5,sizeof(plain));
    check_equal(crypto_dtls_record_open(&rx,forged,size,plain,sizeof(plain),&n,&type),SALTS_CRYPTO_EVERIFY);
    check_true(all_zero(plain,3u)); check_equal(plain[3],0xa5u); check_true(!rx.received);
    check_equal(crypto_dtls_record_open(&rx,wire,size,plain,sizeof(plain),&n,&type),SALTS_CRYPTO_OK);
  }
  it("never wraps the 48-bit sending sequence or resets a live key") {
    uint8_t wire[64]; size_t n=99u;
    crypto_dtls_record_epoch before=tx;
    check_equal(crypto_dtls_record_init(&tx,2u,key,salt),SALTS_CRYPTO_ESTATE);
    check_equal(&tx,&before,sizeof(tx)); tx.next_send=CRYPTO_DTLS_MAX_SEQUENCE;
    check_equal(crypto_dtls_record_seal(&tx,21u,"ab",2u,wire,sizeof(wire),&n),SALTS_CRYPTO_OK);
    const uint8_t last[]={0xff,0xff,0xff,0xff,0xff,0xff}; check_equal(wire+5,last,6u);
    check_equal(tx.next_send,CRYPTO_DTLS_MAX_SEQUENCE+1u);
    check_equal(crypto_dtls_record_seal(&tx,21u,"ab",2u,wire,sizeof(wire),&n),SALTS_CRYPTO_ESTATE);
    check_equal(n,0u);
    crypto_dtls_record_clear(&tx); check_true(all_zero(&tx,sizeof(tx)));
    check_equal(crypto_dtls_record_init(&tx,0u,key,salt),SALTS_CRYPTO_EINVAL);
  }
  it("bounds maximum and empty records and preserves coalesced datagram views") {
    static uint8_t data[CRYPTO_DTLS_MAX_PLAINTEXT],wire[2*(CRYPTO_DTLS_MAX_PLAINTEXT+CRYPTO_DTLS_RECORD_OVERHEAD)],out[CRYPTO_DTLS_MAX_PLAINTEXT];
    memset(data,0x46,sizeof(data)); size_t n,m,opened; uint8_t type;
    check_equal(crypto_dtls_record_seal(&tx,22u,data,sizeof(data),wire,sizeof(wire),&n),SALTS_CRYPTO_OK);
    check_equal(n,sizeof(data)+CRYPTO_DTLS_RECORD_OVERHEAD);
    check_equal(crypto_dtls_record_seal(&tx,23u,NULL,0u,wire+n,sizeof(wire)-n,&m),SALTS_CRYPTO_OK);
    check_equal(m,CRYPTO_DTLS_RECORD_OVERHEAD);
    crypto_dtls_record_view a,b;
    check_equal(crypto_dtls_record_parse(wire,n+m,&a),SALTS_CRYPTO_OK); check_equal(a.record_size,n);
    check_equal(crypto_dtls_record_parse(wire+n,m,&b),SALTS_CRYPTO_OK); check_equal(b.record_size,m);
    check_equal(crypto_dtls_record_open(&rx,wire,n,out,sizeof(out),&opened,&type),SALTS_CRYPTO_OK);
    check_equal(opened,sizeof(data)); check_equal(out,data,sizeof(data));
    check_equal(crypto_dtls_record_open(&rx,wire+n,m,out,0u,&opened,&type),SALTS_CRYPTO_OK); check_equal(opened,0u);
    crypto_dtls_record_view old=a;
    check_equal(crypto_dtls_record_parse(wire,12u,&a),SALTS_CRYPTO_EVERIFY); check_equal(&a,&old,sizeof(a));
    check_equal(crypto_dtls_record_seal(&tx,23u,data,sizeof(data)+1u,wire,sizeof(wire),&n),SALTS_CRYPTO_EINVAL);
  }
  it("rejects aliases before clearing caller storage or changing key state") {
    uint8_t wire[64],plain[16],type; size_t n,size; size_t alias[8]; memset(alias,0xa5,sizeof(alias));
    crypto_dtls_record_epoch before=tx;
    check_equal(crypto_dtls_record_seal(&tx,23u,alias,8u,wire,sizeof(wire),alias),SALTS_CRYPTO_EINVAL);
    check_equal(((uint8_t *)alias)[0],0xa5u); check_equal(&tx,&before,sizeof(tx));
    check_equal(crypto_dtls_record_seal(&tx,23u,&tx,8u,wire,sizeof(wire),&size),SALTS_CRYPTO_EINVAL);
    check_equal(crypto_dtls_record_init(&tx,2u,(const uint8_t *)&tx,salt),SALTS_CRYPTO_EINVAL);
    check_equal(&tx,&before,sizeof(tx));
    check_equal(crypto_dtls_record_seal(&tx,23u,"F",1u,wire,sizeof(wire),&size),SALTS_CRYPTO_OK);
    memset(plain,0xa5,sizeof(plain)); before=rx;
    check_equal(crypto_dtls_record_open(&rx,wire,size,plain,sizeof(plain),&n,plain),SALTS_CRYPTO_EINVAL);
    check_equal(plain[0],0xa5u); check_equal(&rx,&before,sizeof(rx));
    check_equal(crypto_dtls_record_open(&rx,wire,size,plain,sizeof(plain),&n,&type),SALTS_CRYPTO_OK);
  }
  it("exchanges exact records with an independent AESGCM peer") {
    const char *input=getenv("SALTS_DTLS_RECORD_INPUT"),*output=getenv("SALTS_DTLS_RECORD_OUTPUT");
    check_true(input && output);
    if (input && output) {
      uint8_t wire[128],plain[128],type; size_t n=0u;
      FILE *file=fopen(input,"rb"); check_true(file!=NULL);
      if (file) { n=fread(wire,1u,sizeof(wire),file); check_true(!ferror(file)); check_equal(fclose(file),0); }
      size_t opened=0u;
      check_equal(crypto_dtls_record_open(&rx,wire,n,plain,sizeof(plain),&opened,&type),SALTS_CRYPTO_OK);
      check_equal(opened,23u); check_equal(plain,"independent DTLS record",23u); check_equal(type,23u);
      check_equal(rx.highest_received,17u);
      check_equal(crypto_dtls_record_seal(&tx,23u,"native DTLS record",18u,wire,sizeof(wire),&n),SALTS_CRYPTO_OK);
      file=fopen(output,"wb"); check_true(file!=NULL);
      if (file) { check_equal(fwrite(wire,1u,n,file),n); check_equal(fclose(file),0); }
    }
  }
}
