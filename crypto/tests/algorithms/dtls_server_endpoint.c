/* Formal wire endpoint. UDP address pinning and actual send terminals belong
 * to the Go test adapter; this endpoint has no NativeIO claim. */
#include "../../src/crypto_dtls_server.h"
#include <gmssl/mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
typedef struct endpoint {
  crypto_dtls_server_context context; crypto_dtls_server server;
  uint8_t application[32768],peer[32]; size_t application_size,peer_size;
  int references,checks; bool reject;
} endpoint;
static unsigned get32(const uint8_t *p) { return (unsigned)p[0]<<24u | (unsigned)p[1]<<16u | (unsigned)p[2]<<8u | p[3]; }
static void put32(uint8_t *p,uint32_t n) { for (unsigned i=0;i<4u;++i) p[i]=(uint8_t)(n>>(24u-8u*i)); }
static int zero(const void *p,size_t n) { const uint8_t *v=p; unsigned x=0; while(n--) x|=*v++; return !x; }
static void retain(void *p) { ++((endpoint *)p)->references; }
static void release(void *p) { --((endpoint *)p)->references; }
static int check(void *p,const crypto_tls_stream_peer_certificate_chain *chain,bool server,crypto_tls_stream_security_profile profile) {
  endpoint *e=p; ++e->checks;
  if (server || !chain->count || profile!=CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD ||
      !e->server.verified_finished || e->server.phase!=CRYPTO_DTLS_SERVER_FINISHED ||
      crypto_dtls_server_abort(&e->server)!=SALTS_CRYPTO_ESTATE) return -1;
  return e->reject ? -1 : 0;
}
static int application(void *p,const uint8_t *data,size_t size) {
  endpoint *e=p;
  if (e->server.phase!=CRYPTO_DTLS_SERVER_READY || e->application_size>sizeof(e->application)-2u ||
      size>sizeof(e->application)-e->application_size-2u) return -1;
  uint8_t *out=e->application+e->application_size; out[0]=(uint8_t)(size>>8u); out[1]=(uint8_t)size;
  if (size) memcpy(out+2u,data,size); e->application_size+=size+2u;
  return crypto_dtls_server_write(&e->server,"reentry",7u)==SALTS_CRYPTO_ESTATE ? 0 : -1;
}
int main(int argc,char **argv) {
  if ((argc!=3 && argc!=4) || (argc==4 && strcmp(argv[3],"exporter")) || (strcmp(argv[2],"strict") && strcmp(argv[2],"static"))) return 2;
#ifdef _WIN32
  if (_setmode(_fileno(stdin),_O_BINARY)==-1 || _setmode(_fileno(stdout),_O_BINARY)==-1) return 2;
#endif
  endpoint *e=calloc(1u,sizeof(*e)); if(!e) return 2; e->reject=strcmp(argv[1],"reject")==0;
  const crypto_tls_stream_peer_policy policy={check,retain,release,e,CRYPTO_TLS_PEER_POLICY_STANDARD,CRYPTO_TLS_PEER_POLICY_CLIENT};
  uint8_t request[13],input[24576],reply[60]; int result=0;
  for (;;) {
    size_t n=fread(request,1u,sizeof(request),stdin); if (!n && feof(stdin)) break;
    if (n!=sizeof(request)) { result=2; break; }
    const size_t size=get32(request+9u); uint64_t now=0;
    for (unsigned i=1u;i<=8u;++i) now=(now<<8u)|request[i];
    if (size>sizeof(input) || fread(input,1u,size,stdin)!=size) { result=2; break; }
    int status; const uint8_t *output=NULL; size_t output_size=0;
    switch(request[0]) {
      case 'I': {
        if (size<14u) { status=SALTS_CRYPTO_EINVAL; break; }
        const size_t cert_size=get32(input+2u),key_size=get32(input+6u),roots_size=get32(input+10u);
        if (cert_size>size-14u || key_size>size-14u-cert_size || roots_size!=size-14u-cert_size-key_size) { status=SALTS_CRYPTO_EINVAL; break; }
        crypto_tls_credentials raw={.size=sizeof(raw),.certificate_chain={input+14u,cert_size,CRYPTO_TLS_ENCODING_DER},
          .private_key={input+14u+cert_size,key_size,CRYPTO_TLS_ENCODING_DER}},object_input={.size=sizeof(raw)};
        crypto_tls_credential_object *object=NULL;
        status=0;
        if (input[1]) { status=crypto_tls_credential_object_create(&raw,CRYPTO_TLS_CREDENTIAL_SINGLE,&object); object_input.object=object; }
        crypto_tls_data roots={input+14u+cert_size+key_size,roots_size,CRYPTO_TLS_ENCODING_DER};
        const bool strict=strcmp(argv[2],"strict")==0;
        crypto_dtls_server_config config={input[1] ? &object_input : &raw,input[0] ? &roots : NULL,
          input[0] ? &policy : NULL,strict ? "localhost" : NULL,strict ? 9u : 0u,"test",4u,10000u,input[0]!=0u,argc==4};
        if (!status) status=crypto_dtls_server_context_init(&e->context,&config);
        crypto_tls_credential_object_release(object); break;
      }
      case 'G': {
        e->application_size=0u;
        if (!size || !input[0] || input[0]>32u || input[0]>size-1u) { status=SALTS_CRYPTO_EINVAL; break; }
        const size_t address_size=input[0],wire_size=size-1u-address_size;
        const uint8_t *address=input+1u,*wire=input+1u+address_size;
        if (e->server.phase==CRYPTO_DTLS_SERVER_ZERO) {
          crypto_dtls_cookie_result gate; size_t reply_size=0;
          status=crypto_dtls_cookie_gate(&e->context.cookie,address,address_size,wire,wire_size,now,reply,sizeof(reply),&reply_size,&gate);
          if (!status && gate.address_verified) {
            status=crypto_dtls_server_accept(&e->server,&e->context,address,address_size,wire,wire_size,now,application,e);
            memcpy(e->peer,address,address_size); e->peer_size=address_size;
          } else if (!status) { output=reply; output_size=reply_size; }
        } else if (address_size!=e->peer_size || memcmp(address,e->peer,address_size)) status=CRYPTO_DTLS_SERVER_DROP;
        else status=crypto_dtls_server_receive(&e->server,now,wire,wire_size);
        if (e->application_size) { output=e->application; output_size=e->application_size; }
        break;
      }
      case 'E': {
        if (size<7u || input[0]>1u) { status=SALTS_CRYPTO_EINVAL; break; }
        const size_t label=(size_t)input[1]*256u+input[2],context=(size_t)input[3]*256u+input[4],n=(size_t)input[5]*256u+input[6];
        if (label>size-7u || context!=size-7u-label) { status=SALTS_CRYPTO_EINVAL; break; }
        const crypto_dtls_export_request r={input+7u,label,input+7u+label,context,input[0]!=0u};
        status=crypto_dtls_server_export(&e->server,&r,e->application,n);
        if (!status) { output=e->application; output_size=n; } break;
      }
      case 'Q':
        e->application[0]=e->server.fatal.description; e->application[1]=e->server.fatal.peer_description;
        put32(e->application+2u,(uint32_t)e->server.fatal.error); output=e->application; output_size=6u; status=0; break;
      case 'N': status=crypto_dtls_server_next(&e->server,now,&output,&output_size); break;
      case 'S': status=size==1u ? crypto_dtls_server_sent(&e->server,now,input[0]!=0u) : SALTS_CRYPTO_EINVAL; break;
      case 'W': status=crypto_dtls_server_write(&e->server,input,size); break;
      case 'O': status=crypto_dtls_server_close(&e->server); break;
      case 'A': status=crypto_dtls_server_abort(&e->server);
        if (e->server.pending) { output=e->server.pending_wire; output_size=e->server.pending_size; } break;
      case 'C': status=crypto_dtls_server_clear(&e->server); if (!status) e->peer_size=0u; break;
      case 'X': status=crypto_dtls_server_context_clear(&e->context); break;
      default: result=2; goto done;
    }
    uint8_t response[24]={0}; put32(response,(uint32_t)status); response[4]=(uint8_t)e->server.phase;
    response[5]=(uint8_t)(e->server.pending | (e->server.saw_ccs<<1u) | (e->server.verified_finished<<2u) |
      (zero(&e->server.secrets,sizeof(e->server.secrets))<<3u) | (zero(&e->server.ephemeral.key,sizeof(e->server.ephemeral.key))<<4u) |
      (zero(e->server.secrets.master,48u)<<5u) | ((e->references!=0)<<6u) | (e->context.ready<<7u));
    response[6]=(uint8_t)((unsigned)e->checks>>8u); response[7]=(uint8_t)e->checks;
    put32(response+8u,e->context.ready ? (uint32_t)atomic_load_explicit(&e->context.leases,memory_order_relaxed) : 0u);
    put32(response+12u,(uint32_t)e->server.verify_result); put32(response+16u,(uint32_t)e->server.verify_index); put32(response+20u,(uint32_t)output_size);
    if (fwrite(response,1u,24u,stdout)!=24u || (output_size && fwrite(output,1u,output_size,stdout)!=output_size) || fflush(stdout)) { result=2; break; }
    gmssl_secure_clear(input,sizeof(input));
    gmssl_secure_clear(e->application,sizeof(e->application));
  }
done:
  if (e->server.pending) { (void)crypto_dtls_server_abort(&e->server); (void)crypto_dtls_server_sent(&e->server,e->server.last_now,false); }
  if (crypto_dtls_server_clear(&e->server)!=0 || crypto_dtls_server_context_clear(&e->context)!=0 || e->references) result=3;
  gmssl_secure_clear(input,sizeof(input)); gmssl_secure_clear(e,sizeof(*e)); free(e); return result;
}
