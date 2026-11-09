/* Pipe endpoint for the module-owned independent DTLS state-machine oracle.
 * Send terminals/time are supplied by the oracle, not claimed as NativeIO. */
#include "../../src/crypto_dtls_client.h"
#include <gmssl/mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
typedef struct endpoint {
  crypto_dtls_client client;
  uint8_t application[32768]; size_t application_size;
  int references,checks,reject;
} endpoint;
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0]<<24u | (uint32_t)p[1]<<16u | (uint32_t)p[2]<<8u | p[3]; }
static void put32(uint8_t *p,uint32_t n) { for (unsigned i=0;i<4u;++i) p[i]=(uint8_t)(n>>(24u-8u*i)); }
static int zero(const void *p,size_t n) { const uint8_t *b=p; unsigned v=0; while (n--) v|=*b++; return !v; }
static void retain(void *context) { ++((endpoint *)context)->references; }
static void release(void *context) { --((endpoint *)context)->references; }
static int policy(void *context,const crypto_tls_stream_peer_certificate_chain *chain,bool server,crypto_tls_stream_security_profile profile) {
  endpoint *e=context; ++e->checks;
  if (!server || !chain->count || profile!=CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD ||
      !e->client.verified_finished || e->client.phase!=CRYPTO_DTLS_CLIENT_FINISHED) return -1;
  if (crypto_dtls_client_abort(&e->client)!=SALTS_CRYPTO_ESTATE) return -1; /* Reentry must reject. */
  return e->reject ? -1 : 0;
}
static int application(void *context,const uint8_t *data,size_t size) {
  endpoint *e=context;
  if (e->client.phase!=CRYPTO_DTLS_CLIENT_READY || e->application_size>sizeof(e->application)-2u ||
      size>sizeof(e->application)-e->application_size-2u) return -1;
  uint8_t *p=e->application+e->application_size; p[0]=(uint8_t)(size>>8u); p[1]=(uint8_t)size;
  if (size) memcpy(p+2u,data,size); e->application_size+=2u+size;
  return crypto_dtls_client_write(&e->client,"reentry",7u)==SALTS_CRYPTO_ESTATE ? 0 : -1;
}
int main(int argc,char **argv) {
  if ((argc!=3 && argc!=4 && argc!=5) || (argc==5 && strcmp(argv[4],"exporter"))) return 2;
#ifdef _WIN32
  if (_setmode(_fileno(stdin),_O_BINARY)==-1 || _setmode(_fileno(stdout),_O_BINARY)==-1) return 2;
#endif
  endpoint *e=calloc(1u,sizeof(*e)); if (!e) return 2;
  e->reject=strcmp(argv[2],"reject")==0;
  const crypto_tls_stream_peer_policy peer_policy={policy,retain,release,e,CRYPTO_TLS_PEER_POLICY_STANDARD,CRYPTO_TLS_PEER_POLICY_SERVER};
  uint8_t request[13],input[CRYPTO_DTLS_MAX_PLAINTEXT+CRYPTO_DTLS_RECORD_OVERHEAD+1u]; int result=0;
  for (;;) {
    size_t n=fread(request,1u,sizeof(request),stdin);
    if (!n && feof(stdin)) break;
    if (n!=sizeof(request)) { result=2; break; }
    const size_t size=get32(request+9u); uint64_t now=0;
    for (unsigned i=1u;i<=8u;++i) now=(now<<8u)|request[i];
    if (size>sizeof(input) || fread(input,1u,size,stdin)!=size) { result=2; break; }
    int status; const uint8_t *output=NULL; size_t output_size=0;
    switch (request[0]) {
      case 'I': {
        const char *alpn=argc>=4 ? argv[3] : "test";
        crypto_dtls_client_config config={input,size,argv[1],strlen(argv[1]),alpn,strlen(alpn),
          strcmp(argv[2],"none")==0 ? NULL : &peer_policy,application,e};
        config.enable_exporter=argc==5;
        status=crypto_dtls_client_init(&e->client,&config); break;
      }
      case 'J': {
        if (size<13u) { status=SALTS_CRYPTO_EINVAL; break; }
        const size_t roots=get32(input+1u),cert=get32(input+5u),key=get32(input+9u);
        if (roots>size-13u || cert>size-13u-roots || key!=size-13u-roots-cert || input[0]>1u) {
          status=SALTS_CRYPTO_EINVAL; break;
        }
        crypto_tls_credentials raw={0}; raw.size=sizeof(raw);
        raw.certificate_chain=(crypto_tls_data){input+13u+roots,cert,CRYPTO_TLS_ENCODING_DER};
        raw.private_key=(crypto_tls_data){input+13u+roots+cert,key,CRYPTO_TLS_ENCODING_DER};
        crypto_tls_credential_object *object=NULL; crypto_tls_credentials from_object={0}; from_object.size=sizeof(from_object);
        status=0;
        if (input[0] && cert) {
          status=crypto_tls_credential_object_create(&raw,CRYPTO_TLS_CREDENTIAL_SINGLE,&object);
          from_object.object=object;
        }
        const char *alpn=argc>=4 ? argv[3] : "test";
        const crypto_dtls_client_config config={input+13u,roots,argv[1],strlen(argv[1]),alpn,strlen(alpn),
          strcmp(argv[2],"none")==0 ? NULL : &peer_policy,application,e,cert ? (input[0] ? &from_object : &raw) : NULL,argc==5};
        if (!status) status=crypto_dtls_client_init(&e->client,&config);
        crypto_tls_credential_object_release(object); break;
      }
      case 'E': {
        if (size<7u || input[0]>1u) { status=SALTS_CRYPTO_EINVAL; break; }
        const size_t label=(size_t)input[1]*256u+input[2],context=(size_t)input[3]*256u+input[4],n=(size_t)input[5]*256u+input[6];
        if (label>size-7u || context!=size-7u-label) { status=SALTS_CRYPTO_EINVAL; break; }
        const crypto_dtls_export_request r={input+7u,label,input+7u+label,context,input[0]!=0u};
        status=crypto_dtls_client_export(&e->client,&r,e->application,n);
        if (!status) { output=e->application; output_size=n; } break;
      }
      case 'Q':
        e->application[0]=e->client.fatal.description; e->application[1]=e->client.fatal.peer_description;
        put32(e->application+2u,(uint32_t)e->client.fatal.error); output=e->application; output_size=6u; status=0; break;
      case 'N': status=crypto_dtls_client_next(&e->client,now,&output,&output_size); break;
      case 'S': status=size==1u ? crypto_dtls_client_sent(&e->client,now,input[0]!=0u) : SALTS_CRYPTO_EINVAL; break;
      case 'R':
        e->application_size=0u; status=crypto_dtls_client_receive(&e->client,now,input,size);
        output=e->application; output_size=e->application_size; break;
      case 'W': status=crypto_dtls_client_write(&e->client,input,size); break;
      case 'O': status=crypto_dtls_client_close(&e->client); break;
      case 'A':
        status=crypto_dtls_client_abort(&e->client);
        if (e->client.pending) { output=e->client.pending_wire; output_size=e->client.pending_size; }
        break;
      case 'C': status=crypto_dtls_client_clear(&e->client); break;
      default: result=2; goto done;
    }
    uint8_t response[24]={0}; put32(response,(uint32_t)status); response[4]=(uint8_t)e->client.phase;
    response[5]=(uint8_t)(e->client.pending | (e->client.saw_ccs<<1u) | (e->client.verified_finished<<2u) |
      (zero(&e->client.secrets,sizeof(e->client.secrets))<<3u) | (zero(&e->client.ephemeral.key,sizeof(e->client.ephemeral.key))<<4u) |
      (zero(e->client.secrets.master,sizeof(e->client.secrets.master))<<5u) |
      (zero(&e->client.identity,sizeof(e->client.identity))<<6u) | (e->client.selected_identity<<7u));
    response[6]=(uint8_t)((unsigned)e->checks>>8u); response[7]=(uint8_t)e->checks;
    put32(response+8u,(uint32_t)e->references); put32(response+12u,(uint32_t)e->client.verify_result);
    put32(response+16u,(uint32_t)e->client.verify_index); put32(response+20u,(uint32_t)output_size);
    if (fwrite(response,1u,sizeof(response),stdout)!=sizeof(response) ||
        (output_size && fwrite(output,1u,output_size,stdout)!=output_size) || fflush(stdout)) { result=2; break; }
    gmssl_secure_clear(input,sizeof(input));
    gmssl_secure_clear(e->application,sizeof(e->application));
  }
done:
  if (e->client.pending) { (void)crypto_dtls_client_abort(&e->client);
    (void)crypto_dtls_client_sent(&e->client,e->client.last_now,false); }
  if (crypto_dtls_client_clear(&e->client)!=0 || e->references) result=3;
  gmssl_secure_clear(input,sizeof(input)); gmssl_secure_clear(e,sizeof(*e)); free(e); return result;
}
