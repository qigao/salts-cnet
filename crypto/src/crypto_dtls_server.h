#ifndef CRYPTO_DTLS_SERVER_INTERNAL_H
#define CRYPTO_DTLS_SERVER_INTERNAL_H
#include "crypto_dtls_cookie.h"
#include "crypto_dtls_exchange.h"
#include "crypto_dtls_secrets.h"
#include "crypto_dtls_wire.h"
#include <crypto/tls_credentials.h>
#include <gmssl/tls.h>
#include <stdatomic.h>

enum { CRYPTO_DTLS_SERVER_IDLE=1, CRYPTO_DTLS_SERVER_BUSY=2, CRYPTO_DTLS_SERVER_DROP=3,
       CRYPTO_DTLS_SERVER_MTU=1200, CRYPTO_DTLS_SERVER_MESSAGE_BYTES=CRYPTO_DTLS_WIRE_CHAIN_BYTES+18 };
typedef struct crypto_dtls_server_config {
  const crypto_tls_credentials *credentials;
  const crypto_tls_data *client_roots;
  const crypto_tls_stream_peer_policy *peer_policy;
  /* NULL/0 selects the sole fixed identity without SNI routing. A configured
   * DNS name requires exact SNI admission and its RFC6066 acknowledgment. */
  const char *server_name; size_t server_name_size;
  const void *alpn; size_t alpn_size;
  uint32_t cookie_lifetime_ms;
  bool require_client_certificate;
  bool enable_exporter;
} crypto_dtls_server_config;
typedef struct crypto_dtls_server_context {
  TLS_CTX identity;
  crypto_dtls_cookie_context cookie;
  crypto_tls_stream_peer_policy policy;
  atomic_size_t leases;
  char server_name[CRYPTO_DTLS_WIRE_DNS_BYTES+1]; uint8_t alpn[255];
  size_t server_name_size,alpn_size,chain_size;
  uint16_t cipher,signature;
  bool ready,require_client_certificate,policy_retained,in_callback,exporter_enabled;
} crypto_dtls_server_context;
typedef enum crypto_dtls_server_phase {
  CRYPTO_DTLS_SERVER_ZERO, CRYPTO_DTLS_SERVER_CERTIFICATE, CRYPTO_DTLS_SERVER_KEY,
  CRYPTO_DTLS_SERVER_VERIFY, CRYPTO_DTLS_SERVER_FINISHED, CRYPTO_DTLS_SERVER_SEND_FINAL,
  CRYPTO_DTLS_SERVER_READY, CRYPTO_DTLS_SERVER_CLOSING, CRYPTO_DTLS_SERVER_CLOSED, CRYPTO_DTLS_SERVER_FAILED
} crypto_dtls_server_phase;
typedef struct crypto_dtls_server_message {
  uint8_t body[CRYPTO_DTLS_SERVER_MESSAGE_BYTES]; size_t size;
  uint16_t sequence; uint8_t type,handshake_type; bool encrypted;
} crypto_dtls_server_message;
typedef enum crypto_dtls_server_flight_kind {
  CRYPTO_DTLS_SERVER_INITIAL_FLIGHT, CRYPTO_DTLS_SERVER_FINAL_FLIGHT,
  CRYPTO_DTLS_SERVER_REPEAT_FLIGHT, CRYPTO_DTLS_SERVER_APPLICATION, CRYPTO_DTLS_SERVER_CLOSE
} crypto_dtls_server_flight_kind;
typedef struct crypto_dtls_server {
  crypto_dtls_server_context *context;
  crypto_dtls_reassembly messages;
  crypto_dtls_transcript transcript;
  crypto_dtls_ephemeral ephemeral;
  crypto_dtls_secrets secrets;
  crypto_dtls_flight_timer timer;
  crypto_dtls_fatal fatal;
  crypto_dtls_server_message flight[5];
  uint8_t pending_wire[CRYPTO_DTLS_SERVER_MTU],scratch[CRYPTO_DTLS_MAX_PLAINTEXT];
  uint8_t chain[CRYPTO_DTLS_WIRE_CHAIN_BYTES],client_random[32],server_random[32];
  uint8_t hello_hash[32],client_finished[12],server_finished[12];
  size_t chain_size,flight_count,flight_index,flight_offset,pending_size,pending_advance;
  uint64_t plain_sequence,last_now;
  uint16_t client_first,client_finished_sequence,server_finished_sequence;
  crypto_dtls_server_phase phase;
  crypto_dtls_server_flight_kind flight_kind;
  int failure,verify_result; size_t verify_index;
  int (*on_data)(void *,const uint8_t *,size_t); void *data_context;
  bool pending,in_callback,saw_ccs,verified_finished,offered_points,offered_renegotiation,offered_sni;
  bool write_epoch,read_epoch;
} crypto_dtls_server;

/* Private fixed DTLS1.2 profile. Context init/clear/admission lifecycle is
 * exclusive; separate admitted stream owners may execute concurrently.
 * Context storage lives through successful clear, which rejects active leases. */
int crypto_dtls_server_context_init(crypto_dtls_server_context *,const crypto_dtls_server_config *);
int crypto_dtls_server_context_clear(crypto_dtls_server_context *);
/* Stateless listener uses crypto_dtls_cookie_gate BEFORE reserving stream
 * storage. Accept independently validates that proof, then acquires a lease.
 * Invalid cookie leaves zero stream unchanged and returns DROP. Config bytes
 * and incoming packet are immutable borrows during calls only. */
int crypto_dtls_server_accept(crypto_dtls_server *,crypto_dtls_server_context *,
    const void *address,size_t address_size,const void *wire,size_t size,uint64_t now,
    int (*on_data)(void *,const uint8_t *,size_t),void *data_context);
/* FAILED may still publish one sealed fatal; sent preserves original failure.
 * No retry. Clear may discard an unprepared alert, never a native wire borrow. */
int crypto_dtls_server_next(crypto_dtls_server *,uint64_t now,const uint8_t **wire,size_t *size);
/* Exactly one actual terminal per successful next, even after abort. */
int crypto_dtls_server_sent(crypto_dtls_server *,uint64_t now,bool success);
/* Caller pins the peer address at admission. Wire is immutable through callback
 * and return. BUSY consumes nothing; caller retains input until actual sends
 * drain. No callback mutation reentry; data borrow expires on callback return. */
int crypto_dtls_server_receive(crypto_dtls_server *,uint64_t now,const void *wire,size_t size);
int crypto_dtls_server_write(crypto_dtls_server *,const void *plain,size_t size);
int crypto_dtls_server_close(crypto_dtls_server *);
/* Same private exporter contract as client; context/owner bytes cannot alias
 * inputs/output. READY means the final Finished's actual send has completed. */
int crypto_dtls_server_export(const crypto_dtls_server *,const crypto_dtls_export_request *,void *,size_t);
int crypto_dtls_server_abort(crypto_dtls_server *);
int crypto_dtls_server_data_failed(crypto_dtls_server *);
int crypto_dtls_server_clear(crypto_dtls_server *);
#endif
