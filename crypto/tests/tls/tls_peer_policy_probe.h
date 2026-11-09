#include <crypto/tls_stream.h>
#include <stdatomic.h>
#include <string.h>

typedef struct peer_policy_probe {
  atomic_uint references, retains, releases, calls, invalid;
  bool peer_is_server;
  int decision;
  crypto_tls_stream_security_profile profile;
} peer_policy_probe;

static void peer_policy_init(peer_policy_probe *p, bool peer_is_server) {
  memset(p, 0, sizeof(*p));
  atomic_init(&p->references, 1u);
  atomic_init(&p->retains, 0u);
  atomic_init(&p->releases, 0u);
  atomic_init(&p->calls, 0u);
  atomic_init(&p->invalid, 0u);
  p->peer_is_server = peer_is_server;
}
static void peer_policy_retain(void *ctx) {
  peer_policy_probe *p = ctx;
  atomic_fetch_add(&p->references, 1u);
  atomic_fetch_add(&p->retains, 1u);
}
static void peer_policy_release(void *ctx) {
  peer_policy_probe *p = ctx;
  if (atomic_fetch_sub(&p->references, 1u) < 2u)
    atomic_fetch_add(&p->invalid, 1u);
  atomic_fetch_add(&p->releases, 1u);
}
static int peer_policy_check(void *ctx,
    const crypto_tls_stream_peer_certificate_chain *chain, bool peer_is_server,
    crypto_tls_stream_security_profile profile) {
  peer_policy_probe *p = ctx;
  atomic_fetch_add(&p->calls, 1u);
  if (atomic_load(&p->references) < 2u || peer_is_server != p->peer_is_server ||
      profile != p->profile || chain->count == 0u ||
      chain->certificates[0].data == NULL || chain->certificates[0].size == 0u) {
    atomic_fetch_add(&p->invalid, 1u);
    return CRYPTO_TLS_STREAM_EIO;
  }
  return p->decision;
}
static crypto_tls_stream_peer_policy peer_policy_descriptor(peer_policy_probe *p) {
  return (crypto_tls_stream_peer_policy){.check = peer_policy_check, .retain = peer_policy_retain,
                               .release = peer_policy_release, .context = p};
}
static bool peer_policy_finished(peer_policy_probe *p, unsigned calls) {
  return atomic_load(&p->references) == 1u && atomic_load(&p->retains) == 1u &&
      atomic_load(&p->releases) == 1u && atomic_load(&p->calls) == calls &&
      atomic_load(&p->invalid) == 0u;
}
