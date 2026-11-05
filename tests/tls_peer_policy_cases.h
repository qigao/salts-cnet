#include "tls_peer_policy_probe.h"
#include "cnet_tls.h"

static int run_peer_policy_cases(void) {
  const char *label = "authenticated peer policy admission and lifetime";
  peer_policy_probe p;
  peer_policy_init(&p, true);
  cnet_tls_peer_policy policy = peer_policy_descriptor(&p);
  cnet_tls_client client = {0};
  cnet_tls_server server = {0};
  cnet_tls_context *first = NULL, *second = NULL;
  cnet_tls_client_config cfg = {.size = sizeof(cfg),
      .ca_file = CORE_TLS_TEST_P384_CA, .peer_policy = &policy};
  cnet_tls_server_config server_cfg = {.size = sizeof(server_cfg),
      .cert_file = CORE_TLS_TEST_P384_LEAF, .key_file = CORE_TLS_TEST_P384_KEY,
      .peer_policy = &policy};
  int result = 0;
  REQUIRE(cnet_tls_server_init(&server, &server_cfg) == SALTS_EINVAL);
  REQUIRE(server.impl == NULL && client.impl == NULL);
  for (unsigned missing = 0; missing < 3; ++missing) {
    policy = peer_policy_descriptor(&p);
    if (missing == 0) policy.check = NULL;
    if (missing == 1) policy.retain = NULL;
    if (missing == 2) policy.release = NULL;
    REQUIRE(cnet_tls_client_init(&client, &cfg) == SALTS_EINVAL);
    REQUIRE(server.impl == NULL && client.impl == NULL);
  }
  policy = peer_policy_descriptor(&p);
  cfg.ca_file = "this-test-trust-file-does-not-exist.pem";
  REQUIRE(cnet_tls_client_init(&client, &cfg) != SALTS_OK);
  REQUIRE(client.impl == NULL && atomic_load(&p.retains) == 0u && atomic_load(&p.releases) == 0u);
  cfg.ca_file = CORE_TLS_TEST_P384_CA;
  REQUIRE(cnet_tls_client_init(&client, &cfg) == SALTS_OK);
  memset(&policy, 0, sizeof(policy)); /* Context owns the copied descriptor. */
  first = cnet_tls_client_context(&client);
  cnet_tls_context_retain(first);
  second = first;
  cnet_tls_context_retain(second);
  REQUIRE(cnet_tls_client_destroy(&client) == SALTS_OK);
  REQUIRE(atomic_load(&p.releases) == 0u);
  cnet_tls_context_release(first); first = NULL;
  REQUIRE(atomic_load(&p.releases) == 0u);
  cnet_tls_context_release(second); second = NULL;
  REQUIRE(peer_policy_finished(&p, 0u));

  for (unsigned scenario = 0u; scenario < 5u; ++scenario) {
    peer_policy_init(&p, true);
    policy = peer_policy_descriptor(&p);
    p.decision = scenario == 1u ? CRYPTO_TLS_STREAM_EIO : scenario == 2u ? 1 : 0;
    const tls_case_options options = {
        .label = "real TLS peer admission",
        .ca_file = scenario == 3u ? CORE_TLS_TEST_P384_WRONG_CA : CORE_TLS_TEST_P384_CA,
        .verified_hostname = scenario == 4u ? "wrong.example" : "localhost",
        .expect_success = scenario == 0u,
        .client_peer_policy = &policy, .release_tls_context_early = true};
    REQUIRE(run_case(&options) == 0);
    REQUIRE(peer_policy_finished(&p, scenario < 3u ? 1u : 0u));
  }
cleanup:
  cnet_tls_context_release(first);
  cnet_tls_context_release(second);
  (void)cnet_tls_client_destroy(&client);
  (void)cnet_tls_server_destroy(&server);
  return result;
}

static int run_mutual_peer_policy_case(const tls_case_options *original,
                                      bool reject_client, bool reject_server) {
  const char *label = "CNet mTLS peer admission on both endpoints";
  peer_policy_probe client, server;
  peer_policy_init(&client, true);
  peer_policy_init(&server, false);
  client.profile = server.profile = CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13;
  client.decision = reject_client ? CRYPTO_TLS_STREAM_EIO : 0;
  server.decision = reject_server ? 1 : 0;
  cnet_tls_peer_policy cp = peer_policy_descriptor(&client);
  cnet_tls_peer_policy sp = peer_policy_descriptor(&server);
  tls_case_options options = *original;
  options.client_peer_policy = &cp;
  options.server_peer_policy = &sp;
  options.release_tls_context_early = true;
  int result = 0;
  REQUIRE(run_case(&options) == 0);
  REQUIRE(peer_policy_finished(&client, 1u));
  /* Client rejection can stop its Finished from reaching the server. */
  REQUIRE(peer_policy_finished(&server, reject_client ? atomic_load(&server.calls) : 1u));
  REQUIRE(atomic_load(&server.calls) <= 1u);
cleanup:
  return result;
}

