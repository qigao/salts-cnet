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
  for (unsigned invalid = 0u; invalid < 4u; ++invalid) {
    cnet_tls_client_config cache = {.size = sizeof(cache), .ca_file = "absent-session-ca.pem",
        .session_cache_capacity = invalid == 0u ? 17u : 1u,
        .security_profile = invalid == 3u ? CNET_TLS_SECURITY_PROFILE_TLCP11 : CNET_TLS_SECURITY_PROFILE_STANDARD,
        .minimum_version = invalid == 2u ? CNET_TLS_PROTOCOL_VERSION_1_2 : 0,
        .maximum_version = invalid == 2u ? CNET_TLS_PROTOCOL_VERSION_1_2 : 0};
    REQUIRE(cnet_tls_client_init(&client,&cache) == (invalid == 0u ? SALTS_EINVAL : SALTS_ENOTSUP));
    REQUIRE(client.impl == NULL);
  }
  REQUIRE(cnet_tls_server_init(&server, &server_cfg) == SALTS_EINVAL);
  REQUIRE(server.impl == NULL && client.impl == NULL);
  for (unsigned bad = 0u; bad < 5u; ++bad) {
    cnet_tls_client_config cc = {.size = sizeof(cc), .ca_file = "absent-version-ca.pem"};
    cnet_tls_server_config sc = {.size = sizeof(sc), .cert_file = "absent-version-cert.pem", .key_file = "absent-version-key.pem"};
    cc.minimum_version = bad == 0u ? 99 : bad == 1u ? 13 : 12;
    cc.maximum_version = bad == 2u ? 99 : 12;
    cc.security_profile = bad == 3u ? CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13 :
        bad == 4u ? CNET_TLS_SECURITY_PROFILE_TLCP11 : CNET_TLS_SECURITY_PROFILE_STANDARD;
    sc.minimum_version = cc.minimum_version; sc.maximum_version = cc.maximum_version;
    sc.security_profile = cc.security_profile;
    const int expected = bad < 3u ? SALTS_EINVAL : SALTS_ENOTSUP;
    REQUIRE(cnet_tls_client_init(&client, &cc) == expected);
    REQUIRE(cnet_tls_server_init(&server, &sc) == expected);
    REQUIRE(client.impl == NULL && server.impl == NULL);
  }
  for (unsigned missing = 0; missing < 3; ++missing) {
    policy = peer_policy_descriptor(&p);
    if (missing == 0) policy.check = NULL;
    if (missing == 1) policy.retain = NULL;
    if (missing == 2) policy.release = NULL;
    REQUIRE(cnet_tls_client_init(&client, &cfg) == SALTS_EINVAL);
    REQUIRE(server.impl == NULL && client.impl == NULL);
  }
  policy = peer_policy_descriptor(&p);
  /* Unsupported declarations fail before loading deliberately absent files,
   * without acquiring a policy reference or opening any connection. */
  for (unsigned local_server = 0u; local_server < 2u; ++local_server) {
    for (unsigned profile = 0u; profile < (local_server ? 2u : 3u); ++profile) {
      for (unsigned invalid = 0u; invalid < 4u; ++invalid) {
        policy = peer_policy_descriptor(&p);
        if (invalid == 0u) policy.supported_profiles = 7u ^ (1u << profile);
        if (invalid == 1u) policy.supported_peer_roles = local_server ?
            CRYPTO_TLS_PEER_POLICY_SERVER : CRYPTO_TLS_PEER_POLICY_CLIENT;
        if (invalid == 2u) policy.supported_profiles = 8u;
        if (invalid == 3u) policy.supported_peer_roles = 4u;
        cnet_tls_client_config bad_client = {.size = sizeof(bad_client),
            .ca_file = "absent-policy-trust.pem", .security_profile = (cnet_tls_security_profile)profile,
            .peer_policy = &policy};
        cnet_tls_server_config bad_server = {.size = sizeof(bad_server),
            .ca_file = "absent-policy-trust.pem", .cert_file = "absent-policy-cert.pem",
            .key_file = "absent-policy-key.pem", .client_auth = CNET_TLS_CLIENT_AUTH_REQUIRED,
            .security_profile = (cnet_tls_security_profile)profile, .peer_policy = &policy};
        int status = local_server ? cnet_tls_server_init(&server, &bad_server) :
                                   cnet_tls_client_init(&client, &bad_client);
        REQUIRE(status == (invalid < 2u ? SALTS_ENOTSUP : SALTS_EINVAL));
        REQUIRE(client.impl == NULL && server.impl == NULL);
        REQUIRE(atomic_load(&p.retains) == 0u && atomic_load(&p.releases) == 0u &&
                atomic_load(&p.calls) == 0u && atomic_load(&p.references) == 1u);
      }
    }
  }
  policy = peer_policy_descriptor(&p);
  cfg.ca_file = "this-test-trust-file-does-not-exist.pem";
  for (unsigned invalid = 0u; invalid < 5u; ++invalid) {
    int64_t value = invalid == 0u ? -1 : invalid == 1u ? INT64_MIN :
        invalid == 2u ? INT64_MAX : invalid == 3u ? INT64_C(253402300800) : 0;
    cnet_tls_client_config bad_client = {.size = sizeof(bad_client),
        .ca_file = cfg.ca_file, .verification_time = &value};
    cnet_tls_server_config bad_server = {.size = sizeof(bad_server),
        .cert_file = "absent-time-cert.pem", .key_file = "absent-time-key.pem",
        .ca_file = cfg.ca_file, .verification_time = &value,
        .client_auth = invalid < 4u ? CNET_TLS_CLIENT_AUTH_REQUIRED : CNET_TLS_CLIENT_AUTH_NONE};
    if (invalid < 4u) REQUIRE(cnet_tls_client_init(&client, &bad_client) == SALTS_EINVAL);
    REQUIRE(cnet_tls_server_init(&server, &bad_server) == SALTS_EINVAL);
    REQUIRE(client.impl == NULL && server.impl == NULL);
    REQUIRE(atomic_load(&p.retains) == 0u && atomic_load(&p.calls) == 0u);
  }
  for (unsigned invalid = 0u; invalid < 3u; ++invalid) {
    uint32_t depth = invalid == 0u ? 6u : invalid == 1u ? UINT32_MAX : 1u;
    cnet_tls_client_config bad_client = {.size = sizeof(bad_client),
        .ca_file = cfg.ca_file, .verification_depth = depth};
    cnet_tls_server_config bad_server = {.size = sizeof(bad_server),
        .cert_file = "absent-depth-cert.pem", .key_file = "absent-depth-key.pem",
        .ca_file = invalid < 2u ? cfg.ca_file : NULL,
        .client_auth = invalid < 2u ? CNET_TLS_CLIENT_AUTH_REQUIRED : CNET_TLS_CLIENT_AUTH_NONE,
        .verification_depth = depth};
    if (invalid < 2u) REQUIRE(cnet_tls_client_init(&client, &bad_client) == SALTS_EINVAL);
    REQUIRE(cnet_tls_server_init(&server, &bad_server) == SALTS_EINVAL);
    REQUIRE(client.impl == NULL && server.impl == NULL);
  }
  for (unsigned invalid = 0u; invalid < 2u; ++invalid) {
    cnet_tls_security_profile profile = invalid ? CNET_TLS_SECURITY_PROFILE_TLCP11 : CNET_TLS_SECURITY_PROFILE_STANDARD;
    cnet_tls_client_config bad_client = {.size = sizeof(bad_client),
        .ca_file = cfg.ca_file, .security_profile = profile, .peer_key_update_limit = 2u};
    cnet_tls_server_config bad_server = {.size = sizeof(bad_server),
        .cert_file = "absent-update-cert.pem", .key_file = "absent-update-key.pem",
        .security_profile = profile, .peer_key_update_limit = 2u};
    REQUIRE(cnet_tls_client_init(&client, &bad_client) == SALTS_ENOTSUP);
    REQUIRE(cnet_tls_server_init(&server, &bad_server) == SALTS_ENOTSUP);
    REQUIRE(client.impl == NULL && server.impl == NULL);
  }
  for (unsigned invalid = 0u; invalid < 3u; ++invalid) {
    cnet_tls_security_profile profile = invalid == 0u ? CNET_TLS_SECURITY_PROFILE_STANDARD :
        invalid == 1u ? CNET_TLS_SECURITY_PROFILE_TLCP11 : CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13;
    uint32_t limit = invalid < 2u ? 1u : CNET_TLS_KEY_UPDATE_RECORD_LIMIT_MAX + 1u;
    cnet_tls_client_config bad_client = {.size = sizeof(bad_client),
        .ca_file = cfg.ca_file, .security_profile = profile, .key_update_record_limit = limit};
    cnet_tls_server_config bad_server = {.size = sizeof(bad_server),
        .cert_file = "absent-rotation-cert.pem", .key_file = "absent-rotation-key.pem",
        .security_profile = profile, .key_update_record_limit = limit};
    REQUIRE(cnet_tls_client_init(&client, &bad_client) == (invalid < 2u ? SALTS_ENOTSUP : SALTS_EINVAL));
    REQUIRE(cnet_tls_server_init(&server, &bad_server) == (invalid < 2u ? SALTS_ENOTSUP : SALTS_EINVAL));
    REQUIRE(client.impl == NULL && server.impl == NULL);
  }
  for (unsigned invalid = 0u; invalid < 4u; ++invalid) {
    const cnet_tls_security_profile profile = invalid == 0u ? CNET_TLS_SECURITY_PROFILE_STANDARD :
        invalid == 1u ? CNET_TLS_SECURITY_PROFILE_TLCP11 : CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13;
    const uint64_t limit = invalid < 2u ? UINT64_C(1) :
        invalid == 2u ? CNET_TLS_KEY_UPDATE_BYTE_LIMIT_MAX + 1u : UINT64_MAX;
    cnet_tls_client_config bad_client = {.size = sizeof(bad_client),
        .ca_file = "absent-byte-limit-ca.pem", .peer_policy = &policy,
        .security_profile = profile, .key_update_byte_limit = limit};
    cnet_tls_server_config bad_server = {.size = sizeof(bad_server),
        .cert_file = "absent-byte-limit-cert.pem", .key_file = "absent-byte-limit-key.pem",
        .ca_file = "absent-byte-limit-ca.pem", .client_auth = CNET_TLS_CLIENT_AUTH_REQUIRED,
        .peer_policy = &policy, .security_profile = profile, .key_update_byte_limit = limit};
    const int expected = invalid < 2u ? SALTS_ENOTSUP : SALTS_EINVAL;
    REQUIRE(cnet_tls_client_init(&client, &bad_client) == expected);
    REQUIRE(cnet_tls_server_init(&server, &bad_server) == expected);
    REQUIRE(client.impl == NULL && server.impl == NULL);
    REQUIRE(atomic_load(&p.retains) == 0u && atomic_load(&p.calls) == 0u);
  }
  for (unsigned unsupported = 0u; unsupported < 2u; ++unsupported) {
    const cnet_tls_security_profile profile = unsupported ? CNET_TLS_SECURITY_PROFILE_TLCP11 : CNET_TLS_SECURITY_PROFILE_STANDARD;
    cnet_tls_client_config bad_client = {.size = sizeof(bad_client),
        .ca_file = "absent-interval-ca.pem", .peer_policy = &policy,
        .security_profile = profile, .key_update_interval_ms = UINT32_MAX};
    cnet_tls_server_config bad_server = {.size = sizeof(bad_server),
        .cert_file = "absent-interval-cert.pem", .key_file = "absent-interval-key.pem",
        .ca_file = "absent-interval-ca.pem", .client_auth = CNET_TLS_CLIENT_AUTH_REQUIRED,
        .peer_policy = &policy, .security_profile = profile, .key_update_interval_ms = 1u};
    REQUIRE(cnet_tls_client_init(&client, &bad_client) == SALTS_ENOTSUP);
    REQUIRE(cnet_tls_server_init(&server, &bad_server) == SALTS_ENOTSUP);
    REQUIRE(client.impl == NULL && server.impl == NULL);
    REQUIRE(atomic_load(&p.retains) == 0u && atomic_load(&p.calls) == 0u);
  }
  for (unsigned profile = 0u; profile < 2u; ++profile) {
    for (unsigned mode = 0u; mode < 3u; ++mode) {
      cnet_tls_security_profile selected = profile ? CNET_TLS_SECURITY_PROFILE_TLCP11 : CNET_TLS_SECURITY_PROFILE_STANDARD;
      cnet_tls_client_config cc = {.size = sizeof(cc), .ca_file = "absent-peer-spacing-ca.pem", .peer_policy = &policy,
          .security_profile = selected, .peer_key_update_min_interval_ms = mode != 1u ? UINT32_MAX : 0u,
          .peer_key_update_min_bytes = mode != 0u ? UINT32_MAX : 0u};
      cnet_tls_server_config sc = {.size = sizeof(sc), .cert_file = "absent-peer-spacing-cert.pem",
          .key_file = "absent-peer-spacing-key.pem", .ca_file = cc.ca_file, .peer_policy = &policy,
          .client_auth = CNET_TLS_CLIENT_AUTH_REQUIRED, .security_profile = selected,
          .peer_key_update_min_interval_ms = cc.peer_key_update_min_interval_ms,
          .peer_key_update_min_bytes = cc.peer_key_update_min_bytes};
      REQUIRE(cnet_tls_client_init(&client, &cc) == SALTS_ENOTSUP);
      REQUIRE(cnet_tls_server_init(&server, &sc) == SALTS_ENOTSUP);
      REQUIRE(client.impl == NULL && server.impl == NULL);
      REQUIRE(atomic_load(&p.retains) == 0u && atomic_load(&p.calls) == 0u && atomic_load(&p.releases) == 0u);
    }
  }
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
    if (scenario == 0u) {
      policy.supported_profiles = CRYPTO_TLS_PEER_POLICY_STANDARD | CRYPTO_TLS_PEER_POLICY_SHANGMI_TLS13;
      policy.supported_peer_roles = CRYPTO_TLS_PEER_POLICY_CLIENT | CRYPTO_TLS_PEER_POLICY_SERVER;
    }
    p.decision = scenario == 1u ? CRYPTO_TLS_STREAM_EIO : scenario == 2u ? 1 : 0;
    const tls_case_options options = {
        .label = "real TLS peer admission",
        .ca_file = scenario == 3u ? CORE_TLS_TEST_P384_WRONG_CA : CORE_TLS_TEST_P384_CA,
        .verified_hostname = scenario == 4u ? "wrong.example" : "localhost",
        .expect_success = scenario == 0u,
        .expected_failure = scenario == 0u ? CRYPTO_TLS_FAILURE_NONE : scenario < 3u ? CRYPTO_TLS_FAILURE_PEER_POLICY :
            scenario == 3u ? CRYPTO_TLS_FAILURE_TRUST_ANCHOR : CRYPTO_TLS_FAILURE_NONE,
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
  cp.supported_profiles = sp.supported_profiles = CRYPTO_TLS_PEER_POLICY_SHANGMI_TLS13;
  cp.supported_peer_roles = CRYPTO_TLS_PEER_POLICY_SERVER;
  sp.supported_peer_roles = CRYPTO_TLS_PEER_POLICY_CLIENT;
  tls_case_options options = *original;
  options.client_peer_policy = &cp;
  options.server_peer_policy = &sp;
  options.release_tls_context_early = true;
  if (reject_client || reject_server) options.expected_failure = CRYPTO_TLS_FAILURE_PEER_POLICY;
  int result = 0;
  REQUIRE(run_case(&options) == 0);
  REQUIRE(peer_policy_finished(&client, 1u));
  /* Client rejection can stop its Finished from reaching the server. */
  REQUIRE(peer_policy_finished(&server, reject_client ? atomic_load(&server.calls) : 1u));
  REQUIRE(atomic_load(&server.calls) <= 1u);
cleanup:
  return result;
}
