/* Real CNet owner only: no direct Crypto/GmSSL linkage in this executable. */
static size_t crl_policy_read_file(const char *path, uint8_t *buffer, size_t capacity) {
  FILE *file = fopen(path, "rb");
  if (file == NULL) return 0u;
  size_t size = fread(buffer, 1u, capacity, file);
  bool valid = !ferror(file) && fgetc(file) == EOF && !ferror(file);
  fclose(file);
  return valid ? size : 0u;
}

static int run_cnet_crl_policy_case(char **argv) {
  const char *label = "CNet owned direct-issuer SM2 CRL snapshot";
  uint8_t issuer[4096], crl[65536];
  char certificate_id[] = "1234567812345678", crl_id[] = "1234567812345678";
  const bool peer_is_server = strcmp(argv[8], "client") == 0;
  const bool accept = strcmp(argv[12], "accept") == 0;
  cnet_tls_peer_policy policy = {0};
  cnet_tls_client client = {0};
  cnet_tls_server server = {0};
  peer_policy_probe rejected;
  peer_policy_init(&rejected, peer_is_server);
  int result = 0;
  cnet_tls_sm2_crl_config config = {.size = sizeof(config),
      .issuer_certificate = issuer, .issuer_certificate_size = crl_policy_read_file(argv[9], issuer, sizeof(issuer)),
      .crl = crl, .crl_size = crl_policy_read_file(argv[10], crl, sizeof(crl)),
      .certificate_signing_identity = certificate_id, .certificate_signing_identity_size = 16u,
      .crl_signing_identity = crl_id, .crl_signing_identity_size = 16u,
      .minimum_crl_number = 42u, .maximum_age_seconds = 3600u,
      .peer_is_server = peer_is_server};
  REQUIRE(config.issuer_certificate_size != 0u && config.crl_size != 0u);
  if (strcmp(argv[13], "wrong-cert-id") == 0) certificate_id[0] = '!';
  if (strcmp(argv[13], "wrong-crl-id") == 0) crl_id[0] = '!';
  if (strcmp(argv[13], "wrong-role") == 0) config.peer_is_server = !peer_is_server;
  if (strcmp(argv[13], "factory-reject") == 0 || strcmp(argv[13], "wrong-crl-id") == 0) {
    REQUIRE(cnet_tls_sm2_crl_peer_policy_create(&config, &policy) == SALTS_ECONNABORTED);
    REQUIRE(policy.check == NULL && policy.retain == NULL && policy.release == NULL && policy.context == NULL);
    goto cleanup;
  }
  /* Admission failures must clear output and never dereference oversized spans. */
  for (unsigned invalid = 0u; invalid < 8u; ++invalid) {
    cnet_tls_sm2_crl_config bad = config;
    if (invalid == 0u) bad.size = 0u;
    if (invalid == 1u) bad.issuer_certificate_size = 4097u;
    if (invalid == 2u) bad.crl_size = 65537u;
    if (invalid == 3u) bad.maximum_age_seconds = 0u;
    if (invalid == 4u) bad.certificate_signing_identity_size = 8192u;
    if (invalid == 5u) bad.crl_signing_identity_size = 0u;
    if (invalid == 6u) bad.crl = NULL;
    if (invalid == 7u) bad.issuer_certificate = NULL;
    policy = peer_policy_descriptor(&rejected); /* Nonzero descriptor, never retained. */
    REQUIRE(cnet_tls_sm2_crl_peer_policy_create(&bad, &policy) == SALTS_EINVAL);
    REQUIRE(policy.check == NULL && policy.retain == NULL && policy.release == NULL && policy.context == NULL);
  }
  REQUIRE(cnet_tls_sm2_crl_peer_policy_create(&config, &policy) == SALTS_OK);
  REQUIRE(policy.check != NULL && policy.retain != NULL && policy.release != NULL && policy.context != NULL);
  REQUIRE(policy.supported_profiles == CRYPTO_TLS_PEER_POLICY_SHANGMI_TLS13);
  REQUIRE(policy.supported_peer_roles == (config.peer_is_server ? CRYPTO_TLS_PEER_POLICY_SERVER : CRYPTO_TLS_PEER_POLICY_CLIENT));
  if (strcmp(argv[13], "wrong-role") == 0) {
    cnet_tls_client_config cc = {.size = sizeof(cc), .ca_file = "absent-policy-trust.pem",
        .security_profile = CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13, .peer_policy = &policy};
    cnet_tls_server_config sc = {.size = sizeof(sc), .ca_file = "absent-policy-trust.pem",
        .cert_file = "absent-policy-cert.pem", .key_file = "absent-policy-key.pem",
        .client_auth = CNET_TLS_CLIENT_AUTH_REQUIRED,
        .security_profile = CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13, .peer_policy = &policy};
    REQUIRE((peer_is_server ? cnet_tls_client_init(&client, &cc) : cnet_tls_server_init(&server, &sc)) == SALTS_ENOTSUP);
    REQUIRE(client.impl == NULL && server.impl == NULL);
    goto cleanup;
  }
  /* Creation consumes all data synchronously; corrupt the original buffers. */
  memset(issuer, 0, sizeof(issuer)); memset(crl, 0, sizeof(crl));
  memset(certificate_id, 0, sizeof(certificate_id)); memset(crl_id, 0, sizeof(crl_id));
  crypto_tls_stream_peer_certificate_chain chain = {0};
  REQUIRE((policy.check)(policy.context, &chain, peer_is_server, CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD) != 0);
  REQUIRE((policy.check)(policy.context, &chain, peer_is_server, CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11) != 0);
  REQUIRE((policy.check)(policy.context, &chain, peer_is_server, CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13) != 0);
  chain.count = 3u;
  REQUIRE((policy.check)(policy.context, &chain, peer_is_server, CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13) != 0);
  tls_case_options options = {.label = label, .ca_file = argv[2], .server_ca_file = argv[3],
      .server_cert_file = argv[4], .server_key_file = argv[5],
      .client_cert_file = argv[6], .client_key_file = argv[7],
      .verified_hostname = strcmp(argv[13], "wrong-name") == 0 ? "127.0.0.2" : "localhost",
      .expect_success = accept, .expect_server_rejection = !accept && !peer_is_server,
      .security_profile = CNET_TLS_SECURITY_PROFILE_SHANGMI_TLS13,
      .client_peer_policy = peer_is_server ? &policy : NULL,
      .server_peer_policy = peer_is_server ? NULL : &policy,
      .release_peer_policy = &policy, .release_tls_context_early = true};
  REQUIRE(run_case(&options) == 0);
  REQUIRE(policy.context == NULL); /* Caller ref released before handshake progress. */
cleanup:
  (void)cnet_tls_client_destroy(&client);
  (void)cnet_tls_server_destroy(&server);
  if (policy.release != NULL) policy.release(policy.context);
  return result;
}

typedef struct tlcp_crl_probe {
  cnet_tls_peer_policy actual;
  atomic_uint references, calls, invalid;
  size_t expected_certificates;
} tlcp_crl_probe;

static void tlcp_crl_probe_retain(void *context) {
  tlcp_crl_probe *p = context;
  p->actual.retain(p->actual.context);
  atomic_fetch_add(&p->references, 1u);
}
static void tlcp_crl_probe_release(void *context) {
  tlcp_crl_probe *p = context;
  p->actual.release(p->actual.context);
  atomic_fetch_sub(&p->references, 1u);
}
static int tlcp_crl_probe_check(void *context,
    const crypto_tls_stream_peer_certificate_chain *chain, bool peer_is_server,
    crypto_tls_stream_security_profile profile) {
  tlcp_crl_probe *p = context;
  atomic_fetch_add(&p->calls, 1u);
  if (!peer_is_server || profile != CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 ||
      chain->count != p->expected_certificates) {
    atomic_fetch_add(&p->invalid, 1u);
    return SALTS_ECONNABORTED;
  }
  int status = (p->actual.check)(p->actual.context, chain, peer_is_server, profile);
  if (status != 0) return status;
  /* Exercise structural and profile gates with authenticated real DER views.
   * Inspection does not publish CONNECTED or transfer ownership of these views. */
  crypto_tls_stream_peer_certificate_chain bad = *chain;
  bad.certificates[1] = bad.certificates[0];
  if ((p->actual.check)(p->actual.context, &bad, true, profile) == 0) goto invalid;
  bad = *chain; bad.count = 1u;
  if ((p->actual.check)(p->actual.context, &bad, true, profile) == 0) goto invalid;
  bad = *chain; bad.count = 4u;
  if ((p->actual.check)(p->actual.context, &bad, true, profile) == 0) goto invalid;
  bad = *chain; bad.count = 3u; bad.certificates[2] = bad.certificates[0];
  if ((p->actual.check)(p->actual.context, &bad, true, profile) == 0) goto invalid;
  bad = *chain; bad.certificates[1].data = NULL;
  if ((p->actual.check)(p->actual.context, &bad, true, profile) == 0) goto invalid;
  if ((p->actual.check)(p->actual.context, chain, false, profile) == 0 ||
      (p->actual.check)(p->actual.context, chain, true, CRYPTO_TLS_STREAM_SECURITY_PROFILE_SHANGMI_TLS13) == 0 ||
      (p->actual.check)(p->actual.context, chain, true, CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD) == 0) goto invalid;
  return 0;
invalid:
  atomic_fetch_add(&p->invalid, 1u);
  return SALTS_ECONNABORTED;
}

static int run_cnet_tlcp_crl_policy_case(char **argv) {
  const char *label = "CNet TLCP dual-certificate CRL admission";
  uint8_t issuer[4096], crl[65536];
  char certificate_id[] = "1234567812345678", crl_id[] = "1234567812345678";
  cnet_tls_peer_policy policy = {0};
  cnet_tls_client client = {0};
  tlcp_crl_probe probe = {0};
  atomic_init(&probe.references, 0u);
  atomic_init(&probe.calls, 0u);
  atomic_init(&probe.invalid, 0u);
  probe.expected_certificates = strcmp(argv[8], "with-issuer") == 0 ? 3u : 2u;
  int result = 0;
  cnet_tls_sm2_crl_config config = {.size = sizeof(config),
      .issuer_certificate = issuer, .issuer_certificate_size = crl_policy_read_file(argv[5], issuer, sizeof(issuer)),
      .crl = crl, .crl_size = crl_policy_read_file(argv[6], crl, sizeof(crl)),
      .certificate_signing_identity = certificate_id, .certificate_signing_identity_size = 16u,
      .crl_signing_identity = crl_id, .crl_signing_identity_size = 16u,
      .minimum_crl_number = 42u, .maximum_age_seconds = 3600u, .peer_is_server = true};
  REQUIRE(config.issuer_certificate_size != 0u && config.crl_size != 0u);
  if (strcmp(argv[8], "unsupported-client-auth") == 0) {
    config.peer_is_server = false;
    REQUIRE(cnet_tlcp_sm2_crl_peer_policy_create(&config, &policy) == SALTS_ENOTSUP);
    REQUIRE(policy.check == NULL && policy.release == NULL && policy.retain == NULL && policy.context == NULL);
    goto cleanup;
  }
  if (strcmp(argv[8], "factory-reject") == 0) {
    REQUIRE(cnet_tlcp_sm2_crl_peer_policy_create(&config, &policy) == SALTS_ECONNABORTED);
    REQUIRE(policy.check == NULL && policy.release == NULL && policy.retain == NULL && policy.context == NULL);
    goto cleanup;
  }
  if (strcmp(argv[8], "wrong-cert-id") == 0) certificate_id[0] = '!';
  if (strcmp(argv[8], "wrong-profile") == 0)
    REQUIRE(cnet_tls_sm2_crl_peer_policy_create(&config, &policy) == SALTS_OK);
  else
    REQUIRE(cnet_tlcp_sm2_crl_peer_policy_create(&config, &policy) == SALTS_OK);
  REQUIRE(policy.supported_profiles == (strcmp(argv[8], "wrong-profile") == 0 ?
      CRYPTO_TLS_PEER_POLICY_SHANGMI_TLS13 : CRYPTO_TLS_PEER_POLICY_TLCP11));
  REQUIRE(policy.supported_peer_roles == CRYPTO_TLS_PEER_POLICY_SERVER);
  probe.actual = policy;
  atomic_store(&probe.references, 1u);
  policy = (cnet_tls_peer_policy){.check = tlcp_crl_probe_check, .retain = tlcp_crl_probe_retain,
      .release = tlcp_crl_probe_release, .context = &probe,
      .supported_profiles = probe.actual.supported_profiles,
      .supported_peer_roles = probe.actual.supported_peer_roles};
  if (strcmp(argv[8], "wrong-profile") == 0) {
    cnet_tls_client_config cc = {.size = sizeof(cc), .ca_file = "absent-policy-trust.pem",
        .security_profile = CNET_TLS_SECURITY_PROFILE_TLCP11, .peer_policy = &policy};
    REQUIRE(cnet_tls_client_init(&client, &cc) == SALTS_ENOTSUP);
    REQUIRE(client.impl == NULL && atomic_load(&probe.references) == 1u && atomic_load(&probe.calls) == 0u);
    policy.release(policy.context);
    memset(&policy, 0, sizeof(policy));
    REQUIRE(atomic_load(&probe.references) == 0u);
    goto cleanup;
  }
  /* No native or policy engine may depend on these caller buffers afterward. */
  memset(issuer, 0, sizeof(issuer)); memset(crl, 0, sizeof(crl));
  memset(certificate_id, 0, sizeof(certificate_id)); memset(crl_id, 0, sizeof(crl_id));
  REQUIRE(run_python_ssl_server(argv[2], "tlcp", argv[3], argv[4],
      strcmp(argv[7], "accept") == 0, NULL, NULL, NULL, &policy) == 0);
  REQUIRE(policy.context == NULL);
  REQUIRE(atomic_load(&probe.references) == 0u && atomic_load(&probe.invalid) == 0u);
  REQUIRE(atomic_load(&probe.calls) == (strcmp(argv[3], "127.0.0.2") == 0 ? 0u : 1u));
cleanup:
  (void)cnet_tls_client_destroy(&client);
  if (policy.release != NULL) policy.release(policy.context);
  return result;
}
