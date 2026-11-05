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
  if (policy.release != NULL) policy.release(policy.context);
  return result;
}
