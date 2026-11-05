static int run_server_identity_cases(void) {
  const char *label = "immutable server identity set";
  cnet_tls_server server = {0};
  int result = 0;
  for (unsigned bad = 0u; bad < 12u; ++bad) {
    cnet_tls_server_identity ids[2] = {
        {sizeof(ids[0]), "missing-first.pem", "missing-first-key.pem", NULL, NULL},
        {sizeof(ids[0]), "missing-second.pem", "missing-second-key.pem", NULL, NULL}};
    cnet_tls_credentials memory = {.size = sizeof(memory)};
    cnet_tls_server_config cfg = {.size = sizeof(cfg), .identities = ids, .identity_count = 2u};
    switch (bad) {
      case 0: cfg.identities = NULL; break;
      case 1: cfg.identity_count = 0u; break;
      case 2: cfg.identity_count = 5u; break;
      case 3: cfg.identity_count = SIZE_MAX; break;
      case 4: cfg.cert_file = "conflict.pem"; break;
      case 5: cfg.credentials = &memory; break;
      case 6: ids[1].size--; break;
      case 7: ids[1].key_file = NULL; break;
      case 8: ids[1].cert_file = ""; break;
      case 9: ids[1].credentials = &memory; break;
      case 10: ids[1].cert_file = ids[1].key_file = NULL; ids[1].credentials = &memory; break;
      case 11: cfg.key_password = "conflict"; break;
    }
    REQUIRE(cnet_tls_server_init(&server, &cfg) == SALTS_EINVAL);
    REQUIRE(server.impl == NULL);
  }
  cnet_tls_server_identity ids[4];
  for (unsigned i = 0u; i < 4u; ++i)
    ids[i] = (cnet_tls_server_identity){sizeof(ids[i]), CORE_TLS_TEST_P384_LEAF,
        CORE_TLS_TEST_P384_KEY, NULL, NULL};
  cnet_tls_server_config cfg = {.size = sizeof(cfg), .identities = ids, .identity_count = 4u};
  REQUIRE(cnet_tls_server_init(&server, &cfg) == SALTS_OK);
  REQUIRE(cnet_tls_server_destroy(&server) == SALTS_OK);
  /* A later load failure must not publish the valid first identity. */
  ids[3].key_file = "absent-fourth-key.pem";
  REQUIRE(cnet_tls_server_init(&server, &cfg) == SALTS_EIO);
  REQUIRE(server.impl == NULL);
cleanup:
  (void)cnet_tls_server_destroy(&server);
  return result;
}
