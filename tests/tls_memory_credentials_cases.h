static size_t tls_memory_fixture(const char *path, const char *label, unsigned encoding,
    unsigned char *bytes, size_t capacity) {
  FILE *f = fopen(path, "rb");
  if (!f) return 0u;
  size_t size = 0u;
  bool ok;
  if (encoding == CRYPTO_TLS_ENCODING_PEM) {
    size = fread(bytes, 1u, capacity, f);
    ok = !ferror(f) && fgetc(f) == EOF && !ferror(f);
  } else ok = pem_read(f, label, bytes, &size, capacity) == 1;
  fclose(f);
  return ok ? size : 0u;
}

static void tls_memory_contexts(unsigned encoding, unsigned bad) {
  unsigned char ca[16384], cert[16384], key[16384];
  crypto_tls_data trust = {ca, tls_memory_fixture(CRYPTO_CLOSE_TEST_CA, "CERTIFICATE", encoding, ca, sizeof(ca)), encoding};
  crypto_tls_credentials credentials = {.size = sizeof(credentials),
      .certificate_chain = {cert, tls_memory_fixture(CRYPTO_CLOSE_TEST_SERVER_CERT, "CERTIFICATE", encoding, cert, sizeof(cert)), encoding},
      .private_key = {key, tls_memory_fixture(CRYPTO_CLOSE_TEST_SERVER_KEY, "PRIVATE KEY", encoding, key, sizeof(key)), encoding}};
  crypto_tls_stream_client_config client = {.size = sizeof(client), .ca_data = &trust};
  crypto_tls_stream_server_config server = {.size = sizeof(server), .credentials = &credentials};
  check(trust.size && credentials.certificate_chain.size && credentials.private_key.size);
  int expected = CRYPTO_TLS_STREAM_EIO;
  switch (bad) {
    case 1: server.cert_file = "absent.pem"; server.key_file = "absent.key"; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 2: credentials.private_key.data = NULL; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 3: credentials.private_key.size = SIZE_MAX; expected = CRYPTO_TLS_STREAM_ERANGE; break;
    case 4: credentials.certificate_chain = trust; break; /* Wrong private-key binding. */
    case 5: credentials.private_key.encoding = 99; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 6: credentials.private_key.size = 0u; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 7: credentials.encryption_key = credentials.private_key; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 8: key[credentials.private_key.size++] = '!'; break;
    case 9: cert[credentials.certificate_chain.size++] = '!'; break;
    case 10: credentials.private_key.size /= 2u; break;
    case 11: server.key_password = "not-accepted-for-memory"; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 12: credentials.size = 0u; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 13: client.ca_file = "absent-memory-trust.pem"; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 14: trust.data = NULL; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 15: trust.size = 0u; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 16: trust.encoding = 99; expected = CRYPTO_TLS_STREAM_EINVAL; break;
    case 17: trust.size = SIZE_MAX; expected = CRYPTO_TLS_STREAM_ERANGE; break;
    case 18: ca[trust.size++] = '!'; break;
    case 19: ca[0] = '!'; break;
    default: break;
  }
  if (bad >= 13u) {
    check_equal(crypto_tls_stream_client_context_create(&client, &stream_context[0]), expected);
    check_null(stream_context[0]);
  } else if (bad) {
    check_equal(crypto_tls_stream_server_context_create(&server, &stream_context[1]), expected);
    check_null(stream_context[1]);
  } else {
    check_equal(crypto_tls_stream_client_context_create(&client, &stream_context[0]), CRYPTO_TLS_STREAM_OK);
    check_equal(crypto_tls_stream_server_context_create(&server, &stream_context[1]), CRYPTO_TLS_STREAM_OK);
  }
  /* Context must not borrow descriptors, certificate bytes or key input. */
  memset(ca, 0xa5, sizeof(ca)); memset(cert, 0xa5, sizeof(cert)); memset(key, 0xa5, sizeof(key));
}
