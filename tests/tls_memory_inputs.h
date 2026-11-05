/* Formal CNet fixture adapter: independent peers provide matching PEM/DER
 * files. Erase and release all source storage before any handshake progress. */
typedef struct tls_test_memory {
  unsigned char bytes[4][CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES];
  unsigned char passwords[2][32];
  cnet_tls_data ca;
  cnet_tls_credentials credentials;
} tls_test_memory;

static int tls_test_read(tls_test_memory *m, unsigned slot, const char *path,
    const char *part, cnet_tls_data *out) {
  const char *mode = getenv("SALTS_TEST_TLS_MEMORY");
  char name[2048];
  if (!path || snprintf(name, sizeof(name), "%s%s%s%s", path, part,
      slot >= 2u && getenv("SALTS_TEST_TLS_ENCRYPTED") ? ".encrypted" : "",
      strcmp(mode, "der") == 0 ? ".der" : "") >= (int)sizeof(name)) return SALTS_EINVAL;
  FILE *f = fopen(name, "rb");
  if (!f) return SALTS_EIO;
  size_t n = fread(m->bytes[slot], 1u, sizeof(m->bytes[slot]), f);
  bool valid = n && !ferror(f) && fgetc(f) == EOF && !ferror(f);
  fclose(f);
  if (!valid) return SALTS_EIO;
  *out = (cnet_tls_data){m->bytes[slot], n,
      strcmp(mode, "der") == 0 ? CRYPTO_TLS_ENCODING_DER : CRYPTO_TLS_ENCODING_PEM};
  return SALTS_OK;
}
static void tls_test_memory_free(tls_test_memory *m) {
  if (m) {
    volatile unsigned char *p = (volatile unsigned char *)m;
    for (size_t i = 0; i < sizeof(*m); ++i) p[i] = 0u;
    free(m);
  }
}
static int tls_test_prepare(tls_test_memory *m, const char *ca, const char *cert,
    const char *key, bool tlcp) {
  int status = SALTS_OK;
  m->credentials.size = sizeof(m->credentials);
  if (ca) status = tls_test_read(m, 0u, ca, "", &m->ca);
  if (status == SALTS_OK && cert) status = tls_test_read(m, 1u, cert, "", &m->credentials.certificate_chain);
  if (status == SALTS_OK && key) status = tls_test_read(m, 2u, key, tlcp ? ".sign" : "", &m->credentials.private_key);
  if (status == SALTS_OK && tlcp) status = tls_test_read(m, 3u, key, ".enc", &m->credentials.encryption_key);
  if (getenv("SALTS_TEST_TLS_ENCRYPTED")) {
    const char sign_password[] = "memory\0sign", enc_password[] = "memory\0encryption";
    memcpy(m->passwords[0], sign_password, sizeof(sign_password) - 1u);
    memcpy(m->passwords[1], enc_password, sizeof(enc_password) - 1u);
    m->credentials.private_key_password = (crypto_tls_password){m->passwords[0], sizeof(sign_password) - 1u};
    if (tlcp) m->credentials.encryption_key_password =
        (crypto_tls_password){m->passwords[1], sizeof(enc_password) - 1u};
  }
  return status;
}
static int tls_test_server_init(cnet_tls_server *server, const cnet_tls_server_config *config) {
  if (!getenv("SALTS_TEST_TLS_MEMORY")) return cnet_tls_server_init(server, config);
  tls_test_memory *m = calloc(1u, sizeof(*m));
  if (!m) return SALTS_ENOMEM;
  int status = tls_test_prepare(m, config->ca_file, config->cert_file, config->key_file,
      config->security_profile == CNET_TLS_SECURITY_PROFILE_TLCP11);
  cnet_tls_server_config memory = *config;
  memory.ca_data = config->ca_file ? &m->ca : NULL;
  memory.credentials = &m->credentials;
  memory.ca_file = memory.cert_file = memory.key_file = NULL;
  if (status == SALTS_OK) status = cnet_tls_server_init(server, &memory);
  tls_test_memory_free(m);
  return status;
}
static int tls_test_connect(cnet_client *client, const cnet_connect_options *options,
    cnet_connection *out) {
  if (!getenv("SALTS_TEST_TLS_MEMORY") || !options->tls) return cnet_connect(client, options, out);
  const cnet_tls_client_config *config = options->tls;
  tls_test_memory *m = calloc(1u, sizeof(*m));
  if (!m) return SALTS_ENOMEM;
  int status = tls_test_prepare(m, config->ca_file, config->cert_file, config->key_file, false);
  cnet_tls_client_config memory = *config;
  memory.ca_data = config->ca_file ? &m->ca : NULL;
  memory.credentials = config->cert_file ? &m->credentials : NULL;
  memory.ca_file = memory.cert_file = memory.key_file = NULL;
  cnet_connect_options copied = *options;
  copied.tls = &memory;
  if (status == SALTS_OK) status = cnet_connect(client, &copied, out);
  tls_test_memory_free(m);
  return status;
}
