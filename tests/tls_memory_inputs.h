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
  const char *prf = getenv("SALTS_TEST_TLS_PBKDF2");
  const char *prf_suffix = "";
  if (prf) {
    if (!getenv("SALTS_TEST_TLS_ENCRYPTED")) return SALTS_EINVAL;
    if (strcmp(prf, "sha384") == 0) prf_suffix = ".sha384";
    else if (strcmp(prf, "sha512") == 0) prf_suffix = ".sha512";
    else return SALTS_EINVAL;
  }
  char name[2048];
  if (!path || snprintf(name, sizeof(name), "%s%s%s%s%s", path, part,
      slot >= 2u && getenv("SALTS_TEST_TLS_ENCRYPTED") ?
          (strcmp(getenv("SALTS_TEST_TLS_ENCRYPTED"), "aes") == 0 ? ".aes" :
           strcmp(getenv("SALTS_TEST_TLS_ENCRYPTED"), "aes128") == 0 ? ".aes128" :
           strcmp(getenv("SALTS_TEST_TLS_ENCRYPTED"), "aes192") == 0 ? ".aes192" : ".encrypted") : "",
      slot >= 2u ? prf_suffix : "",
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
    m->credentials.private_key_password = (crypto_tls_password){m->passwords[0],
        getenv("SALTS_TEST_TLS_EMPTY_PASSWORD") ? 0u : sizeof(sign_password) - 1u};
    if (tlcp) m->credentials.encryption_key_password =
        (crypto_tls_password){m->passwords[1], sizeof(enc_password) - 1u};
  }
  return status;
}
static int tls_test_server_init(cnet_tls_server *server, const cnet_tls_server_config *config) {
  const cnet_tls_signature_scheme sm2 = CRYPTO_TLS_SIGNATURE_SM2_SM3;
  cnet_tls_server_config certificate_policy = *config;
  if (getenv("SALTS_TEST_TLS_SM2_CERT_POLICY")) {
    certificate_policy.certificate_signature_algorithms = &sm2;
    certificate_policy.certificate_signature_algorithm_count = 1;
    config = &certificate_policy;
  }
  const char *alternate = getenv("SALTS_TEST_TLS_ALT_CERT");
  const bool use_memory = getenv("SALTS_TEST_TLS_MEMORY") != NULL;
  if (!alternate && !use_memory) return cnet_tls_server_init(server, config);
  cnet_tls_server_config selected = *config;
  cnet_tls_server_identity ids[2] = {
      {.size = sizeof(ids[0]), .cert_file = config->cert_file, .key_file = config->key_file,
       .key_password = config->key_password},
      {.size = sizeof(ids[0]), .cert_file = alternate, .key_file = getenv("SALTS_TEST_TLS_ALT_KEY")}};
  tls_test_memory *memory[2] = {NULL, NULL};
  const size_t count = alternate ? 2u : 1u;
  int status = SALTS_OK;
  if (use_memory) {
    for (size_t i = 0u; i < count && status == SALTS_OK; ++i) {
      memory[i] = calloc(1u, sizeof(*memory[i]));
      if (!memory[i]) { status = SALTS_ENOMEM; break; }
      status = tls_test_prepare(memory[i], i == 0u ? config->ca_file : NULL,
          ids[i].cert_file, ids[i].key_file, config->security_profile == CNET_TLS_SECURITY_PROFILE_TLCP11);
      ids[i].credentials = &memory[i]->credentials;
      ids[i].cert_file = ids[i].key_file = NULL;
      ids[i].key_password = NULL;
    }
    if (status == SALTS_OK) {
      selected.ca_data = config->ca_file ? &memory[0]->ca : NULL;
      selected.ca_file = NULL;
    }
  }
  if (alternate) {
    selected.identities = ids; selected.identity_count = count;
    selected.cert_file = selected.key_file = selected.key_password = NULL;
    selected.credentials = NULL;
  } else if (status == SALTS_OK) {
    selected.credentials = &memory[0]->credentials;
    selected.cert_file = selected.key_file = selected.key_password = NULL;
  }
  if (status == SALTS_OK) status = cnet_tls_server_init(server, &selected);
  for (size_t i = 0u; i < count; ++i) tls_test_memory_free(memory[i]);
  memset(ids, 0, sizeof(ids));
  return status;
}

static int tls_test_connect(cnet_client *client, const cnet_connect_options *options,
    cnet_connection *out) {
  const cnet_tls_signature_scheme sm2 = CRYPTO_TLS_SIGNATURE_SM2_SM3;
  cnet_tls_client_config certificate_policy;
  cnet_connect_options configured = *options;
  if (options->tls && getenv("SALTS_TEST_TLS_SM2_CERT_POLICY")) {
    certificate_policy = *options->tls;
    certificate_policy.certificate_signature_algorithms = &sm2;
    certificate_policy.certificate_signature_algorithm_count = 1;
    configured.tls = &certificate_policy;
    options = &configured;
  }
  const char *alternate = getenv("SALTS_TEST_TLS_CLIENT_ALT_CERT");
  const bool use_memory = getenv("SALTS_TEST_TLS_MEMORY") != NULL;
  if ((!alternate && !use_memory) || !options->tls) return cnet_connect(client, options, out);
  const cnet_tls_client_config *config = options->tls;
  cnet_tls_client_config selected = *config;
  cnet_tls_client_identity ids[2] = {
      {.size = sizeof(ids[0]), .cert_file = config->cert_file, .key_file = config->key_file,
       .key_password = config->key_password},
      {.size = sizeof(ids[0]), .cert_file = alternate, .key_file = getenv("SALTS_TEST_TLS_CLIENT_ALT_KEY")}};
  tls_test_memory *memory[2] = {NULL, NULL};
  const size_t count = alternate ? 2u : 1u;
  int status = SALTS_OK;
  if (use_memory) {
    for (size_t i = 0u; i < count && status == SALTS_OK; ++i) {
      memory[i] = calloc(1u, sizeof(*memory[i]));
      if (!memory[i]) { status = SALTS_ENOMEM; break; }
      status = tls_test_prepare(memory[i], i == 0u ? config->ca_file : NULL,
          ids[i].cert_file, ids[i].key_file, false);
      ids[i].credentials = ids[i].cert_file ? &memory[i]->credentials : NULL;
      ids[i].cert_file = ids[i].key_file = ids[i].key_password = NULL;
    }
    if (status == SALTS_OK) {
      selected.ca_data = config->ca_file ? &memory[0]->ca : NULL;
      selected.ca_file = NULL;
    }
  }
  if (alternate) {
    selected.identities = ids; selected.identity_count = count;
    selected.cert_file = selected.key_file = selected.key_password = NULL;
    selected.credentials = NULL;
  } else if (status == SALTS_OK) {
    selected.credentials = ids[0].credentials;
    selected.cert_file = selected.key_file = selected.key_password = NULL;
  }
  cnet_connect_options copied = *options;
  copied.tls = &selected;
  if (status == SALTS_OK) status = cnet_connect(client, &copied, out);
  for (size_t i = 0u; i < count; ++i) tls_test_memory_free(memory[i]);
  memset(ids, 0, sizeof(ids));
  return status;
}
