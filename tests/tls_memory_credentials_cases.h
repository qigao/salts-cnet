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

/* Formal envelope negatives exercise the real context loader. Independent Go
 * peers additionally generate encrypted SM2 inputs and perform authenticated IO. */
#include <gmssl/pkcs8.h>
#include <gmssl/base64.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>

static size_t tls_memory_encrypt(unsigned encoding, unsigned scenario, unsigned char *out,
    const unsigned char *password, size_t password_size) {
  unsigned char plain[8192], ciphertext[8208] = {0}, der[16384], salt[65] = {1}, iv[16] = {2}, key[16];
  SM4_KEY cipher;
  size_t plain_size = tls_memory_fixture(CRYPTO_CLOSE_TEST_SERVER_KEY, "PRIVATE KEY",
      CRYPTO_TLS_ENCODING_DER, plain, sizeof(plain));
  size_t cipher_size = 0u, size = 0u;
  unsigned char *p = der;
  check(plain_size);
  check_equal(sm3_pbkdf2((const char *)password, password_size, salt, 16u, 10000u, sizeof(key), key), 1);
  sm4_set_encrypt_key(&cipher, key);
  check_equal(sm4_cbc_padding_encrypt(&cipher, iv, plain, plain_size, ciphertext, &cipher_size), 1);
  int iterations = scenario == 9u ? 9999 : scenario == 10u ? 1000001 : 10000;
  int prf = scenario == 11u ? -1 : OID_hmac_sm3;
  int key_size = scenario == 12u ? 32 : -1;
  size_t salt_size = scenario == 13u ? 7u : scenario == 14u ? 65u : 16u;
  if (scenario == 15u) --cipher_size;
  if (scenario == 16u) ciphertext[cipher_size - 17u] ^= 1u; /* Invalid final padding. */
  if (scenario == 18u) cipher_size = sizeof(ciphertext);
  check_equal(pkcs8_enced_private_key_info_to_der(salt, salt_size, iterations, key_size, prf,
      OID_sm4_cbc, iv, sizeof(iv), ciphertext, cipher_size, &p, &size), 1);
  if (scenario == 7u) der[size++] = 0u;
  if (scenario == 8u) --size;
  if (encoding == CRYPTO_TLS_ENCODING_DER) memcpy(out, der, size);
  else {
    const char *begin = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
    const char *end = "\n-----END ENCRYPTED PRIVATE KEY-----\n";
    size_t offset = strlen(begin);
    memcpy(out, begin, offset);
    int encoded = base64_encode_block(out + offset, der, (int)size);
    check(encoded > 0); offset += (size_t)encoded;
    memcpy(out + offset, end, strlen(end)); size = offset + strlen(end);
  }
  memset(plain, 0, sizeof(plain)); memset(key, 0, sizeof(key)); memset(&cipher, 0, sizeof(cipher));
  return size;
}

static void tls_memory_contexts(unsigned encoding, unsigned bad, unsigned version, unsigned encrypted) {
  unsigned char ca[16384], cert[16384], key[16384];
  crypto_tls_data trust = {ca, tls_memory_fixture(CRYPTO_CLOSE_TEST_CA, "CERTIFICATE", encoding, ca, sizeof(ca)), encoding};
  crypto_tls_credentials credentials = {.size = sizeof(credentials),
      .certificate_chain = {cert, tls_memory_fixture(CRYPTO_CLOSE_TEST_SERVER_CERT, "CERTIFICATE", encoding, cert, sizeof(cert)), encoding},
      .private_key = {key, tls_memory_fixture(CRYPTO_CLOSE_TEST_SERVER_KEY, "PRIVATE KEY", encoding, key, sizeof(key)), encoding}};
  crypto_tls_stream_client_config client = {.size = sizeof(client), .ca_data = &trust, .minimum_version = version, .maximum_version = version};
  crypto_tls_stream_server_config server = {.size = sizeof(server), .credentials = &credentials, .minimum_version = version, .maximum_version = version};
  check(trust.size && credentials.certificate_chain.size && credentials.private_key.size);
  unsigned char password[] = {'m', 'e', 'm', 0, 'k', 'e', 'y'};
  int expected = CRYPTO_TLS_STREAM_EIO;
  if (encrypted) {
    size_t password_size = encrypted == 17u ? 0u : sizeof(password);
    credentials.private_key.size = tls_memory_encrypt(encoding, encrypted, key, password, password_size);
    credentials.private_key_password = (crypto_tls_password){password, password_size};
    switch (encrypted) {
      case 2: password[6] ^= 1u; break; /* Bytes beyond NUL remain significant. */
      case 3: credentials.private_key_password = (crypto_tls_password){0}; break;
      case 4: credentials.private_key_password.data = NULL; expected = CRYPTO_TLS_STREAM_EINVAL; break;
      case 5: credentials.private_key_password.size = SIZE_MAX; expected = CRYPTO_TLS_STREAM_ERANGE; break;
      case 6: credentials.encryption_key_password = credentials.private_key_password; expected = CRYPTO_TLS_STREAM_EINVAL; break;
      case 18: expected = CRYPTO_TLS_STREAM_ERANGE; break;
      default: break;
    }
  }
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
  if (encrypted > 1u && encrypted != 17u) {
    check_equal(crypto_tls_stream_server_context_create(&server, &stream_context[1]), expected);
    check_null(stream_context[1]);
  } else if (bad >= 13u) {
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
  memset(password, 0xa5, sizeof(password));
}
