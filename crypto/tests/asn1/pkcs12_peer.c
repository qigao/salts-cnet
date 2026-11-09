/* Pipe endpoint owned by the formal PKCS#12 interoperability suite. */
#include <crypto/tls_stream.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
int main(int argc, char **argv) {
  unsigned char input[CRYPTO_TLS_PKCS12_MAX_BYTES + 1u];
  unsigned char password[CRYPTO_TLS_PASSWORD_MAX_BYTES + 1u];
  size_t password_size = 0u;
  if (argc != 3 || strlen(argv[1]) % 2u || strlen(argv[1]) / 2u > sizeof(password)) return 2;
  for (size_t i = 0u; argv[1][i]; i += 2u) {
    unsigned value;
    if (sscanf(argv[1] + i, "%2x", &value) != 1) return 2;
    password[password_size++] = (unsigned char)value;
  }
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1) return 2;
#endif
  const size_t n = fread(input, 1u, sizeof(input), stdin);
  if (ferror(stdin)) return 2;
  crypto_tls_credential_object *object = NULL;
  const crypto_tls_data data = {input, n, CRYPTO_TLS_ENCODING_DER};
  const crypto_tls_password pass = {password, password_size};
  const crypto_tls_credential_kind kind = strcmp(argv[2], "tlcp") == 0
      ? CRYPTO_TLS_CREDENTIAL_TLCP_SERVER : CRYPTO_TLS_CREDENTIAL_SINGLE;
  int status = crypto_tls_credential_object_from_pkcs12(&data, &pass, kind, &object);
  memset(input, 0xa5, sizeof(input)); memset(password, 0xa5, sizeof(password));
  if (status != CRYPTO_TLS_STREAM_OK && object) return 3;
  if (status == CRYPTO_TLS_STREAM_OK) {
    crypto_tls_credentials identity = {.size = sizeof(identity), .object = object};
    crypto_tls_stream_server_config server = {.size = sizeof(server), .credentials = &identity,
        .security_profile = kind == CRYPTO_TLS_CREDENTIAL_TLCP_SERVER
            ? CRYPTO_TLS_STREAM_SECURITY_PROFILE_TLCP11 : CRYPTO_TLS_STREAM_SECURITY_PROFILE_STANDARD};
    crypto_tls_stream_context *context = NULL;
    status = crypto_tls_stream_server_context_create(&server, &context);
    crypto_tls_credential_object_release(object); object = NULL;
    /* Import must own independent provider storage after the last reference. */
    crypto_tls_stream *stream = NULL;
    if (status == CRYPTO_TLS_STREAM_OK)
      status = crypto_tls_stream_create(context, true, NULL, 32768u, &stream);
    crypto_tls_stream_destroy(stream);
    crypto_tls_stream_context_release(context);
  }
  crypto_tls_credential_object_release(object);
  printf("%d\n", status);
  return fflush(stdout) == 0 ? 0 : 4;
}
