/* Binary pipe endpoint for the formal independent Python key-container test. */
#include <crypto/sm2_keys.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
int main(int argc, char **argv) {
  static const unsigned char password[] = {'p', 0, 'a', 's', 's'};
  unsigned char key[32] = {0}, der[321]; size_t n = 0; int status;
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
      _setmode(_fileno(stdout), _O_BINARY) == -1) return 2;
#endif
  if (argc != 2) return 2;
  key[31] = 1;
  if (strcmp(argv[1], "encrypt") == 0) {
    status = salts_crypto_sm2_pkcs8_encrypt(key, password, sizeof(password), 10000, der, sizeof(der), &n);
    if (status != SALTS_CRYPTO_OK) return 3;
    return fwrite(der, 1, n, stdout) == n && fflush(stdout) == 0 ? 0 : 4;
  }
  if (strcmp(argv[1], "decrypt") != 0) return 2;
  n = fread(der, 1, sizeof(der), stdin);
  if (ferror(stdin) || !feof(stdin)) return 4;
  status = salts_crypto_sm2_pkcs8_decrypt(der, n, password, sizeof(password), 10000, key);
  if (status != SALTS_CRYPTO_OK) return 3;
  return fwrite(key, 1, sizeof(key), stdout) == sizeof(key) && fflush(stdout) == 0 ? 0 : 4;
}
