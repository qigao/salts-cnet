/* Formal independent-peer endpoint: fixed bounded input, binary pipes only. */
#include <crypto/sm2_x509.h>
#include <stdio.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
int main(void) {
  unsigned char input[65+2+8191+4096+1], subject[65];
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1) return 2;
#endif
  size_t n = fread(input, 1, sizeof(input), stdin);
  if (ferror(stdin) || !feof(stdin) || n < 68) return 2;
  size_t idn = ((size_t)input[65] << 8) | input[66];
  if (idn > 8191 || 67+idn >= n) return 2;
  const void *cert = input+67+idn; size_t cn = n-67-idn;
  int status = salts_crypto_sm2_x509_verify_signature(cert, cn, input, input+67, idn);
  if (status != SALTS_CRYPTO_OK) return 3;
  if (salts_crypto_sm2_x509_public_key(cert, cn, subject) != SALTS_CRYPTO_OK) return 4;
  return fwrite(subject, 1, sizeof(subject), stdout) == sizeof(subject) && fflush(stdout) == 0 ? 0 : 5;
}
