#include <tinytest.h>

/* Reuse the unchanged P-256/P-384 DER negative-path fixture, preserving its
 * data-oracle and error cleanup. TinyTest owns registration and failure. */
int crypto_x509_real_legacy_entry(void);

spec("Crypto X509 strict DER certificates") {
  it("runs real P256/P384 DER, malformed encoding and concatenated-chain cases") {
    const int result = crypto_x509_real_legacy_entry();
    check(result == 0, "X509 DER original fixture failed: %d", result);
  }
}
