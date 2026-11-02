#include <tinytest.h>

/* Preserve the byte-exact 951-byte SaltsNet regression with one Crypto owner
 * and with the original independent source-conformance entry intact. */
int crypto_x509_saltsnet_legacy_entry(void);

spec("Crypto X509 original SaltsNet certificate") {
  it("checks the complete 951-byte RSA certificate, DN and negative cases") {
    const int result = crypto_x509_saltsnet_legacy_entry();
    check(result == 0, "SaltsNet X509 regression failed: %d", result);
  }
}
