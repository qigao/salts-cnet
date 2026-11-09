/* Canonical TinyTest runner for the optional real CNet static Crypto owner.
 * The original main remains unmodified as a test-only legacy entry.
 * Python TLS/mTLS peer invocations must keep their exact stdout protocol
 * and original exit semantics; they are external peer drivers, not unit tests.
 */
#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <string.h>

int saltscore_cnet_crypto_legacy_main(int argc, char **argv);

static int owner_argc;
static char **owner_argv;

spec("Original CNet single static Crypto owner") {
  it("qualifies real TLS 1.2/1.3, strict CA/SAN and owner admission") {
    const int status = saltscore_cnet_crypto_legacy_main(owner_argc, owner_argv);
    check(status == 0, "CNet static owner native integration returned %d", status);
  }
}

int main(int argc, char **argv) {
  if (!argv || argc < 1 || !argv[0]) return 2;
  if (argc > 1 && argv[1] &&
      (strcmp(argv[1], "--mtls") == 0 ||
       strcmp(argv[1], "--external-san") == 0)) {
    /* Python TLS/mTLS peers require the original byte-exact process protocol.
     * Their command-line modes must bypass TinyTest output entirely. */
    return saltscore_cnet_crypto_legacy_main(argc, argv);
  }
  char *native_argv[] = {argv[0]};
  owner_argc = 1;
  owner_argv = native_argv;
  /* Normal framework CLI options (--filter, --list, --tap) remain usable
   * without being mistaken for an external TLS peer. */
  return ttest_main__(argc, argv, TTEST_INVOKE_SPEC_ADAPTER__,
                      TT_USE_COLOR != 0, TT_USE_TAP != 0,
                      TTEST_IS_ATTY__() != 0, TTEST_PRINT_TRACE_DEFAULT__);
}
