/* Canonical TinyTest entry for the existing two-plugin CNet DSO harness.
 * Preserve the independently driven --mtls external peer mode byte for byte.
 * The built CTest host passes exactly two real plugin paths.
 */
#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <string.h>

int saltscore_cnet_m6_legacy_main(int argc, char **argv);

static int loader_argc;
static char **loader_argv;

spec("Original CNet two-plugin single Crypto DSO") {
  it("validates eight real provider epochs and unload/reload across threads") {
    const int status = saltscore_cnet_m6_legacy_main(loader_argc, loader_argv);
    check(status == 0, "CNet M6 two-plugin DSO owner returned %d", status);
  }
}

int main(int argc, char **argv) {
  if (!argv || argc < 1 || !argv[0]) return 2;
  if (argc > 1 && argv[1] && strcmp(argv[1], "--mtls") == 0) {
    /* External Python peer mode: keep exact IO, exit and child behavior. */
    return saltscore_cnet_m6_legacy_main(argc, argv);
  }
  if (argc != 3 || !argv[1] || !argv[2]) return 2;
  loader_argc = argc;
  loader_argv = argv;
  char *runner_argv[] = {argv[0]};
  return ttest_main__(1, runner_argv, TTEST_INVOKE_SPEC_ADAPTER__,
                      TT_USE_COLOR != 0, TT_USE_TAP != 0,
                      TTEST_IS_ATTY__() != 0, TTEST_PRINT_TRACE_DEFAULT__);
}
