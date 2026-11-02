#define TINYTEST_NO_MAIN
#include <tinytest.h>
#include <process.h>
#include <error_codes.h>
#include <clock.h>
#include <thread.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t retained_release_count;

static void release_retained_payload(void *payload) {
  ++retained_release_count;
  free(payload);
}

static int test_native_retainer(const char *self) {
  salts_process_retainer_t owner = {0};
  salts_process_retainer_token_t first = {0};
  salts_process_retainer_token_t token = {0};
  salts_process_retainer_token_t second = {99u, 99u};
  salts_process_options_t opts;
  salts_process_t *child = NULL;
  const char *const args[] = {"--core-child-sleep", NULL};
  void *payload = NULL;
  uint64_t deadline;
  size_t reaped = 0u;
  size_t pending = 0u;
  int status;

  retained_release_count = 0u;
  if (salts_process_retainer_init(&owner, 1u) != SALTS_OK) return 20;
  if (salts_process_retainer_reserve(&owner, &first) != SALTS_OK ||
      first.generation == 0u)
    return 21;
  if (salts_process_retainer_reserve(&owner, &second) != SALTS_ENOBUFS ||
      second.index != 0u || second.generation != 0u)
    return 22;
  if (salts_process_retainer_destroy(&owner) != SALTS_EBUSY) return 23;
  if (salts_process_retainer_release(&owner, first) != SALTS_OK) return 24;
  if (salts_process_retainer_reserve(&owner, &token) != SALTS_OK ||
      token.index != first.index || token.generation == 0u ||
      token.generation == first.generation)
    return 25;
  if (salts_process_retainer_release(&owner, first) != SALTS_EINVAL) return 26;

  payload = malloc(1u);
  if (!payload) return 27;
  salts_process_options_init(&opts);
  opts.program = self;
  opts.args = args;
  opts.flags = SALTS_PROCESS_CAPTURE_STDOUT | SALTS_PROCESS_CAPTURE_STDERR;
  opts.timeout_ms = 10000u;
  if (salts_process_spawn(&opts, &child) != SALTS_OK || !child) return 28;

  if (salts_process_retainer_adopt(
          &owner, token, &child, payload, release_retained_payload) !=
          SALTS_EBUSY ||
      !child)
    return 29;
  if (salts_process_terminate(child) != SALTS_OK) return 30;
  if (salts_process_retainer_adopt(
          &owner, token, &child, payload, release_retained_payload) !=
          SALTS_OK ||
      child != NULL)
    return 31;
  payload = NULL;
  if (salts_process_retainer_release(&owner, token) != SALTS_EINVAL) return 32;

  deadline = cmeta_monotonic_ms() + 15000u;
  for (;;) {
    reaped = SIZE_MAX;
    pending = SIZE_MAX;
    status = salts_process_retainer_run_ready(&owner, 1u, &reaped, &pending);
    if (status != SALTS_OK && status != SALTS_EBUSY) return 33;
    if (pending == 0u) {
      if (status != SALTS_OK || reaped != 1u || retained_release_count != 1u)
        return 34;
      break;
    }
    if (reaped != 0u || retained_release_count != 0u) return 35;
    if (cmeta_monotonic_ms() >= deadline) return 36;
    cmeta_sleep_ms(1u);
  }

  if (salts_process_retainer_destroy(&owner) != SALTS_OK || owner.impl != NULL)
    return 37;
  if (salts_process_retainer_destroy(&owner) != SALTS_EINVAL) return 38;
  return 0;
}

static int saltscore_legacy_process_entry(int argc, char **argv) {
  salts_process_options_t opts;
  salts_process_result_t result;
  salts_process_t *child = NULL;
  const char *const args[] = {"--core-child", NULL};
  char bytes[128] = {0};
  size_t count = 0;
  int retainer_status;

  if (argc > 1 && strcmp(argv[1], "--core-child") == 0) {
    fputs("SaltsProcessChild:ok\n", stdout);
    fflush(stdout);
    return 19;
  }
  if (argc > 1 && strcmp(argv[1], "--core-child-sleep") == 0) {
    cmeta_sleep_ms(5000u);
    return 0;
  }
  if (!argv || !argv[0] || !argv[0][0]) return 1;

  salts_process_options_init(&opts);
  opts.program = argv[0];
  opts.args = args;
  opts.flags = SALTS_PROCESS_CAPTURE_STDOUT | SALTS_PROCESS_CAPTURE_STDERR;
  opts.timeout_ms = 10000;
  if (salts_process_spawn(&opts, &child) != SALTS_OK || !child) return 2;
  if (salts_process_wait_for(child, 12000, &result) != SALTS_OK) return 3;
  if (result.state != SALTS_PROCESS_EXITED || result.exit_code != 19) return 4;
  if (salts_process_read_stdout(child, bytes, sizeof(bytes), &count) != SALTS_OK)
    return 5;
  if (count < sizeof("SaltsProcessChild:ok") - 1u ||
      memcmp(bytes, "SaltsProcessChild:ok", sizeof("SaltsProcessChild:ok") - 1u) != 0)
    return 6;
  salts_process_destroy(child);
  child = NULL;
  if (salts_process_spawn(NULL, &child) == SALTS_OK || child) return 7;

  retainer_status = test_native_retainer(argv[0]);
  if (retainer_status != 0) return retainer_status;

  puts("Salts::Process real child, exit and bounded retainer PASS");
  return 0;
}

/* Child modes are not TinyTest tests: the parent verifies exact stdout and
 * the deliberate exit code 19. Keep their process contract byte-identical. */
static int saltscore_process_argc;
static char **saltscore_process_argv;

spec("Core native Process spawn and retainer") {
  it("verifies real child exit, bounded output, cancel and retainer lifetime") {
    const int result = saltscore_legacy_process_entry(
        saltscore_process_argc, saltscore_process_argv);
    check(result == 0, "original Process contract returned %d", result);
  }
}

int main(int argc, char **argv) {
  if (argc > 1 && argv && argv[1] &&
      (strcmp(argv[1], "--core-child") == 0 ||
       strcmp(argv[1], "--core-child-sleep") == 0)) {
    return saltscore_legacy_process_entry(argc, argv);
  }
  saltscore_process_argc = argc;
  saltscore_process_argv = argv;
  char *runner_argv[] = {argv[0]};
  return ttest_main__(1, runner_argv, TTEST_INVOKE_SPEC_ADAPTER__,
                      TT_USE_COLOR != 0, TT_USE_TAP != 0,
                      TTEST_IS_ATTY__() != 0, TTEST_PRINT_TRACE_DEFAULT__);
}
