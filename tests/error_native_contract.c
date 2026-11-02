#include <cmeta_error.h>
#include <tinytest.h>
#include <thread.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define REQUIRE(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "error contract failed at line %d: %s\n", __LINE__, #condition); \
    return 1; \
  } \
} while (0)

enum { WORKERS = 8, REGISTRY_CAPACITY = 64 };

typedef struct {
  cmeta_mutex_t mutex;
  cmeta_cond_t changed;
  size_t ready;
  int release;
} error_barrier;

typedef struct {
  error_barrier *barrier;
  cmeta_error_entry_t entry;
  cmeta_error_domain_desc_t domain;
  const char *unknown;
  char expected[64];
  int status;
} error_worker;

static void register_and_wait(void *argument) {
  error_worker *worker = (error_worker *)argument;
  int unknown_code = SALTS_ERROR_CUSTOM(worker->domain.domain, 2);
  worker->status = cmeta_error_register_domain(&worker->domain);
  worker->unknown = cmeta_strerror(unknown_code);
  snprintf(worker->expected, sizeof(worker->expected), "unknown error %d", unknown_code);
  cmeta_mutex_lock(&worker->barrier->mutex);
  ++worker->barrier->ready;
  cmeta_cond_broadcast(&worker->barrier->changed);
  while (!worker->barrier->release)
    cmeta_cond_wait(&worker->barrier->changed, &worker->barrier->mutex);
  cmeta_mutex_unlock(&worker->barrier->mutex);
  if (worker->status == SALTS_OK)
    worker->status = cmeta_error_unregister_domain(worker->domain.domain);
}

static int concurrent_registry_and_thread_local_output(void) {
  error_barrier barrier;
  error_worker workers[WORKERS];
  cmeta_thread_t threads[WORKERS];
  size_t index;
  memset(&barrier, 0, sizeof(barrier));
  memset(workers, 0, sizeof(workers));
  memset(threads, 0, sizeof(threads));
  cmeta_mutex_init(&barrier.mutex);
  cmeta_cond_init(&barrier.changed);
  REQUIRE(barrier.mutex != NULL && barrier.changed != NULL);

  /* All first calls race through the original once and shared registry. */
  for (index = 0; index < WORKERS; ++index) {
    error_worker *worker = &workers[index];
    worker->barrier = &barrier;
    worker->entry.code = SALTS_ERROR_CUSTOM(500 + (int)index, 1);
    worker->entry.name = "WORKER_ERROR";
    worker->entry.message = "borrowed worker message";
    worker->domain.domain = 500 + (int)index;
    worker->domain.domain_name = "worker";
    worker->domain.entries = &worker->entry;
    worker->domain.count = 1;
    REQUIRE(cmeta_thread_create(&threads[index], register_and_wait, worker) == SALTS_OK);
  }
  cmeta_mutex_lock(&barrier.mutex);
  while (barrier.ready != WORKERS)
    cmeta_cond_wait(&barrier.changed, &barrier.mutex);
  (void)cmeta_strerror(SALTS_ERROR_CUSTOM(999, 1));
  for (index = 0; index < WORKERS; ++index) {
    error_worker *worker = &workers[index];
    cmeta_error_info_t info = cmeta_error_info(worker->entry.code);
    REQUIRE(worker->status == SALTS_OK);
    REQUIRE(info.domain == SALTS_ERROR_DOMAIN_CUSTOM);
    REQUIRE(info.custom_domain == worker->domain.domain);
    REQUIRE(info.message == worker->entry.message);
    REQUIRE(strcmp(worker->unknown, worker->expected) == 0);
    if (index != 0) REQUIRE(worker->unknown != workers[0].unknown);
  }
  barrier.release = 1;
  cmeta_cond_broadcast(&barrier.changed);
  cmeta_mutex_unlock(&barrier.mutex);
  for (index = 0; index < WORKERS; ++index) {
    REQUIRE(cmeta_thread_join(&threads[index]) == SALTS_OK);
    REQUIRE(workers[index].status == SALTS_OK);
    REQUIRE(cmeta_error_info(workers[index].entry.code).domain == SALTS_ERROR_DOMAIN_UNKNOWN);
  }
  cmeta_cond_destroy(&barrier.changed);
  cmeta_mutex_destroy(&barrier.mutex);
  return 0;
}

static int native_domain_helpers(void) {
  static const char *const names[] = {"none", "salts", "custom", "posix", "win32", "unknown"};
  static const char *const rejected[] = {"", "None", "WIN32", "win32 ", "SALTS_ERROR_DOMAIN_WIN32"};
  size_t index;
  cmeta_error_domain_t output = SALTS_ERROR_DOMAIN_POSIX;
  REQUIRE(SALTS_ERROR_DOMAIN_NONE == 0 && SALTS_ERROR_DOMAIN_SALTS == 1);
  REQUIRE(SALTS_ERROR_DOMAIN_CUSTOM == 2 && SALTS_ERROR_DOMAIN_POSIX == 3);
  REQUIRE(SALTS_ERROR_DOMAIN_WIN32 == 4 && SALTS_ERROR_DOMAIN_UNKNOWN == 5);
  REQUIRE(cmeta_error_domain_count() == sizeof(names) / sizeof(names[0]));
  for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
    cmeta_error_domain_t value = (cmeta_error_domain_t)index;
    REQUIRE(cmeta_error_domain_is_valid(value));
    REQUIRE(strcmp(cmeta_error_domain_to_string(value), names[index]) == 0);
    REQUIRE(cmeta_error_domain_from_string(names[index], &output) == 0);
    REQUIRE(cmeta_error_domain_equals(output, value));
  }
  output = SALTS_ERROR_DOMAIN_POSIX;
  REQUIRE(cmeta_error_domain_from_string(NULL, &output) == -1);
  REQUIRE(output == SALTS_ERROR_DOMAIN_POSIX);
  REQUIRE(cmeta_error_domain_from_string("posix", NULL) == -1);
  for (index = 0; index < sizeof(rejected) / sizeof(rejected[0]); ++index) {
    REQUIRE(cmeta_error_domain_from_string(rejected[index], &output) == -1);
    REQUIRE(output == SALTS_ERROR_DOMAIN_POSIX);
  }
  REQUIRE(!cmeta_error_domain_is_valid((cmeta_error_domain_t)-1));
  REQUIRE(!cmeta_error_domain_is_valid((cmeta_error_domain_t)6));
  REQUIRE(strcmp(cmeta_error_domain_to_string((cmeta_error_domain_t)-1), "unknown") == 0);
  REQUIRE(!cmeta_error_domain_equals(SALTS_ERROR_DOMAIN_NONE, SALTS_ERROR_DOMAIN_UNKNOWN));
  return 0;
}

static int bounded_registry_and_borrowed_storage(void) {
  cmeta_error_entry_t entries[REGISTRY_CAPACITY + 1];
  cmeta_error_domain_desc_t domains[REGISTRY_CAPACITY + 1];
  char domain_name[] = "original-domain";
  char entry_name[] = "ORIGINAL_NAME";
  char message[] = "original message";
  cmeta_error_info_t info;
  size_t index;
  for (index = 0; index <= REGISTRY_CAPACITY; ++index) {
    entries[index].code = SALTS_ERROR_CUSTOM(100 + (int)index, 1);
    entries[index].name = entry_name;
    entries[index].message = message;
    domains[index].domain = 100 + (int)index;
    domains[index].domain_name = domain_name;
    domains[index].entries = &entries[index];
    domains[index].count = 1;
    REQUIRE(cmeta_error_register_domain(&domains[index]) ==
            (index < REGISTRY_CAPACITY ? SALTS_OK : SALTS_ENOSPC));
  }
  REQUIRE(cmeta_error_register_domain(&domains[0]) == SALTS_EALREADY);
  info = cmeta_error_info(entries[0].code);
  REQUIRE(info.domain_name == domain_name && info.name == entry_name && info.message == message);
  /* Storage is borrowed. Mutate only while callers are quiescent and alive. */
  memcpy(message, "modified message", sizeof(message));
  REQUIRE(strcmp(cmeta_strerror(entries[0].code), "modified message") == 0);
  domains[0].domain_name = "replacement domain";
  entries[0].name = "REPLACED_NAME";
  REQUIRE(cmeta_error_info(entries[0].code).domain_name == domains[0].domain_name);
  REQUIRE(cmeta_error_info(entries[0].code).name == entries[0].name);

  REQUIRE(cmeta_error_unregister_domain(domains[17].domain) == SALTS_OK);
  REQUIRE(cmeta_error_unregister_domain(domains[17].domain) == SALTS_ENOENT);
  REQUIRE(cmeta_error_info(entries[REGISTRY_CAPACITY - 1].code).domain == SALTS_ERROR_DOMAIN_CUSTOM);
  REQUIRE(cmeta_error_register_domain(&domains[REGISTRY_CAPACITY]) == SALTS_OK);
  for (index = 0; index <= REGISTRY_CAPACITY; ++index) {
    if (index != 17) REQUIRE(cmeta_error_unregister_domain(domains[index].domain) == SALTS_OK);
  }
  info = cmeta_error_info(entries[0].code);
  REQUIRE(info.domain == SALTS_ERROR_DOMAIN_UNKNOWN && info.custom_domain == 100);
  REQUIRE(strcmp(info.domain_name, "custom") == 0 && strcmp(info.name, "UNKNOWN") == 0);
  return 0;
}

static int invalid_descriptors_and_encoding_boundaries(void) {
  cmeta_error_entry_t entry = {SALTS_ERROR_CUSTOM(32767, 65535), "MAX", "maximum valid code"};
  cmeta_error_domain_desc_t good = {32767, "maximum", &entry, 1};
  cmeta_error_domain_desc_t bad;
  const int bad_codes[] = {0, 1, SALTS_ERROR_CUSTOM(32767, 0), SALTS_ERROR_CUSTOM(1, 1), INT_MIN};
  size_t index;
  REQUIRE(entry.code == -INT_MAX);
  REQUIRE(SALTS_ERROR_CUSTOM_DOMAIN(entry.code) == 32767);
  REQUIRE(SALTS_ERROR_CUSTOM_LOCAL(entry.code) == 65535);
  REQUIRE(SALTS_ERROR_CUSTOM_DOMAIN(INT_MIN) == 0);
  REQUIRE(SALTS_ERROR_CUSTOM_LOCAL(INT_MIN) == 0);
  REQUIRE(cmeta_error_register_domain(&good) == SALTS_OK);
  REQUIRE(cmeta_error_info(entry.code).message == entry.message);
  REQUIRE(cmeta_error_unregister_domain(good.domain) == SALTS_OK);
  REQUIRE(cmeta_error_register_domain(NULL) == SALTS_EINVAL);
  bad = good; bad.domain_name = NULL;
  REQUIRE(cmeta_error_register_domain(&bad) == SALTS_EINVAL);
  bad = good; bad.entries = NULL;
  REQUIRE(cmeta_error_register_domain(&bad) == SALTS_EINVAL);
  bad = good; bad.count = 0;
  REQUIRE(cmeta_error_register_domain(&bad) == SALTS_EINVAL);
  bad = good; bad.domain = 0;
  REQUIRE(cmeta_error_register_domain(&bad) == SALTS_EINVAL);
  bad = good; bad.domain = 32768;
  REQUIRE(cmeta_error_register_domain(&bad) == SALTS_EINVAL);
  REQUIRE(cmeta_error_unregister_domain(0) == SALTS_EINVAL);
  REQUIRE(cmeta_error_unregister_domain(32768) == SALTS_EINVAL);
  for (index = 0; index < sizeof(bad_codes) / sizeof(bad_codes[0]); ++index) {
    entry.code = bad_codes[index];
    REQUIRE(cmeta_error_register_domain(&good) == SALTS_EINVAL);
  }
  entry.code = SALTS_ERROR_CUSTOM(32767, 65535);
  entry.name = NULL;
  REQUIRE(cmeta_error_register_domain(&good) == SALTS_EINVAL);
  entry.name = "MAX"; entry.message = NULL;
  REQUIRE(cmeta_error_register_domain(&good) == SALTS_EINVAL);
  return 0;
}

static int resolution_order_and_output(void) {
  cmeta_error_info_t info = cmeta_error_info(SALTS_OK);
  cmeta_result_t result;
  char expected[64];
  REQUIRE(info.code == 0 && info.custom_domain == 0 && info.domain == SALTS_ERROR_DOMAIN_NONE);
  REQUIRE(strcmp(info.name, "SALTS_OK") == 0 && strcmp(info.message, "success") == 0);
#define CHECK_SALTS_CODE(code_value, unused_value, code_name, code_message) do { \
  info = cmeta_error_info(code_value); \
  REQUIRE(info.code == code_value && info.custom_domain == 0); \
  REQUIRE(info.domain == SALTS_ERROR_DOMAIN_SALTS); \
  REQUIRE(strcmp(info.domain_name, "salts") == 0); \
  REQUIRE(strcmp(info.name, code_name) == 0 && strcmp(info.message, code_message) == 0); \
} while (0);
  SALTS_ERROR_CODE_ITEMS(CHECK_SALTS_CODE)
#undef CHECK_SALTS_CODE
  info = cmeta_error_info(ENOENT);
  REQUIRE(info.code == ENOENT && info.domain == SALTS_ERROR_DOMAIN_POSIX);
  REQUIRE(strcmp(info.message, strerror(ENOENT)) == 0);
  info = cmeta_error_info(-ENOENT);
  REQUIRE(info.code == -ENOENT && info.domain == SALTS_ERROR_DOMAIN_POSIX);
  REQUIRE(strcmp(info.domain_name, "posix") == 0 && strcmp(info.name, "POSIX") == 0);
  REQUIRE(strcmp(info.message, strerror(ENOENT)) == 0);
  info = cmeta_error_info(INT_MIN);
  snprintf(expected, sizeof(expected), "unknown error %d", INT_MIN);
  REQUIRE(info.code == INT_MIN && info.custom_domain == 0 && info.domain == SALTS_ERROR_DOMAIN_UNKNOWN);
  REQUIRE(strcmp(info.domain_name, "unknown") == 0 && strcmp(info.name, "UNKNOWN") == 0);
  REQUIRE(strcmp(info.message, expected) == 0);
  result = cmeta_result_err(SALTS_OK);
  REQUIRE(cmeta_result_is_err(result) && result.code == SALTS_OK);
  result = cmeta_result_from_code(ENOENT);
  REQUIRE(cmeta_result_is_err(result) && result.code == ENOENT);
  REQUIRE(strcmp(result.message, strerror(ENOENT)) == 0);
#ifdef _WIN32
  /* ENOENT and ERROR_FILE_NOT_FOUND overlap: POSIX must win before Win32. */
  REQUIRE(ENOENT == ERROR_FILE_NOT_FOUND);
  info = cmeta_error_info(-(int)ERROR_FILE_NOT_FOUND);
  REQUIRE(info.domain == SALTS_ERROR_DOMAIN_POSIX);
  info = cmeta_error_info(-(int)ERROR_PIPE_BUSY);
  REQUIRE(info.domain == SALTS_ERROR_DOMAIN_WIN32);
  REQUIRE(strcmp(info.domain_name, "win32") == 0 && strcmp(info.name, "WIN32") == 0);
  REQUIRE(info.message[0] != '\0');
  REQUIRE(strchr("\r\n\t ", info.message[strlen(info.message) - 1]) == NULL);
#endif
  return 0;
}

static int saltscore_legacy_entry_error_native_contract_c(void) {
  if (concurrent_registry_and_thread_local_output() || native_domain_helpers() ||
      bounded_registry_and_borrowed_storage() || invalid_descriptors_and_encoding_boundaries() ||
      resolution_order_and_output()) return 1;
  puts("error domains, bounded borrowed registry, native precedence and thread-local output: PASS");
  return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("Error registry native lifetime") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_error_native_contract_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
