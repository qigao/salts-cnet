#include <clock.h>
#include <tinytest.h>
#include <error_codes.h>
#include <platform.h>
#include <random.h>
#include <thread.h>

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static void increment(void *arg) {
  int *value = (int *)arg;
  ++*value;
}

static atomic_int timer_repeat_count;
static atomic_int timer_oneshot_count;
static atomic_int timer_destroy_race_count;

static void repeating_timer_cb(cmeta_timer_t *timer) {
  int value = atomic_fetch_add(&timer_repeat_count, 1) + 1;
  if (value >= 5) {
    (void)cmeta_timer_stop(timer);
  }
}

static void oneshot_timer_cb(cmeta_timer_t *timer) {
  (void)timer;
  atomic_fetch_add(&timer_oneshot_count, 1);
}

static void destroy_race_timer_cb(cmeta_timer_t *timer) {
  atomic_int *counter = (atomic_int *)cmeta_timer_get_data(timer);
  if (counter) atomic_fetch_add(counter, 1);
  cmeta_sleep_ms(1u);
}

static int test_original_time_and_system_surface(void) {
  cmeta_timeval_t tv = {0};
  cmeta_timezone_t tz = {0};
  struct tm utc = {0};
  struct tm local = {0};
  struct tm input = {0};
  char buffer[SALTS_PLATFORM_INFO_MAX] = {0};
  cmeta_platform_cpu_info_t cpu = {0};
  cmeta_platform_memory_info_t memory = {0};
  cmeta_platform_load_average_t load = {0};
  cmeta_platform_network_interface_t interfaces[16];
  size_t count = 0;
  time_t epoch;
  int status;

  if (cmeta_gettimeofday(&tv, &tz) != 0 || tv.tv_sec <= 0) return 10;
  if (cmeta_gmtime((time_t)1704110400, &utc) != 0 ||
      utc.tm_year + 1900 != 2024 || utc.tm_mon != 0 || utc.tm_mday != 1 ||
      utc.tm_hour != 12)
    return 11;
  if (cmeta_localtime((time_t)1704110400, &local) != 0) return 12;

  input.tm_year = 2024 - 1900;
  input.tm_mon = 0;
  input.tm_mday = 1;
  input.tm_hour = 12;
  epoch = cmeta_timegm(&input);
  if (epoch != (time_t)1704110400) return 13;
  if (cmeta_timegm(NULL) != (time_t)-1) return 14;

  if (cmeta_mktime(&local) == (time_t)-1) return 15;

  memset(buffer, 0, sizeof(buffer));
  if (cmeta_strftime_utc(epoch, "%Y-%m-%dT%H:%M:%SZ",
                         buffer, sizeof(buffer)) <= 0 ||
      strcmp(buffer, "2024-01-01T12:00:00Z") != 0)
    return 16;
  if (cmeta_strftime_local(epoch, "%Y", buffer, sizeof(buffer)) <= 0)
    return 17;

  if (cmeta_platform_os_name(buffer, sizeof(buffer)) != 0 || buffer[0] == '\0')
    return 18;
  if (cmeta_platform_os_version(buffer, sizeof(buffer)) != 0 || buffer[0] == '\0')
    return 19;
  if (cmeta_platform_arch(buffer, sizeof(buffer)) != 0 || buffer[0] == '\0')
    return 20;
  if (cmeta_platform_username(buffer, sizeof(buffer)) != 0 || buffer[0] == '\0')
    return 21;
  if (cmeta_platform_hostname(buffer, sizeof(buffer)) != 0 || buffer[0] == '\0')
    return 22;
  if (cmeta_platform_cpu_info(&cpu) != 0 || cpu.core_count < 1 ||
      cpu.model[0] == '\0')
    return 23;
  if (cmeta_platform_memory_info(&memory) != 0 || memory.total_memory == 0u)
    return 24;
  if (cmeta_platform_load_average(&load) != 0) return 25;

  memset(interfaces, 0, sizeof(interfaces));
  status = cmeta_platform_network_interfaces(
      interfaces, sizeof(interfaces) / sizeof(interfaces[0]), &count);
  if (status == 0) {
    if (count == 0u || count > sizeof(interfaces) / sizeof(interfaces[0]) ||
        interfaces[0].name[0] == '\0')
      return 26;
  } else if (count != 0u) {
    return 27;
  }

  if (cmeta_secure_random(NULL, 0u) != SALTS_OK) return 28;
  return 0;
}

static int test_original_thread_policy(void) {
  cmeta_sync_set_single_threaded(0);
  if (cmeta_sync_is_single_threaded() != 0) return 30;
  cmeta_sync_set_single_threaded(1);
  if (cmeta_sync_is_single_threaded() != 1) return 31;
  cmeta_sync_set_single_threaded(0);
  if (cmeta_getpid() <= 0) return 32;
  return 0;
}

static int test_original_native_timer(void) {
  cmeta_timer_t *timer;
  int marker = 7;

  atomic_store(&timer_repeat_count, 0);
  timer = cmeta_timer_create(NULL);
  if (!timer) return 40;
  cmeta_timer_set_data(timer, &marker);
  if (cmeta_timer_get_data(timer) != &marker ||
      cmeta_timer_get_repeat(timer) != 0u)
    return 41;
  if (cmeta_timer_start(timer, repeating_timer_cb, 100u, 100u) != 0 ||
      cmeta_timer_get_repeat(timer) != 100u)
    return 42;
  cmeta_sleep_ms(1000u);
  if (atomic_load(&timer_repeat_count) < 5) return 43;
  cmeta_timer_destroy(timer);

  atomic_store(&timer_oneshot_count, 0);
  timer = cmeta_timer_create(NULL);
  if (!timer) return 44;
  if (cmeta_timer_start(timer, oneshot_timer_cb, 100u, 0u) != 0) return 45;
  cmeta_sleep_ms(300u);
  if (atomic_load(&timer_oneshot_count) != 1) return 46;
  cmeta_timer_destroy(timer);

  atomic_store(&timer_destroy_race_count, 0);
  for (int i = 0; i < 256; ++i) {
    timer = cmeta_timer_create(NULL);
    if (!timer) return 47;
    cmeta_timer_set_data(timer, &timer_destroy_race_count);
    if (cmeta_timer_start(timer, destroy_race_timer_cb, 1u, 0u) != 0)
      return 48;
    cmeta_sleep_ms(1u);
    cmeta_timer_destroy(timer);
  }
  if (atomic_load(&timer_destroy_race_count) < 0) return 49;
  return 0;
}

static int saltscore_legacy_entry_test_platform_c(void) {
  uint8_t random_bytes[32] = {0};
  cmeta_thread_t thread = NULL;
  cmeta_mutex_t lock = NULL;
  cmeta_thread_affine_state affinity = {0};
  int value = 0;
  int status;

  if (cmeta_platform_secure_random(NULL, 0u) != SALTS_OK ||
      cmeta_platform_secure_random(NULL, 1u) != SALTS_EINVAL ||
      cmeta_platform_secure_random(random_bytes, sizeof(random_bytes)) != SALTS_OK)
    return 1;
  if (cmeta_hrtime() == 0u || cmeta_realtime_ms() == 0u ||
      cmeta_monotonic_ms() == 0u || cmeta_cpu_count() < 1)
    return 2;

  cmeta_mutex_init(&lock);
  if (lock == NULL) return 3;
  cmeta_mutex_lock(&lock);
  cmeta_mutex_unlock(&lock);
  cmeta_mutex_destroy(&lock);
  if (lock != NULL) return 4;

  if (cmeta_thread_affine_init(&affinity, &affinity) != SALTS_OK ||
      cmeta_thread_affine_check(&affinity, &affinity) != SALTS_OK ||
      cmeta_thread_affine_set_busy(&affinity, &affinity, true) != SALTS_OK ||
      cmeta_thread_affine_check(&affinity, &affinity) != SALTS_EBUSY ||
      cmeta_thread_affine_set_busy(&affinity, &affinity, false) != SALTS_OK ||
      cmeta_thread_affine_reset(&affinity, &affinity) != SALTS_OK)
    return 5;

  if (cmeta_thread_create(&thread, increment, &value) != 0 || thread == NULL)
    return 6;
  if (cmeta_thread_join(&thread) != 0 || thread != NULL || value != 1)
    return 7;

  status = test_original_time_and_system_surface();
  if (status != 0) return status;
  status = test_original_thread_policy();
  if (status != 0) return status;
  status = test_original_native_timer();
  if (status != 0) return status;
  return 0;
}

/* Keep the native contract's original exit codes and cleanup paths intact;
 * surface its exact nonzero result as one registered TinyTest failure. */
spec("Platform lifecycle and clock") {
  it("preserves the original native exit and lifetime contract") {
    const int result = saltscore_legacy_entry_test_platform_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
