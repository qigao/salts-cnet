#include <platform.h>
#include <thread.h>
#include <tinytest.hpp>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <type_traits>

static_assert(std::is_standard_layout_v<cmeta_timeval_t>);
static_assert(std::is_standard_layout_v<cmeta_timezone_t>);
static_assert(std::is_standard_layout_v<cmeta_platform_cpu_info_t>);
static_assert(std::is_standard_layout_v<cmeta_platform_memory_info_t>);
static_assert(std::is_standard_layout_v<cmeta_platform_load_average_t>);
static_assert(std::is_standard_layout_v<cmeta_platform_network_interface_t>);

spec("Platform native C++17 public ABI") {
  it("retains all exported native function signatures and runtime thread state") {
  int (*gettimeofday_fn)(cmeta_timeval_t *, cmeta_timezone_t *) =
      &cmeta_gettimeofday;
  int (*gmtime_fn)(std::time_t, std::tm *) = &cmeta_gmtime;
  int (*localtime_fn)(std::time_t, std::tm *) = &cmeta_localtime;
  std::time_t (*timegm_fn)(const std::tm *) = &cmeta_timegm;
  std::time_t (*mktime_fn)(std::tm *) = &cmeta_mktime;
  int (*strftime_utc_fn)(std::time_t, const char *, char *, std::size_t) =
      &cmeta_strftime_utc;
  int (*strftime_local_fn)(std::time_t, const char *, char *, std::size_t) =
      &cmeta_strftime_local;
  int (*secure_random_fn)(void *, std::size_t) = &cmeta_secure_random;
  int (*os_name_fn)(char *, std::size_t) = &cmeta_platform_os_name;
  int (*os_version_fn)(char *, std::size_t) = &cmeta_platform_os_version;
  int (*arch_fn)(char *, std::size_t) = &cmeta_platform_arch;
  int (*username_fn)(char *, std::size_t) = &cmeta_platform_username;
  int (*hostname_fn)(char *, std::size_t) = &cmeta_platform_hostname;
  int (*cpu_info_fn)(cmeta_platform_cpu_info_t *) = &cmeta_platform_cpu_info;
  int (*memory_info_fn)(cmeta_platform_memory_info_t *) =
      &cmeta_platform_memory_info;
  int (*load_fn)(cmeta_platform_load_average_t *) =
      &cmeta_platform_load_average;
  int (*interfaces_fn)(cmeta_platform_network_interface_t *, std::size_t,
                       std::size_t *) =
      &cmeta_platform_network_interfaces;
  cmeta_timer_t *(*timer_create_fn)(void *) = &cmeta_timer_create;
  void (*timer_destroy_fn)(cmeta_timer_t *) = &cmeta_timer_destroy;
  int (*timer_start_fn)(cmeta_timer_t *, cmeta_timer_cb, std::uint64_t,
                        std::uint64_t) =
      &cmeta_timer_start;
  int (*timer_stop_fn)(cmeta_timer_t *) = &cmeta_timer_stop;
  void (*timer_set_data_fn)(cmeta_timer_t *, void *) = &cmeta_timer_set_data;
  void *(*timer_get_data_fn)(cmeta_timer_t *) = &cmeta_timer_get_data;
  std::uint64_t (*timer_get_repeat_fn)(cmeta_timer_t *) =
      &cmeta_timer_get_repeat;
  void (*single_set_fn)(int) = &cmeta_sync_set_single_threaded;
  int (*single_get_fn)(void) = &cmeta_sync_is_single_threaded;
  int (*getpid_fn)(void) = &cmeta_getpid;

  check(!(!gettimeofday_fn || !gmtime_fn || !localtime_fn || !timegm_fn ||
      !mktime_fn || !strftime_utc_fn || !strftime_local_fn ||
      !secure_random_fn || !os_name_fn || !os_version_fn || !arch_fn ||
      !username_fn || !hostname_fn || !cpu_info_fn || !memory_info_fn ||
      !load_fn || !interfaces_fn || !timer_create_fn || !timer_destroy_fn ||
      !timer_start_fn || !timer_stop_fn || !timer_set_data_fn ||
      !timer_get_data_fn || !timer_get_repeat_fn || !single_set_fn ||
      !single_get_fn || !getpid_fn));

  single_set_fn(1);
  check(single_get_fn() == 1 && getpid_fn() > 0);
  single_set_fn(0);
  }
}
