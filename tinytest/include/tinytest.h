/*
 * tinytest.h - BDD/TDD testing framework for C and C++
 *
 * Version: 1.0.0
 * License: MIT
 *
 * The public headers and TinyTest static runtime provide:
 *   - BDD syntax:  spec/describe/it/before/after/before_each/after_each
 *   - TDD syntax:  suite/section/it/check macros
 *   - Strict C11 generic assertions: check_equal, check_greater, etc.
 *   - C++ template, container, string, and exception assertions are provided by
 *     tinytest.hpp; include that header from C++ tests.
 *   - Benchmarking: benchmark_batch/benchmark_ops/benchmark_bytes/benchmark_io
 *   - Output formats: colored console, TAP, JUnit XML
 *   - Test filtering: --filter, --list, focus (fit/it_only), skip (xit)
 *
 * Usage:
 *   #include "tinytest.h" (C tests)
 *   #include "tinytest.hpp" (C++ tests)
 *
 *   spec("my module") {
 *       describe("feature") {
 *           it("should work") {
 *               check(1 + 1 == 2);
 *           }
 *       }
 *   }
 *
 * Define TINYTEST_NO_MAIN before including this header to suppress the
 * built-in main() function (useful for custom test runners).
 */

#ifndef TINYTEST_H
#define TINYTEST_H

/* C++ compatibility */
#ifdef __cplusplus
  #include <exception>
extern "C" {
#endif

#ifdef _WIN32
  #include <stdio.h>
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <Windows.h>
  #include <direct.h>
  #include <io.h>
  #include <sys/stat.h>
  #define TTEST_IS_ATTY__() _isatty(_fileno(stdout))
#else
  #include <dirent.h>
  #include <stdio.h>
  #include <sys/stat.h>
  #include <unistd.h>
  #define TTEST_IS_ATTY__() isatty(STDOUT_FILENO)
#endif

#include <float.h>
#include <math.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
/* C++ has bool built-in, C needs stdbool.h */
#ifndef __cplusplus
  #include <stdbool.h>
  #if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
    #error "TinyTest requires C11 or later"
  #else
    #define TTEST_HAS_C11_GENERIC__ 1
  #endif
#endif

#ifdef _MSC_VER
  #pragma warning(push)
  #pragma warning(disable : 4130)
  #pragma warning(disable : 4702) /* fail-fast longjmp paths can leave marker returns unreachable */
  #pragma warning(disable : 4996) /* _CRT_SECURE_NO_WARNINGS */
  #pragma warning(                                                                                 \
      disable : 4127) /* conditional expression is constant (check macros with constant args) */
#endif

#ifndef TT_USE_COLOR
  #define TT_USE_COLOR 1
#endif

#ifndef TT_USE_TAP
  #define TT_USE_TAP 0
#endif

#ifndef TT_BENCH_NAME_WIDTH
  #define TT_BENCH_NAME_WIDTH 32
#endif

#ifndef TT_BENCH_TABLE
  #define TT_BENCH_TABLE 1
#endif

#if defined(__clang__)
  #define TTEST_NO_SANITIZE_ADDRESS__ __attribute__((no_sanitize("address")))
#elif defined(__GNUC__)
  #define TTEST_NO_SANITIZE_ADDRESS__ __attribute__((no_sanitize_address))
#else
  #define TTEST_NO_SANITIZE_ADDRESS__
#endif

/* Cast macros to avoid -Wold-style-cast in C++ */
#ifdef __cplusplus
  #define TTEST_CAST(type, expr) static_cast<type>(expr)
  #define TTEST_REINTERPRET_CAST(type, expr) reinterpret_cast<type>(expr)
  #define TTEST_CONST_CAST(type, expr) const_cast<type>(expr)
#else
  #define TTEST_CAST(type, expr) ((type)(expr))
  #define TTEST_REINTERPRET_CAST(type, expr) ((type)(expr))
  #define TTEST_CONST_CAST(type, expr) ((type)(expr))
#endif

#define TTEST_COLOR_RESET__ "\x1B[0m"
#define TTEST_COLOR_RED__ "\x1B[31m"
#define TTEST_COLOR_GREEN__ "\x1B[32m"
#define TTEST_COLOR_YELLOW__ "\x1B[33m"
#define TTEST_COLOR_BOLD__ "\x1B[1m"
#define TTEST_COLOR_MAGENTA__ "\x1B[35m"

#include "tinytest/detail/runtime.h"

#if defined(__cplusplus)
  #define TTEST_CONSTRUCTOR__(fn)                                                                  \
    static void fn(void);                                                                          \
    namespace {                                                                                    \
      struct TTEST_CAT2(ttest_ctor_struct_, fn) {                                                  \
        TTEST_CAT2(ttest_ctor_struct_, fn)() { fn(); }                                             \
      };                                                                                           \
      static TTEST_CAT2(ttest_ctor_struct_, fn) TTEST_CAT2(ttest_ctor_obj_, fn);                   \
    }                                                                                              \
    static void fn(void)
#elif defined(_WIN32) && defined(__clang__) && defined(_MSC_VER)
  /*
   * MSVC-ABI Windows C has no language-level global constructor. Use the documented
   * post-compiler initializer slot instead of impersonating compiler-owned
   * .CRT$XCU. The pointer must be retained even though no C expression reads
   * it directly; the CRT walks the section before main().
   */
  #ifdef read
    #pragma push_macro("read")
    #undef read
    #define TTEST_POP_READ__ 1
  #endif
  #pragma section(".CRT$XCV", read)
  #ifdef TTEST_POP_READ__
    #pragma pop_macro("read")
    #undef TTEST_POP_READ__
  #endif
typedef void(__cdecl *ttest_ctor_fn__)(void);
  #define TTEST_CONSTRUCTOR__(fn)                                                                  \
    static void __cdecl fn(void);                                                                  \
    __declspec(allocate(".CRT$XCV"))                                                               \
    __attribute__((used)) static ttest_ctor_fn__ TTEST_CAT2(ttest_ctor_, fn) = fn;                 \
    static void __cdecl fn(void)
#elif defined(_MSC_VER)
  /*
   * MSVC treats manually allocated CRT initializer pointers as ordinary data.
   * Release linking enables /OPT:REF, so the pointer must be an explicit linker
   * root. Keep it in the documented post-compiler initializer slot and force
   * only that symbol; do not disable dead stripping for the whole executable.
   */
  #ifdef read
    #pragma push_macro("read")
    #undef read
    #define TTEST_POP_READ__ 1
  #endif
  #pragma section(".CRT$XCV", read)
  #ifdef TTEST_POP_READ__
    #pragma pop_macro("read")
    #undef TTEST_POP_READ__
  #endif
typedef void(__cdecl *ttest_ctor_fn__)(void);
  #define TTEST_MSVC_STRINGIFY_IMPL__(value) #value
  #define TTEST_MSVC_STRINGIFY__(value) TTEST_MSVC_STRINGIFY_IMPL__(value)
  #if defined(_M_IX86)
    #define TTEST_MSVC_LINKER_SYMBOL__(value) "_" TTEST_MSVC_STRINGIFY__(value)
  #else
    #define TTEST_MSVC_LINKER_SYMBOL__(value) TTEST_MSVC_STRINGIFY__(value)
  #endif
  #define TTEST_CONSTRUCTOR__(fn)                                                                  \
    static void __cdecl fn(void);                                                                  \
    __declspec(allocate(".CRT$XCV")) ttest_ctor_fn__ TTEST_CAT2(ttest_ctor_, fn) = fn;             \
    __pragma(comment(linker, "/include:" TTEST_MSVC_LINKER_SYMBOL__(TTEST_CAT2(ttest_ctor_, fn)))) \
    static void __cdecl fn(void)
#elif defined(__GNUC__) || defined(__clang__)
  /* GNU-ABI Clang (including llvm-mingw) lowers this to its target CRT's
   * initializer format. MSVC-specific allocate pragmas do not register specs
   * in that ABI, even though both toolchains define _WIN32 and __clang__.
   */
  #define TTEST_CONSTRUCTOR__(fn)                                                                  \
    static void fn(void) __attribute__((constructor));                                             \
    static void fn(void)
#else
  #define TTEST_CONSTRUCTOR__(fn) static void fn(void)
#endif

#ifdef __cplusplus
} /* extern "C" */

/* Internal control-flow exception. A failed assertion unwinds C++ frames so
 * destructors run, then is caught at the test boundary. It deliberately does
 * not derive from std::exception so that user catch(...) blocks in tested
 * expressions do not silently absorb it; the framework's own exception
 * macros rethrow it explicitly. */
class ttest_fail_exception__ {};

inline TTEST_NO_SANITIZE_ADDRESS__ void ttest_longjmp_fail__(ttest_config_type__ *config)
    noexcept(false) {
  if (!config) {
    abort();
  }
  throw ttest_fail_exception__();
}

inline void ttest_invoke_spec_cpp__(ttest_config_type__ *config, ttest_spec_fn__ fn) noexcept {
  ttest_active_config__ = config;
  try {
    if (fn) fn(config);
  } catch (const ttest_fail_exception__ &) {
    /* Assertion failure is already stored in config. */
  } catch (const std::exception &error) {
    ttest_record_unhandled_exception__(config, error.what());
  } catch (...) {
    ttest_record_unhandled_exception__(config, "non-standard exception");
  }
}

  #define TTEST_INVOKE_SPEC_ADAPTER__ ttest_invoke_spec_cpp__
#else
  #define ttest_longjmp_fail__(config) ttest_longjmp_fail_c__(config)
  #define TTEST_INVOKE_SPEC_ADAPTER__ NULL
#endif

#if defined(TT_PRINT_TRACE)
  #define TTEST_PRINT_TRACE_DEFAULT__ true
#else
  #define TTEST_PRINT_TRACE_DEFAULT__ false
#endif

#ifndef TINYTEST_NO_MAIN
int main(int argc, char **argv) {
  return ttest_main__(argc, argv, TTEST_INVOKE_SPEC_ADAPTER__, TT_USE_COLOR != 0, TT_USE_TAP != 0,
                      TTEST_IS_ATTY__() != 0, TTEST_PRINT_TRACE_DEFAULT__);
}
#endif

#if defined(__GNUC__) || defined(__clang__)
  #define TTEST_UNUSED_PARAM__ __attribute__((unused))
#else
  #define TTEST_UNUSED_PARAM__
#endif

#define spec(name)                                                                                 \
  static void TTEST_CAT2(ttest_spec_fn_,                                                           \
                         __LINE__)(TTEST_UNUSED_PARAM__ ttest_config_type__ * ttest_config__);     \
  TTEST_CONSTRUCTOR__(TTEST_CAT2(ttest_spec_reg_, __LINE__)) {                                     \
    ttest_register_spec__((name), TTEST_CAT2(ttest_spec_fn_, __LINE__));                           \
  }                                                                                                \
  static void TTEST_CAT2(ttest_spec_fn_,                                                           \
                         __LINE__)(TTEST_UNUSED_PARAM__ ttest_config_type__ * ttest_config__)

#define TTEST_CAT(a, b) a##b
#define TTEST_CAT2(a, b) TTEST_CAT(a, b)

#define TTEST_NODE_IMPL__(flags, node_list, type, format_name, ...)                                \
  for (bool TTEST_CAT2(ttest_has_run_, __LINE__) = 0;                                              \
       (!TTEST_CAT2(ttest_has_run_, __LINE__) &&                                                   \
        ttest_enter_node__(flags, ttest_active_config__, (type),                                   \
                           offsetof(struct ttest_node__, node_list), (format_name), __VA_ARGS__)); \
       ttest_exit_node__(ttest_active_config__), TTEST_CAT2(ttest_has_run_, __LINE__) = 1)

/* A single name argument is a literal string and is never interpreted as a
 * printf format, so names containing '%' are safe. Two or more arguments
 * select printf formatting (e.g. it("row %zu", i)). */
#define TTEST_NODE_DISPATCH_ONE__(flags, node_list, type, name)                                    \
  TTEST_NODE_IMPL__(flags, node_list, type, false, name)
#define TTEST_NODE_DISPATCH__(flags, node_list, type, ...)                                         \
  TTEST_NODE_IMPL__(flags, node_list, type, true, __VA_ARGS__)

#define TTEST_NODE__(flags, node_list, type, ...)                                                  \
  TTEST_OVERLOAD__(TTEST_NODE_DISPATCH_, TTEST_COUNT_ARGS__(__VA_ARGS__))(flags, node_list, type,   \
                                                                          __VA_ARGS__)

#define describe(...)                                                                              \
  TTEST_NODE__(ttest_node_flags_none__, list_children, TTEST_NODE_GROUP__, __VA_ARGS__)
#define group(...) describe(__VA_ARGS__)
#define suite(...) spec(__VA_ARGS__)
#define it(...) TTEST_NODE__(ttest_node_flags_none__, list_children, TTEST_NODE_TEST__, __VA_ARGS__)
#define bench(...)                                                                                 \
  TTEST_NODE__(ttest_node_flags_benchmark__, list_children, TTEST_NODE_TEST__, __VA_ARGS__)
#define it_only(...)                                                                               \
  TTEST_NODE__(ttest_node_flags_focus__, list_children, TTEST_NODE_TEST__, __VA_ARGS__)
#define fit(...) it_only(__VA_ARGS__)
#define it_skip(...)                                                                               \
  TTEST_NODE__(ttest_node_flags_skip__, list_children, TTEST_NODE_TEST__, __VA_ARGS__)
#define xit(...) it_skip(__VA_ARGS__)
#define it_should_fail(...)                                                                        \
  TTEST_NODE__(ttest_node_flags_expected_fail__, list_children, TTEST_NODE_TEST__, __VA_ARGS__)
#define before_each()                                                                              \
  TTEST_NODE__(ttest_node_flags_none__, list_before_each, TTEST_NODE_INTERIM__, "before_each")
#define after_each()                                                                               \
  TTEST_NODE__(ttest_node_flags_none__, list_after_each, TTEST_NODE_INTERIM__, "after_each")

#ifndef TT_NO_CONTEXT_KEYWORD
  #define context(name) describe(name)
#endif

/* TT_invoke: ##__VA_ARGS__ elides the comma when ... is empty.
 * This is a GCC/Clang extension, standardised as __VA_OPT__(,) in C23 and C++20.
 * MSVC traditional preprocessor implements the same comma-elision extension
 * natively; /Zc:preprocessor mode requires C23/C++20 standard __VA_OPT__. */
#if (defined(__cplusplus) && __cplusplus >= 202002L) || \
    (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L)
  #define TT_invoke(func, ...) func(ttest_active_config__ __VA_OPT__(,) __VA_ARGS__)
#else
  #define TT_invoke(func, ...) func(ttest_active_config__, ##__VA_ARGS__)
#endif

#define TTEST_MACRO__(M, ...) TTEST_OVERLOAD__(M, TTEST_COUNT_ARGS__(__VA_ARGS__))(__VA_ARGS__)
#define TTEST_OVERLOAD__(macro_name, suffix) TTEST_EXPAND_OVERLOAD__(macro_name, suffix)
#define TTEST_EXPAND_OVERLOAD__(macro_name, suffix) macro_name##suffix

#define TTEST_COUNT_ARGS__(...)                                                                    \
  TTEST_PATTERN_MATCH__(__VA_ARGS__, _, _, _, _, _, _, _, _, _, ONE__, _)
#define TTEST_PATTERN_MATCH__(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, N, ...) N

#define TTEST_STRING_HELPER__(x) #x
#define TTEST_STRING__(x) TTEST_STRING_HELPER__(x)
/* Two-level stringify: outer macro forces argument expansion before # operator. */
#define TTEST_STRINGIZE_LINE__ TTEST_STRING__(__LINE__)
#define __STRING__LINE__ TTEST_STRINGIZE_LINE__ /* backward-compatible alias */

#define TTEST_FMT_COLOR__ TTEST_COLOR_RED__ "Check failed:" TTEST_COLOR_RESET__ " %s"
#define TTEST_FMT_PLAIN__ "Check failed: %s"

/* Internal implementation that takes file and line. */
#define TTEST_CHECK_IMPL__(condition, file, line, ...)                                              \
  do {                                                                                             \
    if (!ttest_eval_bool__(!!(condition))) {                                                       \
      if (ttest_active_config__) {                                                                 \
        bool ttest_expected_fail__ = (ttest_active_config__->current_test &&                       \
                                      (ttest_active_config__->current_test->flags &                 \
                                       ttest_node_flags_expected_fail__));                          \
        ++ttest_active_config__->assertion_count;                                                  \
        if (!ttest_expected_fail__) {                                                              \
          ++ttest_active_config__->assertion_failed_count;                                         \
        }                                                                                          \
        if (ttest_active_config__->run == TTEST_TEST_RUN__ && !ttest_active_config__->error) {    \
          char *ttest_message__ = ttest_format__(__VA_ARGS__);                                     \
          const char *ttest_format_string__ =                                                      \
              ttest_active_config__->use_color ? TTEST_FMT_COLOR__ : TTEST_FMT_PLAIN__;            \
          snprintf(ttest_active_config__->location_buf,                                            \
                   sizeof(ttest_active_config__->location_buf), "at %s:%s", file, line);           \
          ttest_active_config__->location = ttest_active_config__->location_buf;                   \
          size_t ttest_buffer_length__ =                                                           \
              strlen(ttest_format_string__) + strlen(ttest_message__) + 1;                         \
          ttest_active_config__->error =                                                           \
              TTEST_CAST(char *, calloc(ttest_buffer_length__, sizeof(char)));                     \
          if (ttest_active_config__->use_color) {                                                  \
            snprintf(ttest_active_config__->error, ttest_buffer_length__, TTEST_FMT_COLOR__,       \
                     ttest_message__);                                                             \
          } else {                                                                                 \
            snprintf(ttest_active_config__->error, ttest_buffer_length__, TTEST_FMT_PLAIN__,       \
                     ttest_message__);                                                             \
          }                                                                                        \
          free(ttest_message__);                                                                   \
          ttest_longjmp_fail__(ttest_active_config__);                                             \
        }                                                                                          \
      }                                                                                            \
    } else {                                                                                       \
      if (ttest_active_config__) ++ttest_active_config__->assertion_count;                         \
    }                                                                                              \
  } while (0)

/* Wrapper that captures __FILE__ and __LINE__ */
#define TTEST_CHECK__(condition, ...)                                                              \
  TTEST_CHECK_IMPL__(condition, __FILE__, __STRING__LINE__, __VA_ARGS__)

#define TTEST_CHECK_ONE__(condition)                                                               \
  TTEST_CHECK_IMPL__(condition, __FILE__, __STRING__LINE__, "%s", #condition)

#define check(...) TTEST_MACRO__(TTEST_CHECK_, __VA_ARGS__)

/* String comparison helpers are implemented by the TinyTest static library. */

#ifndef __cplusplus
#define check_contains(haystack, needle)                                                           \
  do {                                                                                             \
    const char *ttest_h__ = (const char *)(haystack);                                              \
    const char *ttest_n__ = (const char *)(needle);                                                \
    TTEST_CHECK__(ttest_str_contains__(ttest_h__, ttest_n__), "expected \"%s\" to contain \"%s\"", \
                  ttest_cstr_or_null__(ttest_h__), ttest_cstr_or_null__(ttest_n__));               \
  } while (0)
#define check_contains_warn(haystack, needle)                                                      \
  do {                                                                                             \
    const char *ttest_h__ = (const char *)(haystack);                                              \
    const char *ttest_n__ = (const char *)(needle);                                                \
    TTEST_WARN__(ttest_str_contains__(ttest_h__, ttest_n__), "expected \"%s\" to contain \"%s\"",  \
                 ttest_cstr_or_null__(ttest_h__), ttest_cstr_or_null__(ttest_n__));                \
  } while (0)

#define check_starts_with(str, prefix)                                                             \
  do {                                                                                             \
    const char *ttest_s__ = (const char *)(str);                                                   \
    const char *ttest_p__ = (const char *)(prefix);                                                \
    TTEST_CHECK__(ttest_str_starts_with__(ttest_s__, ttest_p__),                                   \
                  "expected \"%s\" to start with \"%s\"", ttest_cstr_or_null__(ttest_s__),         \
                  ttest_cstr_or_null__(ttest_p__));                                                \
  } while (0)
#define check_starts_with_warn(str, prefix)                                                        \
  do {                                                                                             \
    const char *ttest_s__ = (const char *)(str);                                                   \
    const char *ttest_p__ = (const char *)(prefix);                                                \
    TTEST_WARN__(ttest_str_starts_with__(ttest_s__, ttest_p__),                                    \
                 "expected \"%s\" to start with \"%s\"", ttest_cstr_or_null__(ttest_s__),          \
                 ttest_cstr_or_null__(ttest_p__));                                                 \
  } while (0)

#define check_ends_with(str, suffix)                                                               \
  do {                                                                                             \
    const char *ttest_s__ = (const char *)(str);                                                   \
    const char *ttest_x__ = (const char *)(suffix);                                                \
    TTEST_CHECK__(ttest_str_ends_with__(ttest_s__, ttest_x__),                                     \
                  "expected \"%s\" to end with \"%s\"", ttest_cstr_or_null__(ttest_s__),           \
                  ttest_cstr_or_null__(ttest_x__));                                                \
  } while (0)
#define check_ends_with_warn(str, suffix)                                                          \
  do {                                                                                             \
    const char *ttest_s__ = (const char *)(str);                                                   \
    const char *ttest_x__ = (const char *)(suffix);                                                \
    TTEST_WARN__(ttest_str_ends_with__(ttest_s__, ttest_x__),                                      \
                 "expected \"%s\" to end with \"%s\"", ttest_cstr_or_null__(ttest_s__),            \
                 ttest_cstr_or_null__(ttest_x__));                                                 \
  } while (0)
#endif

/* Memory comparisons */
#define TTEST_EQUAL_OVERLOAD__(_1, _2, _3, selected, ...) selected
#define TTEST_CHECK_MEMORY_EQUAL__(actual, expected, len)                                          \
  do {                                                                                             \
    const void *ttest_a__ = TTEST_REINTERPRET_CAST(const void *, (actual));                        \
    const void *ttest_e__ = TTEST_REINTERPRET_CAST(const void *, (expected));                      \
    size_t ttest_n__ = TTEST_CAST(size_t, (len));                                                  \
    TTEST_CHECK__(memcmp(ttest_a__, ttest_e__, ttest_n__) == 0, "memory mismatch at %zu bytes",    \
                  ttest_n__);                                                                      \
  } while (0)
#define TTEST_CHECK_MEMORY_EQUAL_WARN__(actual, expected, len)                                     \
  do {                                                                                             \
    const void *ttest_a__ = TTEST_REINTERPRET_CAST(const void *, (actual));                        \
    const void *ttest_e__ = TTEST_REINTERPRET_CAST(const void *, (expected));                      \
    size_t ttest_n__ = TTEST_CAST(size_t, (len));                                                  \
    TTEST_WARN__(memcmp(ttest_a__, ttest_e__, ttest_n__) == 0, "memory mismatch at %zu bytes",     \
                 ttest_n__);                                                                       \
  } while (0)

#define TTEST_CHECK_MEMORY_NOT_EQUAL__(actual, expected, len)                                      \
  do {                                                                                             \
    const void *ttest_a__ = TTEST_REINTERPRET_CAST(const void *, (actual));                        \
    const void *ttest_e__ = TTEST_REINTERPRET_CAST(const void *, (expected));                      \
    size_t ttest_n__ = TTEST_CAST(size_t, (len));                                                  \
    TTEST_CHECK__(memcmp(ttest_a__, ttest_e__, ttest_n__) != 0,                                    \
                  "expected memory to differ at %zu bytes", ttest_n__);                            \
  } while (0)
#define TTEST_CHECK_MEMORY_NOT_EQUAL_WARN__(actual, expected, len)                                 \
  do {                                                                                             \
    const void *ttest_a__ = TTEST_REINTERPRET_CAST(const void *, (actual));                        \
    const void *ttest_e__ = TTEST_REINTERPRET_CAST(const void *, (expected));                      \
    size_t ttest_n__ = TTEST_CAST(size_t, (len));                                                  \
    TTEST_WARN__(memcmp(ttest_a__, ttest_e__, ttest_n__) != 0,                                     \
                 "expected memory to differ at %zu bytes", ttest_n__);                             \
  } while (0)

/* Pointer checks compare the original expression directly so object and
 * function pointers do not need to round-trip through void *. */
#define check_not_null(ptr)                                                                        \
  TTEST_CHECK__((ptr) != NULL, "expected non-null but got NULL")
#define check_not_null_warn(ptr)                                                                   \
  TTEST_WARN__((ptr) != NULL, "expected non-null but got NULL")
#define check_null(ptr)                                                                            \
  TTEST_CHECK__((ptr) == NULL, "expected NULL but got non-null")
#define check_null_warn(ptr)                                                                       \
  TTEST_WARN__((ptr) == NULL, "expected NULL but got non-null")
#define check_is_null(ptr) check_null((ptr))
#define check_is_null_warn(ptr) check_null_warn((ptr))

/* Boolean assertions */
#define check_true(actual) TTEST_CHECK__((actual), "expected true but got false")

#define check_false(actual) TTEST_CHECK__(!(actual), "expected false but got true")

/* Bitmask assertion: (val & mask) == mask */
#define check_bits(actual, mask)                                                                   \
  do {                                                                                             \
    unsigned long long ttest_a__ = TTEST_CAST(unsigned long long, (actual));                       \
    unsigned long long ttest_m__ = TTEST_CAST(unsigned long long, (mask));                         \
    unsigned long long ttest_got__ = ttest_a__ & ttest_m__;                                        \
    TTEST_CHECK__(ttest_got__ == ttest_m__, "expected bits 0x%llx set in 0x%llx, got 0x%llx",      \
                  ttest_m__, ttest_a__, ttest_got__);                                              \
  } while (0)

/* --- Non-fatal assertion --- */
/* Internal implementation that takes file and line. */
#define TTEST_WARN_IMPL__(condition, file, line, ...)                                              \
  do {                                                                                             \
    if (ttest_active_config__) {                                                                   \
      if (!ttest_eval_bool__(!!(condition))) {                                                     \
        /* Warnings are diagnostics, not assertions; they must not count as
         * passed assertions in the summary. */                                                    \
        char *ttest_message__ = ttest_format__(__VA_ARGS__);                                       \
        ++ttest_active_config__->warn_count;                                                       \
        ttest_indent__(stdout, ttest_active_config__->current_test                                 \
                                   ? ttest_active_config__->current_test->level + 1                \
                                   : 1);                                                           \
        if (ttest_active_config__->use_color) {                                                    \
          printf(TTEST_COLOR_YELLOW__ "Warning:" TTEST_COLOR_RESET__ " %s", ttest_message__);      \
        } else {                                                                                   \
          printf("Warning: %s", ttest_message__);                                                  \
        }                                                                                          \
        printf(" at %s:%s\n", file, line);                                                         \
        free(ttest_message__);                                                                     \
      }                                                                                            \
    }                                                                                              \
  } while (0)

/* Wrapper that captures __FILE__ and __LINE__ */
#define TTEST_WARN__(condition, ...)                                                               \
  TTEST_WARN_IMPL__(condition, __FILE__, __STRING__LINE__, __VA_ARGS__)

#define TTEST_WARN_ONE__(condition)                                                                \
  TTEST_WARN_IMPL__(condition, __FILE__, __STRING__LINE__, "%s", #condition)

#define check_warn(...) TTEST_MACRO__(TTEST_WARN_, __VA_ARGS__)

/* --- Info context --- */
#define info(...)                                                                                  \
  do {                                                                                             \
    char *ttest_info_msg__ = ttest_format__(__VA_ARGS__);                                          \
    size_t ttest_info_msg_len__ = strlen(ttest_info_msg__);                                        \
    if (ttest_active_config__->info_len + ttest_info_msg_len__ + 2 <                               \
        sizeof(ttest_active_config__->info_buffer)) {                                              \
      if (ttest_active_config__->info_len > 0) {                                                   \
        ttest_active_config__->info_buffer[ttest_active_config__->info_len++] = ' ';               \
      }                                                                                            \
      memcpy(ttest_active_config__->info_buffer + ttest_active_config__->info_len,                 \
             ttest_info_msg__, ttest_info_msg_len__);                                              \
      ttest_active_config__->info_len += ttest_info_msg_len__;                                     \
      ttest_active_config__->info_buffer[ttest_active_config__->info_len] = '\0';                  \
    }                                                                                              \
    free(ttest_info_msg__);                                                                        \
  } while (0)

#define capture(var, fmt) info(#var "=" fmt, (var))

/* --- BDD keywords (given/when/then) --- */
#define given(...) describe("Given " __VA_ARGS__)
#define when(...) describe("When " __VA_ARGS__)
#define then(...) it("Then " __VA_ARGS__)

/* --- Benchmarking --- */
/* Usage:
 *   benchmark_batch("one operation", samples) { code; }
 *   benchmark_ops("batched operations", samples, operations_per_sample) { code; }
 *   benchmark_bytes("buffer scan", samples, bytes_per_sample) { code; }
 *   benchmark_io("packet batch", samples, operations_per_sample, bytes_per_sample) { code; }
 */
/* Compatibility shim: benchmark titles are no longer configurable. */
#define benchmark_titles(name_title, input_title, iters_title, avg_title, ns_title, min_title,     \
                         max_title, ops_title, size_title, bw_title)                               \
  if (1)

#define TTEST_BENCHMARK_IMPL__(title, sample_count, operation_count, byte_count, track_bytes)      \
  for (                                                                                            \
      struct {                                                                                     \
        int __done;                                                                                \
        size_t __samples;                                                                          \
        size_t __operations_per_sample;                                                            \
        size_t __bytes_per_sample;                                                                 \
        bool __tracks_bytes;                                                                       \
        double __min;                                                                              \
        double __max;                                                                              \
        double __sum;                                                                              \
        const char *__title;                                                                       \
      } ttest_bm__ = {0,                                                                           \
                      TTEST_CAST(size_t, (sample_count)),                                          \
                      TTEST_CAST(size_t, (operation_count)),                                       \
                      TTEST_CAST(size_t, (byte_count)),                                            \
                      TTEST_CAST(bool, (track_bytes)),                                             \
                      1e18,                                                                        \
                      0.0,                                                                         \
                      0.0,                                                                         \
                      (title)};                                                                    \
      !ttest_bm__.__done &&                                                                        \
      (ttest_bench_require_work__(                                                                 \
           ttest_active_config__, ttest_bm__.__title, ttest_bm__.__samples,                        \
           ttest_bm__.__operations_per_sample, ttest_bm__.__bytes_per_sample,                      \
           ttest_bm__.__tracks_bytes, __FILE__, __STRING__LINE__)                                  \
           ? true                                                                                  \
           : (ttest_longjmp_fail__(ttest_active_config__), false));                               \
      ttest_bm__.__done = 1,                                                                       \
        ttest_bench_print__(                                                                       \
            ttest_active_config__, ttest_bm__.__title, ttest_bm__.__samples, ttest_bm__.__sum,     \
            ttest_bm__.__min, ttest_bm__.__max, ttest_bm__.__operations_per_sample,                \
            ttest_bm__.__bytes_per_sample, ttest_bm__.__tracks_bytes,                              \
            ttest_active_config__->current_test ? ttest_active_config__->current_test->level + 1   \
                                                : 1,                                               \
            ttest_active_config__->use_color, TT_BENCH_NAME_WIDTH, TT_BENCH_TABLE))                \
    for (size_t ttest_bm_i__ = 0; ttest_bm_i__ < ttest_bm__.__samples; ++ttest_bm_i__)             \
      for (struct {                                                                                \
             int __done;                                                                           \
             double __started_ms;                                                                  \
             double __elapsed_ms;                                                                  \
           } ttest_bm_timer__ = {0, ttest_get_time_ms__(), 0.0};                                  \
           !ttest_bm_timer__.__done;                                                               \
           ttest_bm_timer__.__done = 1,                                                            \
                 ttest_bm_timer__.__elapsed_ms =                                                   \
                     ttest_get_time_ms__() - ttest_bm_timer__.__started_ms,                        \
                 ttest_bm__.__sum += ttest_bm_timer__.__elapsed_ms,                                \
                 ttest_bm__.__min = ttest_bm_timer__.__elapsed_ms < ttest_bm__.__min               \
                                        ? ttest_bm_timer__.__elapsed_ms                             \
                                        : ttest_bm__.__min,                                        \
                 ttest_bm__.__max = ttest_bm_timer__.__elapsed_ms > ttest_bm__.__max               \
                                        ? ttest_bm_timer__.__elapsed_ms                             \
                                        : ttest_bm__.__max)

#define benchmark_batch(title, samples) TTEST_BENCHMARK_IMPL__(title, samples, 1, 0, false)
#define benchmark_ops(title, samples, operations_per_sample)                                       \
  TTEST_BENCHMARK_IMPL__(title, samples, operations_per_sample, 0, false)
#define benchmark_bytes(title, samples, bytes_per_sample)                                          \
  TTEST_BENCHMARK_IMPL__(title, samples, 1, bytes_per_sample, true)
#define benchmark_io(title, samples, operations_per_sample, bytes_per_sample)                       \
  TTEST_BENCHMARK_IMPL__(title, samples, operations_per_sample, bytes_per_sample, true)

/* Source-compatible legacy alias. Prefer an explicit benchmark_* macro in new code. */
#define benchmark(title, samples, operations_per_sample)                                           \
  benchmark_ops(title, samples, operations_per_sample)

#if defined(TTEST_HAS_C11_GENERIC__)
  #include "tinytest/detail/traits.h"
  #include "tinytest/detail/equality.h"
#endif

/* Use before_all()/after_all() as the cross-language names for one-time setup/teardown hooks. */
#define before_all()                                                                               \
  TTEST_NODE__(ttest_node_flags_none__, list_before, TTEST_NODE_INTERIM__, "before")
#define after_all() TTEST_NODE__(ttest_node_flags_none__, list_after, TTEST_NODE_INTERIM__, "after")

#ifdef _MSC_VER
  #pragma warning(pop)
#endif

#endif /* TINYTEST_H */
