#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef _WIN32
#ifdef __APPLE__
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "tinytest/detail/runtime.h"
#include "tinytest/detail/pp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <direct.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define TTEST_CAST(type, expression) ((type)(expression))
#define TTEST_REINTERPRET_CAST(type, expression) ((type)(expression))
#define TTEST_CONST_CAST(type, expression) ((type)(expression))

#define TTEST_COLOR_RESET__ "\x1B[0m"
#define TTEST_COLOR_RED__ "\x1B[31m"
#define TTEST_COLOR_GREEN__ "\x1B[32m"
#define TTEST_COLOR_YELLOW__ "\x1B[33m"
#define TTEST_COLOR_BOLD__ "\x1B[1m"
#define TTEST_COLOR_MAGENTA__ "\x1B[35m"

ttest_spec_entry__ *ttest_specs__ = NULL;
size_t ttest_spec_count__ = 0;
TTEST_TLS ttest_config_type__ *ttest_active_config__ = NULL;

static char *ttest_strdup__(const char *text) {
#ifdef _WIN32
  return _strdup(text);
#else
  return strdup(text);
#endif
}

void ttest_longjmp_fail_c__(ttest_config_type__ *config) {
  if (!config) abort();
  longjmp(config->jump_buffer, 1);
}

int ttest_eval_bool__(int value) { return value; }

static void ttest_fail_framework__(ttest_config_type__ *config, const char *file,
                                   const char *line, const char *format, ...) {
  const char *prefix = "Framework error: ";
  char *message;
  size_t buffer_length;
  va_list args;

  if (!config || config->run != TTEST_TEST_RUN__ || !config->current_test) {
    fprintf(stderr, "tinytest: framework failure outside an active test\n");
    abort();
  }

  va_start(args, format);
  message = ttest_vformat__(format, args);
  va_end(args);

  ++config->assertion_count;
  ++config->assertion_failed_count;
  snprintf(config->location_buf, sizeof(config->location_buf), "at %s:%s", file, line);
  config->location = config->location_buf;

  buffer_length = strlen(prefix) + strlen(message) + 1;
  config->error = (char *)calloc(buffer_length, sizeof(char));
  if (!config->error) {
    free(message);
    perror("calloc(config->error)");
    abort();
  }
  snprintf(config->error, buffer_length, "%s%s", prefix, message);
  free(message);
}

bool ttest_bench_require_work__(ttest_config_type__ *config, const char *title, size_t samples,
                                size_t operations_per_sample, size_t bytes_per_sample,
                                bool tracks_bytes, const char *file, const char *line) {
  const char *safe_title = title ? title : "(null)";
  if (samples == 0) {
    ttest_fail_framework__(config, file, line,
                           "benchmark \"%s\" requires at least one sample", safe_title);
    return false;
  }
  if (operations_per_sample == 0) {
    ttest_fail_framework__(config, file, line,
                           "benchmark \"%s\" requires at least one operation per sample",
                           safe_title);
    return false;
  }
  if (tracks_bytes && bytes_per_sample == 0) {
    ttest_fail_framework__(config, file, line,
                           "benchmark \"%s\" requires at least one byte per sample", safe_title);
    return false;
  }
  return true;
}

double ttest_get_time_ms__(void) {
#ifdef _WIN32
  LARGE_INTEGER frequency;
  LARGE_INTEGER counter;
  QueryPerformanceFrequency(&frequency);
  QueryPerformanceCounter(&counter);
  return (double)counter.QuadPart * 1000.0 / (double)frequency.QuadPart;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
#endif
}

ttest_result__ ttest_result_ok__(void) {
  ttest_result__ result = {true, TTEST_ERR_OK__, NULL};
  return result;
}

ttest_result__ ttest_result_error__(ttest_error_code__ error, const char *message) {
  ttest_result__ result = {false, error, message};
  return result;
}

void ttest_register_spec__(const char *name, ttest_spec_fn__ fn) {
  ttest_spec_entry__ *entry = (ttest_spec_entry__ *)malloc(sizeof(*entry));
  if (!entry) {
    perror("malloc(spec)");
    abort();
  }
  entry->name = name;
  entry->fn = fn;
  entry->next = ttest_specs__;
  ttest_specs__ = entry;
  ++ttest_spec_count__;
}

ttest_spec_entry__ *ttest_get_spec_entry__(size_t index) {
  ttest_spec_entry__ *entry = ttest_specs__;
  for (size_t i = 0; i < index && entry; ++i) {
    entry = entry->next;
  }
  return entry;
}

void ttest_cleanup_specs__(void) {
  ttest_spec_entry__ *entry = ttest_specs__;
  while (entry) {
    ttest_spec_entry__ *next = entry->next;
    free(entry);
    entry = next;
  }
  ttest_specs__ = NULL;
  ttest_spec_count__ = 0;
}

char *tt_temp_dir(void) {
#ifdef _WIN32
  char path[MAX_PATH];
  DWORD length = GetTempPathA((DWORD)sizeof(path), path);
  if (length == 0 || length >= sizeof(path)) {
    const char *env = getenv("TEMP");
    if (!env) env = getenv("TMP");
    if (!env) env = ".";
    return _strdup(env);
  }
  return _strdup(path);
#else
  const char *path = getenv("TMPDIR");
  if (!path) path = getenv("TMP");
  if (!path) path = getenv("TEMP");
  if (!path) path = "/tmp";
  return ttest_strdup__(path);
#endif
}

char *tt_read_file(const char *path, size_t *out_size) {
  FILE *file = fopen(path, "rb");
  long size;
  char *buffer;

  if (!file) return NULL;
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return NULL;
  }
  size = ftell(file);
  if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return NULL;
  }
  buffer = (char *)malloc((size_t)size + 1);
  if (!buffer) {
    fclose(file);
    return NULL;
  }
  if (size > 0 && fread(buffer, 1, (size_t)size, file) != (size_t)size) {
    fclose(file);
    free(buffer);
    return NULL;
  }
  fclose(file);
  buffer[size] = '\0';
  if (out_size) *out_size = (size_t)size;
  return buffer;
}

int tt_write_file(const char *path, const void *data, size_t size) {
  FILE *file = fopen(path, "wb");
  if (!file) return -1;
  if (size > 0 && fwrite(data, 1, size, file) != size) {
    fclose(file);
    return -1;
  }
  fclose(file);
  return 0;
}

int tt_remove_file(const char *path) {
#ifdef _WIN32
  DWORD attrs = GetFileAttributesA(path);
  if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) &&
      (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    return RemoveDirectoryA(path) ? 0 : -1;
  }
  return DeleteFileA(path) ? 0 : -1;
#else
  return unlink(path) == 0 ? 0 : -1;
#endif
}

int tt_make_dir(const char *path) {
#ifdef _WIN32
  return _mkdir(path) == 0 ? 0 : -1;
#else
  return mkdir(path, 0777) == 0 ? 0 : -1;
#endif
}

int tt_is_dir(const char *path) {
#ifdef _WIN32
  DWORD attrs = GetFileAttributesA(path);
  if (attrs == INVALID_FILE_ATTRIBUTES) return 0;
  return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
#else
  struct stat st;
  if (lstat(path, &st) != 0) return 0;
  return S_ISDIR(st.st_mode) ? 1 : 0;
#endif
}

char *tt_make_temp_file(const char *prefix, const char *suffix) {
  const char *name_prefix = prefix ? prefix : "tt";
  const char *name_suffix = suffix ? suffix : "";
#ifdef _WIN32
  char base[MAX_PATH];
  char file[MAX_PATH];
  if (GetTempPathA((DWORD)sizeof(base), base) == 0) return NULL;
  if (GetTempFileNameA(base, name_prefix, 0, file) == 0) return NULL;
  if (name_suffix[0]) {
    char renamed[MAX_PATH];
    size_t file_length = strlen(file);
    int strip_tmp =
        (file_length >= 4 && strcmp(file + file_length - 4, ".tmp") == 0) ? 4 : 0;
    snprintf(renamed, sizeof(renamed), "%.*s%s", (int)(file_length - strip_tmp), file,
             name_suffix);
    if (!MoveFileExA(file, renamed, MOVEFILE_REPLACE_EXISTING)) {
      DeleteFileA(file);
      return NULL;
    }
    strncpy(file, renamed, sizeof(file) - 1);
    file[sizeof(file) - 1] = '\0';
  }
  return _strdup(file);
#else
  char *directory = tt_temp_dir();
  char path[512];
  int fd;
  if (!directory) return NULL;
  snprintf(path, sizeof(path), "%s/%sXXXXXX", directory, name_prefix);
  fd = mkstemp(path);
  if (fd < 0) {
    free(directory);
    return NULL;
  }
  close(fd);
  if (name_suffix[0]) {
    char renamed[512];
    snprintf(renamed, sizeof(renamed), "%s%s", path, name_suffix);
    if (rename(path, renamed) == 0) {
      free(directory);
      return ttest_strdup__(renamed);
    }
    unlink(path);
    free(directory);
    return NULL;
  }
  free(directory);
  return ttest_strdup__(path);
#endif
}

char *tt_make_temp_dir(const char *prefix) {
  const char *name_prefix = prefix ? prefix : "tt";
#ifdef _WIN32
  char base[MAX_PATH];
  char path[MAX_PATH];
  if (GetTempPathA((DWORD)sizeof(base), base) == 0) return NULL;
  if (GetTempFileNameA(base, name_prefix, 0, path) == 0) return NULL;
  DeleteFileA(path);
  if (CreateDirectoryA(path, NULL) == 0) return NULL;
  return _strdup(path);
#else
  char *directory = tt_temp_dir();
  char path[512];
  if (!directory) return NULL;
  snprintf(path, sizeof(path), "%s/%sXXXXXX", directory, name_prefix);
  if (!mkdtemp(path)) {
    free(directory);
    return NULL;
  }
  free(directory);
  return ttest_strdup__(path);
#endif
}

int tt_remove_tree(const char *path) {
  if (!path || !path[0]) return -1;
  if (!tt_is_dir(path)) return tt_remove_file(path);
#ifdef _WIN32
  char pattern[MAX_PATH];
  WIN32_FIND_DATAA file_data;
  HANDLE find;
  snprintf(pattern, sizeof(pattern), "%s\\*", path);
  find = FindFirstFileA(pattern, &file_data);
  if (find != INVALID_HANDLE_VALUE) {
    do {
      const char *name = file_data.cFileName;
      char child[MAX_PATH];
      if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
      snprintf(child, sizeof(child), "%s\\%s", path, name);
      if ((file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
          (file_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
        tt_remove_tree(child);
      } else {
        tt_remove_file(child);
      }
    } while (FindNextFileA(find, &file_data));
    FindClose(find);
  }
  return RemoveDirectoryA(path) ? 0 : -1;
#else
  DIR *directory = opendir(path);
  if (directory) {
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
      char child[1024];
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
      snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
      if (tt_is_dir(child)) {
        tt_remove_tree(child);
      } else {
        tt_remove_file(child);
      }
    }
    closedir(directory);
  }
  return rmdir(path) == 0 ? 0 : -1;
#endif
}

ttest_array__ *ttest_array_create__(void) {
  ttest_array__ *array = (ttest_array__ *)malloc(sizeof(*array));
  if (!array) {
    perror("malloc(array)");
    abort();
  }
  array->capacity = 4;
  array->size = 0;
  array->values = (void **)calloc(array->capacity, sizeof(*array->values));
  if (!array->values) {
    perror("calloc(array->values)");
    free(array);
    abort();
  }
  return array;
}

void *ttest_array_push__(ttest_array__ *array, void *item) {
  if (array->size == array->capacity) {
    void **values;
    array->capacity *= 2;
    values = (void **)realloc(array->values, sizeof(*array->values) * array->capacity);
    if (!values) {
      perror("realloc(array)");
      abort();
    }
    array->values = values;
  }
  array->values[array->size++] = item;
  return item;
}

void *ttest_array_last__(ttest_array__ *array) {
  return array->size == 0 ? NULL : array->values[array->size - 1];
}

void *ttest_array_pop__(ttest_array__ *array) {
  if (array->size == 0) return NULL;
  return array->values[--array->size];
}

void ttest_array_free__(ttest_array__ *array) {
  if (!array) return;
  free(array->values);
  free(array);
}

ttest_array__ *ttest_array_get_or_create__(ttest_array__ **array) {
  if (!*array) *array = ttest_array_create__();
  return *array;
}

size_t ttest_array_size__(ttest_array__ *array) { return array ? array->size : 0; }

const char *ttest_test_result_name__(ttest_test_result__ result) {
  switch (result) {
#define X(name, value, label, category) \
    case TTEST_RESULT_##name##__:      \
      return label;
    TTEST_TEST_RESULT_X__
#undef X
    default:
      return "unknown";
  }
}

int ttest_test_result_category__(ttest_test_result__ result) {
  switch (result) {
#define X(name, value, label, category) \
    case TTEST_RESULT_##name##__:      \
      return category;
    TTEST_TEST_RESULT_X__
#undef X
    default:
      return TTEST_RESULT_CATEGORY_NONE__;
  }
}

bool ttest_test_result_is_skip__(ttest_test_result__ result) {
  const int category = ttest_test_result_category__(result);
  return category == TTEST_RESULT_CATEGORY_SKIP__ || category == TTEST_RESULT_CATEGORY_FILTER__;
}

bool ttest_test_result_is_fail__(ttest_test_result__ result) {
  const int category = ttest_test_result_category__(result);
  return category == TTEST_RESULT_CATEGORY_FAIL__ || category == TTEST_RESULT_CATEGORY_TODO__;
}

int ttest_str_eq__(const char *a, const char *b) { return a && b && strcmp(a, b) == 0; }

int ttest_str_ne__(const char *a, const char *b) { return !a || !b || strcmp(a, b) != 0; }

int ttest_str_contains__(const char *haystack, const char *needle) {
  return haystack && needle && strstr(haystack, needle) != NULL;
}

int ttest_str_starts_with__(const char *string, const char *prefix) {
  return string && prefix && strncmp(string, prefix, strlen(prefix)) == 0;
}

int ttest_str_ends_with__(const char *string, const char *suffix) {
  size_t string_length;
  size_t suffix_length;
  if (!string || !suffix) return 0;
  string_length = strlen(string);
  suffix_length = strlen(suffix);
  return string_length >= suffix_length &&
         strcmp(string + string_length - suffix_length, suffix) == 0;
}

const char *ttest_cstr_or_null__(const char *string) { return string ? string : "(null)"; }

typedef int (*ttest_vsnprintf_fn__)(char *, size_t, const char *, va_list);

char *ttest_vformat__(const char *format, va_list args) {
  ttest_vsnprintf_fn__ format_to_buffer = vsnprintf;
  va_list copy;
  int length;
  int written;
  char *result;

  va_copy(copy, args);
  length = format_to_buffer(NULL, 0, format, copy);
  va_end(copy);
  if (length < 0) {
    fprintf(stderr, "tinytest: format error while building message\n");
    abort();
  }

  result = (char *)malloc((size_t)length + 1);
  if (!result) {
    perror("malloc(result)");
    abort();
  }
  written = format_to_buffer(result, (size_t)length + 1, format, args);
  if (written < 0 || written > length) {
    free(result);
    fprintf(stderr, "tinytest: format error while writing message\n");
    abort();
  }
  return result;
}

char *ttest_format__(const char *format, ...) {
  va_list args;
  char *result;
  va_start(args, format);
  result = ttest_vformat__(format, args);
  va_end(args);
  return result;
}

static inline void ttest_bench_reset__(ttest_config_type__ *config) {
  config->bench_header_printed = 0;
  config->bench_header_level = 0;
}

ttest_bench_entry__ ttest_bench_make_entry__(
    const char *title, size_t samples, double sum_ms, double min_ms, double max_ms,
    size_t operations_per_sample, size_t bytes_per_sample, bool tracks_bytes) {
  const double bytes_per_mib = 1024.0 * 1024.0;
  const double elapsed_s = sum_ms / 1000.0;
  const double total_operations =
      TTEST_CAST(double, samples) * TTEST_CAST(double, operations_per_sample);
  ttest_bench_entry__ entry;

  memset(&entry, 0, sizeof(entry));
  entry.title = title;
  entry.samples = samples;
  entry.operations_per_sample = operations_per_sample;
  entry.bytes_per_sample = tracks_bytes ? bytes_per_sample : 0;
  entry.tracks_bytes = tracks_bytes;
  entry.avg_op_us = total_operations > 0.0 ? (sum_ms * 1000.0) / total_operations : 0.0;
  entry.avg_sample_us = samples > 0 ? (sum_ms * 1000.0) / TTEST_CAST(double, samples) : 0.0;
  entry.min_sample_us = min_ms * 1000.0;
  entry.max_sample_us = max_ms * 1000.0;
  entry.ops_s = elapsed_s > 0.0 ? total_operations / elapsed_s : 0.0;
  entry.mib_s = tracks_bytes && elapsed_s > 0.0
                    ? (TTEST_CAST(double, samples) * TTEST_CAST(double, bytes_per_sample)) /
                          elapsed_s / bytes_per_mib
                    : 0.0;
  return entry;
}

static inline void ttest_bench_format_optional_metrics__(const ttest_bench_entry__ *entry,
                                                         char *bytes, size_t bytes_cap, char *mib_s,
                                                         size_t mib_s_cap) {
  if (entry->tracks_bytes) {
    snprintf(bytes, bytes_cap, "%zu", entry->bytes_per_sample);
    snprintf(mib_s, mib_s_cap, "%.2f", entry->mib_s);
  } else {
    snprintf(bytes, bytes_cap, "-");
    snprintf(mib_s, mib_s_cap, "-");
  }
}

static inline ttest_test_step__ *ttest_test_step_create__(size_t level, ttest_node__ *node) {
  ttest_test_step__ *step = TTEST_CAST(ttest_test_step__ *, malloc(sizeof(ttest_test_step__)));
  if (!step) {
    perror("malloc(step)");
    abort();
  }
  step->id = node->id;
  step->level = level;
  step->type = node->type;
  step->name = node->name;
  step->flags = node->flags;
  step->executed = false;
  step->passed = false;
  step->result = TTEST_RESULT_PENDING__;
  step->skip_reason = NULL;
  step->failure_message = NULL;
  step->failure_location = NULL;
  step->execution_time_ms = 0.0;
  step->full_path = NULL;
  step->before_each_nodes = NULL;
  step->after_each_nodes = NULL;
  return step;
}

static inline void ttest_test_step_free__(ttest_test_step__ *step) {
  if (step) {
    free(step->failure_message);
    free(step->failure_location);
    free(step->full_path);
    ttest_array_free__(step->before_each_nodes);
    ttest_array_free__(step->after_each_nodes);
    free(step);
  }
}

static char *ttest_build_full_path__(ttest_test_step__ **group_stack, int stack_depth,
                                     const char *test_name) {
  size_t total_len = 0;
  char *path;
  char *dst;

  for (int i = 1; i < stack_depth; ++i) {
    const char *segment = (group_stack[i] != NULL) ? group_stack[i]->name : NULL;
    if (!segment || segment[0] == '\0') continue;
    if (total_len > 0) total_len += 1;
    total_len += strlen(segment);
  }

  if (test_name && test_name[0] != '\0') {
    if (total_len > 0) total_len += 1;
    total_len += strlen(test_name);
  }

  if (total_len == 0) return NULL;

  path = TTEST_CAST(char *, malloc(total_len + 1));
  if (!path) {
    perror("malloc(full_path)");
    abort();
  }

  dst = path;
  for (int i = 1; i < stack_depth; ++i) {
    const char *segment = (group_stack[i] != NULL) ? group_stack[i]->name : NULL;
    size_t len;
    if (!segment || segment[0] == '\0') continue;
    if (dst != path) *dst++ = '.';
    len = strlen(segment);
    memcpy(dst, segment, len);
    dst += len;
  }

  if (test_name && test_name[0] != '\0') {
    size_t len = strlen(test_name);
    if (dst != path) *dst++ = '.';
    memcpy(dst, test_name, len);
    dst += len;
  }

  *dst = '\0';
  return path;
}

static inline ttest_node__ *ttest_node_create__(int id, const char *name, ttest_node_type__ type,
                                                ttest_node_flags__ flags) {
  ttest_node__ *n = TTEST_CAST(ttest_node__ *, malloc(sizeof(ttest_node__)));
  if (!n) {
    perror("malloc(node)");
    abort();
  }
  n->id = id;
  n->next_node_id = id + 1;
  n->name = TTEST_CONST_CAST(char *, name); /* node takes ownership of name */
  n->type = type;
  n->flags = flags;
  n->list_before = NULL;
  n->list_after = NULL;
  n->list_before_each = NULL;
  n->list_after_each = NULL;
  n->list_children = NULL;
  return n;
}

static inline bool ttest_node_is_leaf__(ttest_node__ *node) {
  return !node->list_children || node->list_children->size == 0;
}

static void ttest_node_flatten_internal__(ttest_config_type__ *config, size_t level,
                                          ttest_node__ *node, ttest_array__ *steps,
                                          ttest_array__ *before_each_lists,
                                          ttest_array__ *after_each_lists) {
  if (ttest_node_is_leaf__(node)) {
    ttest_test_step__ *test_step = ttest_test_step_create__(level, node);

    for (size_t listIndex = 0; listIndex < before_each_lists->size; ++listIndex) {
      ttest_array__ *list = TTEST_CAST(ttest_array__ *, before_each_lists->values[listIndex]);
      for (size_t i = 0; i < ttest_array_size__(list); ++i) {
        ttest_array_push__(ttest_array_get_or_create__(&test_step->before_each_nodes),
                           list->values[i]);
      }
    }

    ttest_array_push__(steps, test_step);

    for (size_t listIndex = 0; listIndex < after_each_lists->size; ++listIndex) {
      size_t reverseListIndex = after_each_lists->size - listIndex - 1;
      ttest_array__ *list = TTEST_CAST(ttest_array__ *, after_each_lists->values[reverseListIndex]);
      for (size_t i = 0; i < ttest_array_size__(list); ++i) {
        ttest_array_push__(ttest_array_get_or_create__(&test_step->after_each_nodes),
                           list->values[i]);
      }
    }
    return;
  }

  ttest_array_push__(steps, ttest_test_step_create__(level, node));

  for (size_t i = 0; i < ttest_array_size__(node->list_before); ++i) {
    ttest_array_push__(
        steps, ttest_test_step_create__(level + 1,
                                        TTEST_CAST(ttest_node__ *, node->list_before->values[i])));
  }

  ttest_array_push__(before_each_lists, node->list_before_each);
  ttest_array_push__(after_each_lists, node->list_after_each);

  for (size_t i = 0; i < ttest_array_size__(node->list_children); ++i) {
    ttest_node_flatten_internal__(config, level + 1,
                                  TTEST_CAST(ttest_node__ *, node->list_children->values[i]), steps,
                                  before_each_lists, after_each_lists);
  }

  ttest_array_pop__(before_each_lists);
  ttest_array_pop__(after_each_lists);

  for (size_t i = 0; i < ttest_array_size__(node->list_after); ++i) {
    ttest_array_push__(
        steps, ttest_test_step_create__(level + 1,
                                        TTEST_CAST(ttest_node__ *, node->list_after->values[i])));
  }
}

static ttest_array__ *ttest_node_flatten__(ttest_config_type__ *config, ttest_node__ *node,
                                           ttest_array__ *steps) {
  if (node == NULL) {
    return steps;
  }

  ttest_array__ *before_each_lists = ttest_array_create__();
  ttest_array__ *after_each_lists = ttest_array_create__();
  ttest_node_flatten_internal__(config, 0, node, steps, before_each_lists, after_each_lists);
  ttest_array_free__(before_each_lists);
  ttest_array_free__(after_each_lists);

  return steps;
}

static void ttest_node_free__(ttest_node__ *n) {
  free(n->name);
  ttest_array_free__(n->list_before);
  ttest_array_free__(n->list_after);
  ttest_array_free__(n->list_before_each);
  ttest_array_free__(n->list_after_each);
  ttest_array_free__(n->list_children);
  free(n);
}

static void ttest_invoke_spec_c__(ttest_config_type__ *config, ttest_spec_fn__ fn) {
  ttest_active_config__ = config;
  if (setjmp(config->jump_buffer) != 0) return;
  if (fn) fn(config);
}
static void ttest_tap_failure_diagnostic__(const char *message);

void ttest_indent__(FILE *fp, size_t level) {
  if (!fp) return;
  for (size_t i = 0; i < level; ++i) {
    fprintf(fp, "  ");
  }
}

/* One row list drives every output view so adding a metric cannot desynchronize the columns. */
#define TTEST_BENCH_COLUMNS__                                                                     \
  ("benchmark", ":---", TTEST_BENCH_RENDER_TITLE__),                                            \
  ("samples", "---:", TTEST_BENCH_RENDER_SAMPLES__),                                            \
  ("ops/sample", "---:", TTEST_BENCH_RENDER_OPS_PER_SAMPLE__),                                  \
  ("bytes/sample", "---:", TTEST_BENCH_RENDER_BYTES_PER_SAMPLE__),                              \
  ("avg/op(ns)", "---:", TTEST_BENCH_RENDER_AVG_OP_NS__),                                       \
  ("avg/sample(us)", "---:", TTEST_BENCH_RENDER_AVG_SAMPLE_US__),                               \
  ("min/sample(us)", "---:", TTEST_BENCH_RENDER_MIN_SAMPLE_US__),                               \
  ("max/sample(us)", "---:", TTEST_BENCH_RENDER_MAX_SAMPLE_US__),                               \
  ("ops/s", "---:", TTEST_BENCH_RENDER_OPS_S__),                                                \
  ("MiB/s", "---:", TTEST_BENCH_RENDER_MIB_S__)

#define TTEST_BENCH_COLUMN_LABEL__(row) TTEST_BENCH_COLUMN_LABEL_I__ row
#define TTEST_BENCH_COLUMN_LABEL_I__(label, alignment, renderer) label
#define TTEST_BENCH_COLUMN_ALIGNMENT__(row) TTEST_BENCH_COLUMN_ALIGNMENT_I__ row
#define TTEST_BENCH_COLUMN_ALIGNMENT_I__(label, alignment, renderer) alignment
#define TTEST_BENCH_COLUMN_RENDERER__(row) TTEST_BENCH_COLUMN_RENDERER_I__ row
#define TTEST_BENCH_COLUMN_RENDERER_I__(label, alignment, renderer) renderer

#define TTEST_BENCH_RENDER_TITLE__(entry, bytes, mib_s, use_color)                                 \
  printf("%s%s%s", (use_color) ? TTEST_COLOR_MAGENTA__ : "", (entry)->title,                       \
         (use_color) ? TTEST_COLOR_RESET__ : "")
#define TTEST_BENCH_RENDER_SAMPLES__(entry, bytes, mib_s, use_color) printf("%zu", (entry)->samples)
#define TTEST_BENCH_RENDER_OPS_PER_SAMPLE__(entry, bytes, mib_s, use_color)                        \
  printf("%zu", (entry)->operations_per_sample)
#define TTEST_BENCH_RENDER_BYTES_PER_SAMPLE__(entry, bytes, mib_s, use_color) printf("%s", (bytes))
#define TTEST_BENCH_RENDER_AVG_OP_NS__(entry, bytes, mib_s, use_color)                             \
  printf("%.3f", (entry)->avg_op_us * 1000.0)
#define TTEST_BENCH_RENDER_AVG_SAMPLE_US__(entry, bytes, mib_s, use_color)                         \
  printf("%.3f", (entry)->avg_sample_us)
#define TTEST_BENCH_RENDER_MIN_SAMPLE_US__(entry, bytes, mib_s, use_color)                         \
  printf("%.3f", (entry)->min_sample_us)
#define TTEST_BENCH_RENDER_MAX_SAMPLE_US__(entry, bytes, mib_s, use_color)                         \
  printf("%.3f", (entry)->max_sample_us)
#define TTEST_BENCH_RENDER_OPS_S__(entry, bytes, mib_s, use_color) printf("%.0f", (entry)->ops_s)
#define TTEST_BENCH_RENDER_MIB_S__(entry, bytes, mib_s, use_color) printf("%s", (mib_s))

#define TTEST_BENCH_PRINT_HEADER_CELL__(row, ignored)                                              \
  printf("| %s ", TTEST_BENCH_COLUMN_LABEL__(row));
#define TTEST_BENCH_PRINT_ALIGNMENT_CELL__(row, ignored)                                           \
  printf("| %s ", TTEST_BENCH_COLUMN_ALIGNMENT__(row));
#define TTEST_BENCH_PRINT_TABLE_CELL__(row, ignored)                                               \
  do {                                                                                             \
    printf("| ");                                                                                  \
    TTEST_BENCH_COLUMN_RENDERER__(row)(&e, bytes, mib_s, use_color);                               \
    printf(" ");                                                                                   \
  } while (0);
#define TTEST_BENCH_PRINT_PLAIN_CELL__(row, ignored)                                               \
  do {                                                                                             \
    if (!first_column) printf("  %s=", TTEST_BENCH_COLUMN_LABEL__(row));                           \
    TTEST_BENCH_COLUMN_RENDERER__(row)(&e, bytes, mib_s, use_color);                               \
    first_column = false;                                                                          \
  } while (0);

static void ttest_bench_print_header__(ttest_config_type__ *config, size_t level, bool table) {
  if (!config || !table) return;
  if (config->bench_header_printed && config->bench_header_level == level) return;
  config->bench_header_printed = 1;
  config->bench_header_level = level;
  ttest_indent__(stdout, level);
  printf("  ");
  TTEST_PP_FOR_EACH__(TTEST_BENCH_PRINT_HEADER_CELL__, ~, TTEST_BENCH_COLUMNS__)
  printf("|\n");
  ttest_indent__(stdout, level);
  printf("  ");
  TTEST_PP_FOR_EACH__(TTEST_BENCH_PRINT_ALIGNMENT_CELL__, ~, TTEST_BENCH_COLUMNS__)
  printf("|\n");
}

void ttest_bench_print__(
    ttest_config_type__ *config, const char *title, size_t samples, double sum_ms, double min_ms,
    double max_ms, size_t operations_per_sample, size_t bytes_per_sample, bool tracks_bytes,
    size_t level, bool use_color, int name_width, bool table) {
  ttest_bench_entry__ e =
      ttest_bench_make_entry__(title, samples, sum_ms, min_ms, max_ms, operations_per_sample,
                               bytes_per_sample, tracks_bytes);
  char bytes[32];
  char mib_s[32];

  (void)name_width;
  ttest_bench_format_optional_metrics__(&e, bytes, sizeof(bytes), mib_s, sizeof(mib_s));

  ttest_bench_print_header__(config, level, table);
  ttest_indent__(stdout, level);
  if (table) {
    printf("  ");
    TTEST_PP_FOR_EACH__(TTEST_BENCH_PRINT_TABLE_CELL__, ~, TTEST_BENCH_COLUMNS__)
    printf("|\n");
  } else {
    bool first_column = true;
    TTEST_PP_FOR_EACH__(TTEST_BENCH_PRINT_PLAIN_CELL__, ~, TTEST_BENCH_COLUMNS__)
    printf("\n");
  }
}

bool ttest_enter_node__(ttest_node_flags__ node_flags, ttest_config_type__ *config,
                        ttest_node_type__ type, ptrdiff_t list_offset, bool format_name,
                        const char *fmt, ...) {
  if (config->run == TTEST_INIT_RUN__) {
    char *name;
    if (format_name) {
      va_list va;
      va_start(va, fmt);
      name = ttest_vformat__(fmt, va);
      va_end(va);
    } else {
      name = ttest_strdup__(fmt);
      if (!name) {
        perror("strdup(node name)");
        abort();
      }
    }

    ttest_node__ *top = TTEST_CAST(ttest_node__ *, ttest_array_last__(config->node_stack));
    if (!top) {
      fprintf(stderr, "error: node_stack is empty\n");
      abort();
    }
    unsigned char *list_storage = TTEST_REINTERPRET_CAST(unsigned char *, top) + list_offset;
    ttest_array__ *list = NULL;
    memcpy(&list, list_storage, sizeof(list));
    list = ttest_array_get_or_create__(&list);
    memcpy(list_storage, &list, sizeof(list));

    int id = config->id++;
    ttest_node__ *node = ttest_node_create__(id, name, type, node_flags);
    if (node_flags & ttest_node_flags_focus__) {
      top->flags = TTEST_CAST(ttest_node_flags__,
                              top->flags | (node_flags & ttest_node_flags_focus__));
      config->has_focus_nodes = true;
    }
    ttest_array_push__(list, node);
    ttest_array_push__(config->nodes, node);
    if (type == TTEST_NODE_GROUP__) {
      ttest_array_push__(config->node_stack, node);
      return true;
    }
    return false;
  }

  /* TEST_RUN: no name allocation needed, use existing node */
  if (config->id >= TTEST_CAST(int, config->nodes->size)) {
    fprintf(stderr, "non-deterministic spec\n");
    abort();
  }
  if (!config->nodes || !config->nodes->values) {
    fprintf(stderr, "error: config->nodes is invalid\n");
    abort();
  }
  ttest_node__ *node = TTEST_CAST(ttest_node__ *, config->nodes->values[config->id]);
  if (!node) {
    fprintf(stderr, "error: node at %d is NULL\n", config->id);
    abort();
  }

  int target_node_id = config->target_node_id;
  bool should_enter = target_node_id >= node->id && target_node_id < node->next_node_id;
  if (should_enter) {
    ttest_array_push__(config->node_stack, node);
    config->id++;
  } else {
    config->id = node->next_node_id;
  }
  if (config->print_trace) {
    const char *color = config->use_color ? TTEST_COLOR_MAGENTA__ : "";
    const char *reset = config->use_color ? TTEST_COLOR_RESET__ : "";
    fprintf(stderr, "%s% 3d ", color, target_node_id);
    ttest_indent__(stderr, config->node_stack->size - 1 - (int)should_enter);
    fprintf(stderr, "%s [%d, %d) %s%s\n", should_enter ? ">" : "|", node->id,
            node->next_node_id, node->name, reset);
  }
  return should_enter;
}

void ttest_exit_node__(ttest_config_type__ *config) {
  ttest_node__ *top = TTEST_CAST(ttest_node__ *, ttest_array_pop__(config->node_stack));
  if (top && config->run == TTEST_INIT_RUN__) {
    top->next_node_id = config->id;
  }
}

static inline const char *ttest_skip_message__(const ttest_test_step__ *step) {
  return (step && step->skip_reason && step->skip_reason[0] != '\0') ? step->skip_reason
                                                                     : "Test was skipped";
}

static void ttest_report_skip__(ttest_config_type__ *config, ttest_test_step__ *step) {
  if (config->run == TTEST_TEST_RUN__ && config->use_tap && config->test_tap_index) {
    printf("ok %zu - %s # SKIP %s\n", config->test_tap_index, step->name,
           ttest_skip_message__(step));
  }
}

static void ttest_report_pass__(ttest_config_type__ *config, ttest_test_step__ *step) {
  if (config->run == TTEST_TEST_RUN__) {
    if (config->use_tap) {
      if (config->test_tap_index) {
        printf("ok %zu - %s\n", config->test_tap_index, step->name);
      }
    } else {
      if (step->flags & ttest_node_flags_benchmark__) {
        return;
      }
      ttest_indent__(stdout, step->level);
      printf("%s[ OK    ]%s", config->use_color ? TTEST_COLOR_GREEN__ : "",
             config->use_color ? TTEST_COLOR_RESET__ : "");
      if (step->execution_time_ms > 0.0) {
        printf(" (%.2fms)", step->execution_time_ms);
      }
      printf("\n");
    }
  }
}

static void ttest_report_unexpected_pass__(ttest_config_type__ *config, ttest_test_step__ *step) {
  ++config->failed_test_count;
  if (config->run == TTEST_TEST_RUN__) {
    if (config->use_tap) {
      if (config->test_tap_index) {
        printf("not ok %zu - %s # TODO was expected to fail but passed\n", config->test_tap_index,
               step->name);
      }
    } else {
      ttest_indent__(stdout, step->level);
      printf("%s[ UPASS ]%s", config->use_color ? TTEST_COLOR_YELLOW__ : "",
             config->use_color ? TTEST_COLOR_RESET__ : "");
      if (step->execution_time_ms > 0.0) {
        printf(" (%.2fms)", step->execution_time_ms);
      }
      printf("\n");
      ttest_indent__(stdout, step->level + 1);
      printf("This test was expected to fail but passed\n");
    }
  }
}

static void ttest_report_expected_fail__(ttest_config_type__ *config, ttest_test_step__ *step) {
  if (config->run == TTEST_TEST_RUN__) {
    if (config->use_tap) {
      if (config->test_tap_index) {
        printf("ok %zu - %s # TODO expected failure\n", config->test_tap_index, step->name);
      }
    } else {
      ttest_indent__(stdout, step->level);
      printf("%s[ XFAIL ]%s", config->use_color ? TTEST_COLOR_GREEN__ : "",
             config->use_color ? TTEST_COLOR_RESET__ : "");
      if (step->execution_time_ms > 0.0) {
        printf(" (%.2fms)", step->execution_time_ms);
      }
      printf("\n");
    }
  }
}

static void ttest_report_fail__(ttest_config_type__ *config, ttest_test_step__ *step) {
  ++config->failed_test_count;
  if (config->use_tap) {
    if (config->test_tap_index) {
      printf("not ok %zu - %s", config->test_tap_index, step->name);
      ttest_tap_failure_diagnostic__(config->error);
      printf("\n");
    }
  } else {
    ttest_indent__(stdout, step->level);
    printf("%s[ FAIL  ]%s", config->use_color ? TTEST_COLOR_RED__ : "",
           config->use_color ? TTEST_COLOR_RESET__ : "");
    if (step->execution_time_ms > 0.0) {
      printf(" (%.2fms)", step->execution_time_ms);
    }
    printf("\n");
    if (config->info_len > 0) {
      ttest_indent__(stdout, step->level + 1);
      printf("with info: %s\n", config->info_buffer);
    }
    ttest_indent__(stdout, step->level + 1);
    printf("%s\n", config->error);
    ttest_indent__(stdout, step->level + 2);
    printf("%s\n", config->location);
  }
}

void ttest_record_unhandled_exception__(ttest_config_type__ *config, const char *message) {
  if (!config || config->error) return;
  ++config->assertion_count;
  if (!config->current_test ||
      !(config->current_test->flags & ttest_node_flags_expected_fail__)) {
    ++config->assertion_failed_count;
  }
  snprintf(config->location_buf, sizeof(config->location_buf), "at unhandled C++ exception");
  config->location = config->location_buf;
  config->error = ttest_format__("Unhandled C++ exception: %s", message ? message : "unknown");
}

static void ttest_execute_target__(ttest_config_type__ *config, int target_node_id) {
  config->node_stack->size = 1;
  config->id = 0;
  config->target_node_id = target_node_id;
  config->invoke_spec(config, config->current_spec);
}

static void ttest_execute_cleanup_target__(ttest_config_type__ *config, int target_node_id) {
  char *primary_error = config->error;
  char primary_location[sizeof(config->location_buf)];

  primary_location[0] = '\0';
  if (primary_error && config->location) {
    snprintf(primary_location, sizeof(primary_location), "%s", config->location);
  }
  config->error = NULL;
  config->location = NULL;
  ttest_execute_target__(config, target_node_id);
  if (primary_error) {
    free(config->error);
    config->error = primary_error;
    snprintf(config->location_buf, sizeof(config->location_buf), "%s", primary_location);
    config->location = config->location_buf;
  }
}

static void ttest_run__(ttest_config_type__ *config) {
  ttest_test_step__ *step = config->current_test;

  if (step->type == TTEST_NODE_GROUP__ && !config->use_tap) {
    if (config->has_focus_nodes && !(step->flags & ttest_node_flags_focus__)) {
      return;
    }
    ttest_indent__(stdout, step->level);
    printf("%s%s%s\n", config->use_color ? TTEST_COLOR_BOLD__ : "", step->name,
           config->use_color ? TTEST_COLOR_RESET__ : "");
    return;
  }

  bool skipped = false;
  bool filtered = false;
  const char *skip_reason = NULL;
  if (step->type == TTEST_NODE_TEST__) {
    step->result = TTEST_RESULT_PENDING__;
    step->skip_reason = NULL;
    if (step->flags & ttest_node_flags_skip__) {
      skipped = true;
      skip_reason = "Test was skipped";
    } else if (config->has_focus_nodes && !(step->flags & ttest_node_flags_focus__)) {
      filtered = true;
      skip_reason = "filtered by focus";
    } else if (config->filter && !strstr(step->name, config->filter) &&
               !(step->full_path && strstr(step->full_path, config->filter))) {
      filtered = true;
      skip_reason = "filtered out";
    }
    ++config->test_tap_index;

    /* Print selected test names before execution so a crashing case remains identifiable. */
    if (config->run == TTEST_TEST_RUN__ && !config->use_tap && !skipped && !filtered) {
      ttest_indent__(stdout, step->level);
      printf("%s\n", step->name);
      fflush(stdout);
    }

    if (!skipped && !filtered) {
      if (config->error) {
        free(config->error);
        config->error = NULL;
      }
      config->location = NULL;
      config->info_buffer[0] = '\0';
      config->info_len = 0;
      config->skip_subsequent = false;

      if (step->flags & ttest_node_flags_benchmark__) {
        ttest_bench_reset__(config);
      }

      for (size_t i = 0; i < ttest_array_size__(step->before_each_nodes); ++i) {
        ttest_node__ *hook =
            TTEST_CAST(ttest_node__ *, step->before_each_nodes->values[i]);
        ttest_execute_target__(config, hook->id);
        if (config->error) break;
      }

      if (!config->error) {
        double start_time = ttest_get_time_ms__();
        ttest_execute_target__(config, step->id);
        double end_time = ttest_get_time_ms__();
        step->execution_time_ms = end_time - start_time;
      }

      for (size_t i = 0; i < ttest_array_size__(step->after_each_nodes); ++i) {
        ttest_node__ *hook = TTEST_CAST(ttest_node__ *, step->after_each_nodes->values[i]);
        ttest_execute_cleanup_target__(config, hook->id);
      }
    }

    if (skipped || filtered) {
      step->executed = false;
      step->passed = false;
      step->result = filtered ? TTEST_RESULT_FILTERED__ : TTEST_RESULT_SKIPPED__;
      step->skip_reason = skip_reason;
      ttest_report_skip__(config, step);
    } else if (config->error == NULL) {
      /* Test passed */
      step->executed = true;
      bool is_expected_fail = (step->flags & ttest_node_flags_expected_fail__);
      if (is_expected_fail) {
        step->passed = false;
        step->result = TTEST_RESULT_UNEXPECTED_PASS__;
        step->failure_message = ttest_strdup__("Expected to fail but passed");
        ttest_report_unexpected_pass__(config, step);
      } else {
        step->passed = true;
        step->result = TTEST_RESULT_PASSED__;
        ttest_report_pass__(config, step);
      }
    } else {
      /* Test failed */
      step->executed = true;
      bool is_expected_fail = (step->flags & ttest_node_flags_expected_fail__);
      if (is_expected_fail) {
        step->passed = true; /* Expected failure counts as pass */
        step->result = TTEST_RESULT_EXPECTED_FAIL__;
        ttest_report_expected_fail__(config, step);
      } else {
        step->passed = false;
        step->result = TTEST_RESULT_FAILED__;
        step->failure_message = ttest_strdup__(config->error);
        step->failure_location =
            ttest_strdup__(config->location ? config->location : "at unknown location");
        ttest_report_fail__(config, step);
      }
      free(config->error);
      config->error = NULL;
    }
  } else if (!skipped) {
    if (config->error) {
      free(config->error);
      config->error = NULL;
    }
    config->location = NULL;
    config->info_buffer[0] = '\0';
    config->info_len = 0;
    ttest_execute_target__(config, step->id);
    if (config->error) {
      step->executed = true;
      step->passed = false;
      step->result = TTEST_RESULT_FAILED__;
      step->failure_message = ttest_strdup__(config->error);
      step->failure_location =
          ttest_strdup__(config->location ? config->location : "at unknown location");
      if (config->use_tap) {
        ++config->failed_test_count;
        printf("Bail out! fixture %s failed: %s\n", step->name, config->error);
      } else {
        ttest_report_fail__(config, step);
      }
      free(config->error);
      config->error = NULL;
    } else {
      step->executed = true;
      step->passed = true;
      step->result = TTEST_RESULT_PASSED__;
    }
  }
}

static bool ttest_is_supported_term__(void) {
  bool result;
  const char *term = getenv("TERM");
  result = term && strcmp(term, "") != 0;
#ifndef _WIN32
  return result;
#else
  if (result) {
    return 1;
  }

  /* Attempt to enable virtual terminal processing on Windows.
   * See: https://msdn.microsoft.com/en-us/library/windows/desktop/mt638032(v=vs.85).aspx */
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut == INVALID_HANDLE_VALUE) {
    return 0;
  }

  DWORD dwMode = 0;
  if (!GetConsoleMode(hOut, &dwMode)) {
    return 0;
  }

  dwMode |= 0x4; /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */
  if (!SetConsoleMode(hOut, dwMode)) {
    return 0;
  }

  return 1;
#endif
}

static inline int ttest_is_xml_char__(unsigned char c) {
  return c == '\t' || c == '\n' || c == '\r' || c >= 0x20;
}

static const char *ttest_skip_ansi_escape__(const char *p) {
  if (!p || p[0] != '\x1B') return p;
  ++p;
  if (*p == '[') {
    ++p;
    while (*p && ((TTEST_CAST(unsigned char, *p) >= 0x30 &&
                   TTEST_CAST(unsigned char, *p) <= 0x3F) ||
                  (TTEST_CAST(unsigned char, *p) >= 0x20 &&
                   TTEST_CAST(unsigned char, *p) <= 0x2F))) {
      ++p;
    }
    if (*p && TTEST_CAST(unsigned char, *p) >= 0x40 &&
        TTEST_CAST(unsigned char, *p) <= 0x7E) {
      ++p;
    }
    return p;
  }
  if (*p == ']') {
    ++p;
    while (*p && *p != '\a') {
      if (p[0] == '\x1B' && p[1] == '\\') {
        p += 2;
        return p;
      }
      ++p;
    }
    if (*p == '\a') ++p;
    return p;
  }
  if (*p) ++p;
  return p;
}

static void ttest_tap_failure_diagnostic__(const char *message) {
  /* Append a single-line, ANSI-free diagnostic to a TAP failure line. */
  if (!message || !message[0]) return;
  printf(" # ");
  for (const char *p = message; *p;) {
    if (*p == '\n' || *p == '\r') {
      fputc(' ', stdout);
      ++p;
      continue;
    }
    if (*p == '\x1B') {
      p = ttest_skip_ansi_escape__(p);
      continue;
    }
    fputc(*p, stdout);
    ++p;
  }
}

static void ttest_xml_escape__(FILE *f, const char *str) {
  if (!str) return;
  for (const char *p = str; *p;) {
    unsigned char c = TTEST_CAST(unsigned char, *p);
    if (c == 0x1B) {
      p = ttest_skip_ansi_escape__(p);
      continue;
    }
    if (!ttest_is_xml_char__(c)) {
      ++p;
      continue;
    }
    switch (*p) {
    case '&':
      fprintf(f, "&amp;");
      break;
    case '<':
      fprintf(f, "&lt;");
      break;
    case '>':
      fprintf(f, "&gt;");
      break;
    case '"':
      fprintf(f, "&quot;");
      break;
    case '\'':
      fprintf(f, "&apos;");
      break;
    default:
      fputc(*p, f);
      break;
    }
    ++p;
  }
}

static ttest_result__ ttest_generate_junit__(ttest_config_type__ *config, ttest_array__ *steps,
                                             size_t test_count) {
  FILE *f = fopen(config->junit_file, "w");
  if (!f) {
    return ttest_result_error__(TTEST_ERR_IO__, "could not open JUnit output file");
  }

  /* Get current timestamp in ISO 8601 format */
  time_t now = time(NULL);
  struct tm *tm_info = gmtime(&now);
  if (!tm_info) {
    fclose(f);
    return ttest_result_error__(TTEST_ERR_TIME__, "could not build JUnit timestamp");
  }
  char timestamp[32];
  if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tm_info) == 0) {
    fclose(f);
    return ttest_result_error__(TTEST_ERR_TIME__, "could not format JUnit timestamp");
  }

  /* Count skipped tests */
  size_t skipped_count = 0;
  for (size_t i = 0; i < steps->size; ++i) {
    ttest_test_step__ *step = TTEST_CAST(ttest_test_step__ *, steps->values[i]);
    if (step->type == TTEST_NODE_TEST__ && ttest_test_result_is_skip__(step->result)) {
      ++skipped_count;
    }
  }

  fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  fprintf(f,
          "<testsuites name=\"BDD Test Run\" tests=\"%zu\" failures=\"%zu\" errors=\"0\" "
          "skipped=\"%zu\" time=\"0\" timestamp=\"%s\">\n",
          test_count, config->failed_test_count, skipped_count, timestamp);

  fprintf(f,
          "  <testsuite name=\"tinytest\" tests=\"%zu\" failures=\"%zu\" errors=\"0\" "
          "skipped=\"%zu\" time=\"0\" timestamp=\"%s\">\n",
          test_count, config->failed_test_count, skipped_count, timestamp);

  for (size_t i = 0; i < steps->size; ++i) {
    ttest_test_step__ *step = TTEST_CAST(ttest_test_step__ *, steps->values[i]);
    if (step->type == TTEST_NODE_TEST__) {
      fprintf(f, "    <testcase name=\"");
      ttest_xml_escape__(f, step->name);
      fprintf(f, "\" classname=\"");
      /* Use full hierarchical path if available, otherwise use a generic name */
      if (step->full_path) {
        ttest_xml_escape__(f, step->full_path);
      } else {
        ttest_xml_escape__(f, "tinytest");
      }
      fprintf(f, "\" time=\"%.6f\"", step->execution_time_ms / 1000.0); /* Convert ms to seconds */

      bool is_skip = ttest_test_result_is_skip__(step->result);
      bool is_fail = ttest_test_result_is_fail__(step->result);

      if (is_skip) {
        fprintf(f, ">\n");
        fprintf(f, "      <skipped message=\"");
        ttest_xml_escape__(f, ttest_skip_message__(step));
        fprintf(f, "\" />\n");
        fprintf(f, "    </testcase>\n");
      } else if (is_fail) {
        /* Test failed */
        fprintf(f, ">\n");
        fprintf(f, "      <failure message=\"");
        if (step->failure_message) {
          ttest_xml_escape__(f, step->failure_message);
        } else {
          fprintf(f, "Test failed");
        }
        fprintf(f, "\" type=\"AssertionError\">");
        if (step->failure_location) {
          fprintf(f, "\n");
          ttest_xml_escape__(f, step->failure_location);
        }
        if (step->failure_message) {
          fprintf(f, "\n");
          ttest_xml_escape__(f, step->failure_message);
        }
        fprintf(f, "\n      </failure>\n");
        fprintf(f, "    </testcase>\n");
      } else {
        /* Test passed */
        fprintf(f, " />\n");
      }
    }
  }

  fprintf(f, "  </testsuite>\n");
  fprintf(f, "</testsuites>\n");
  if (ferror(f)) {
    fclose(f);
    return ttest_result_error__(TTEST_ERR_IO__, "could not write complete JUnit output");
  }
  if (fclose(f) != 0) {
    return ttest_result_error__(TTEST_ERR_IO__, "could not close JUnit output file");
  }
  return ttest_result_ok__();
}

int ttest_main__(int argc, char **argv, ttest_invoke_spec_adapter__ invoke_spec,
                 bool default_use_color, bool default_use_tap, bool stdout_is_atty,
                 bool print_trace) {
  #ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  #endif

  double ttest_start_time__ = ttest_get_time_ms__();
  struct ttest_config_type__ config;
  memset(&config, 0, sizeof(config));
  config.run = TTEST_INIT_RUN__;
  config.invoke_spec = invoke_spec ? invoke_spec : ttest_invoke_spec_c__;
  config.use_tap = default_use_tap;
  config.print_trace = print_trace;

  /* Parse command-line arguments */
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--tap") == 0) {
      config.use_tap = 1;
    } else if (strcmp(argv[i], "--color") == 0) {
      config.use_color = 1;
    } else if (strcmp(argv[i], "--no-color") == 0) {
      config.use_color = 0;
    } else if (strcmp(argv[i], "--junit") == 0) {
      if (i + 1 < argc) {
        config.junit_file = argv[++i];
      } else {
        fprintf(stderr, "Error: --junit requires a filename argument\n");
        return 1;
      }
    } else if (strcmp(argv[i], "--list") == 0 || strcmp(argv[i], "-l") == 0) {
      config.list_only = 1;
    } else if (strcmp(argv[i], "--filter") == 0 || strcmp(argv[i], "-f") == 0) {
      if (i + 1 < argc) {
        config.filter = argv[++i];
      } else {
        fprintf(stderr, "Error: --filter requires a pattern argument\n");
        return 1;
      }
    } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      printf("Usage: %s [options]\n", argv[0]);
      printf("Options:\n");
      printf("  --tap              Output in TAP (Test Anything Protocol) format\n");
      printf("  --color            Force colored output\n");
      printf("  --no-color         Disable colored output\n");
      printf("  --junit <file>     Generate JUnit XML report to specified file\n");
      printf("  --list, -l         List all test names without running them\n");
      printf("  --filter, -f <pat> Run only tests whose name contains <pat>\n");
      printf("  --help, -h         Show this help message\n");
      return 0;
    } else {
      fprintf(stderr, "Error: unknown option '%s'\n", argv[i]);
      fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
      return 2;
    }
  }

  const char *tap_env = getenv("TT_USE_TAP");
  if (!config.use_tap && tap_env && strcmp(tap_env, "") != 0 && strcmp(tap_env, "0") != 0) {
    config.use_tap = 1;
  }

  if (!config.use_tap && !config.use_color && default_use_color && stdout_is_atty &&
      ttest_is_supported_term__()) {
    config.use_color = 1;
  }

  if (ttest_spec_count__ == 0) {
    fprintf(stderr, "tinytest: no specs registered\n");
    return 1;
  }

  ttest_array__ *all_steps = ttest_array_create__();
  ttest_array__ *all_step_arrays = ttest_array_create__();
  ttest_array__ *all_roots = ttest_array_create__();
  ttest_array__ *all_nodes = ttest_array_create__();
  ttest_array__ *all_stacks = ttest_array_create__();
  ttest_array__ *all_specs = ttest_array_create__();

  bool has_focus_any = false;
  size_t total_test_count = 0;

  for (size_t s = 0; s < ttest_spec_count__; ++s) {
    ttest_spec_entry__ *spec = ttest_get_spec_entry__(s);
    if (!spec) continue;

    config.run = TTEST_INIT_RUN__;
    config.id = 0;
    config.has_focus_nodes = false;
    config.nodes = ttest_array_create__();
    config.node_stack = ttest_array_create__();

    ttest_node__ *root =
        ttest_node_create__(-1, spec->name, TTEST_NODE_GROUP__, ttest_node_flags_none__);
    ttest_array_push__(config.node_stack, root);

    config.current_spec = spec->fn;
    config.invoke_spec(&config, config.current_spec);

    if (config.has_focus_nodes) {
      has_focus_any = true;
    }

    ttest_array__ *steps = ttest_array_create__();
    ttest_node_flatten__(&config, root, steps);

    enum { TTEST_MAX_GROUP_DEPTH__ = 128 };
    ttest_test_step__ *group_stack[TTEST_MAX_GROUP_DEPTH__];
    int stack_depth = 0;

    for (size_t i = 0; i < steps->size; ++i) {
      ttest_test_step__ *step = TTEST_CAST(ttest_test_step__ *, steps->values[i]);

      while (stack_depth > 0 && group_stack[stack_depth - 1]->level >= step->level) {
        stack_depth--;
      }

      if (step->type == TTEST_NODE_GROUP__) {
        if (stack_depth < TTEST_MAX_GROUP_DEPTH__) {
          group_stack[stack_depth++] = step;
        }
      } else if (step->type == TTEST_NODE_TEST__) {
        step->full_path = ttest_build_full_path__(group_stack, stack_depth, step->name);
        ++total_test_count;
      }
    }

    ttest_array_push__(all_roots, root);
    ttest_array_push__(all_nodes, config.nodes);
    ttest_array_push__(all_stacks, config.node_stack);
    ttest_array_push__(all_step_arrays, steps);
    ttest_array_push__(all_specs, spec);

    for (size_t i = 0; i < steps->size; ++i) {
      ttest_array_push__(all_steps, steps->values[i]);
    }
  }

  if (config.list_only) {
    for (size_t i = 0; i < all_steps->size; ++i) {
      ttest_test_step__ *step = TTEST_CAST(ttest_test_step__ *, all_steps->values[i]);
      if (step->type == TTEST_NODE_GROUP__) {
        ttest_indent__(stdout, step->level);
        printf("%s\n", step->name);
      } else if (step->type == TTEST_NODE_TEST__) {
        ttest_indent__(stdout, step->level);
        const char *tag = "";
        if (step->flags & ttest_node_flags_skip__) tag = " [skip]";
        else if (step->flags & ttest_node_flags_focus__) tag = " [focus]";
        else if (step->flags & ttest_node_flags_expected_fail__) tag = " [should_fail]";
        printf("%s%s\n", step->name, tag);
      }
    }

    for (size_t i = 0; i < all_nodes->size; ++i) {
      ttest_array__ *nodes = TTEST_CAST(ttest_array__ *, all_nodes->values[i]);
      for (size_t j = 0; j < nodes->size; ++j) {
        ttest_node_free__(TTEST_CAST(ttest_node__ *, nodes->values[j]));
      }
      ttest_array_free__(nodes);
      ttest_array_free__(TTEST_CAST(ttest_array__ *, all_stacks->values[i]));
      ttest_node__ *root = TTEST_CAST(ttest_node__ *, all_roots->values[i]);
      root->name = NULL;
      ttest_node_free__(root);
    }
    for (size_t i = 0; i < all_steps->size; ++i) {
      ttest_test_step_free__(TTEST_CAST(ttest_test_step__ *, all_steps->values[i]));
    }
    for (size_t i = 0; i < all_step_arrays->size; ++i) {
      ttest_array_free__(TTEST_CAST(ttest_array__ *, all_step_arrays->values[i]));
    }
    ttest_array_free__(all_roots);
    ttest_array_free__(all_nodes);
    ttest_array_free__(all_stacks);
    ttest_array_free__(all_step_arrays);
    ttest_array_free__(all_specs);
    ttest_array_free__(all_steps);
    ttest_cleanup_specs__();
    return total_test_count == 0u ? 1 : 0;
  }

  if (config.use_tap) {
    printf("TAP version 13\n1..%zu\n", total_test_count);
  }

  config.run = TTEST_TEST_RUN__;
  config.has_focus_nodes = has_focus_any;

  for (size_t i = 0; i < all_step_arrays->size; ++i) {
    ttest_array__ *steps = TTEST_CAST(ttest_array__ *, all_step_arrays->values[i]);
    ttest_spec_entry__ *spec = TTEST_CAST(ttest_spec_entry__ *, all_specs->values[i]);
    config.current_spec = spec ? spec->fn : NULL;
    config.node_stack = TTEST_CAST(ttest_array__ *, all_stacks->values[i]);
    config.nodes = TTEST_CAST(ttest_array__ *, all_nodes->values[i]);
    for (size_t j = 0; j < steps->size; ++j) {
      ttest_test_step__ *step = TTEST_CAST(ttest_test_step__ *, steps->values[j]);
      config.node_stack->size = 1;
      config.id = 0;
      if (config.error) {
        free(config.error);
        config.error = NULL;
      }
      config.location = NULL;
      config.current_test = step;
      ttest_run__(&config);
    }
  }

  double ttest_end_time__ = ttest_get_time_ms__();
  double ttest_duration__ = (ttest_end_time__ - ttest_start_time__) / 1000.0;

  size_t passed_count = 0;
  size_t skipped_count = 0;
  size_t filtered_count = 0;
  size_t todo_count = 0;
  for (size_t i = 0; i < all_steps->size; ++i) {
    ttest_test_step__ *step = TTEST_CAST(ttest_test_step__ *, all_steps->values[i]);
    if (step->type != TTEST_NODE_TEST__) continue;
    switch (ttest_test_result_category__(step->result)) {
      case TTEST_RESULT_CATEGORY_PASS__:
        passed_count++;
        break;
      case TTEST_RESULT_CATEGORY_SKIP__:
        skipped_count++;
        break;
      case TTEST_RESULT_CATEGORY_FILTER__:
        filtered_count++;
        break;
      case TTEST_RESULT_CATEGORY_TODO__:
        todo_count++;
        break;
      default:
        break;
    }
  }

  const bool empty_cases = (total_test_count == 0u);
  const bool empty_filter = (config.filter != NULL && !empty_cases &&
                             filtered_count == total_test_count);
  if (empty_cases) fprintf(stderr, "tinytest: no test cases registered\n");
  if (empty_filter) fprintf(stderr, "tinytest: no test cases match filter '%s'\n", config.filter);

  if (!config.use_tap) {
    const char *c_rst = config.use_color ? TTEST_COLOR_RESET__ : "";
    const char *c_red = config.use_color ? TTEST_COLOR_RED__ : "";
    const char *c_grn = config.use_color ? TTEST_COLOR_GREEN__ : "";
    const char *c_ylw = config.use_color ? TTEST_COLOR_YELLOW__ : "";
    const char *c_bld = config.use_color ? TTEST_COLOR_BOLD__ : "";

    printf("\n==All Tests Summary==\n");
    printf("Total tests %s[PASSED]:\t%zu%s\n", c_grn, passed_count, c_rst);
    printf("Total tests %s[FAILED]:\t%zu%s\n", c_red, config.failed_test_count, c_rst);
    if (config.warn_count > 0) {
      printf("Total tests %s[WARNED]:\t%zu%s\n", c_ylw, config.warn_count, c_rst);
    }
    printf("Total tests %s[SKIPPED]:\t%zu%s\n", c_ylw, skipped_count, c_rst);
    printf("Total tests %s[FILTERED]:\t%zu%s\n", c_ylw, filtered_count, c_rst);
    printf("Total tests %s[TODO]:   \t%zu%s\n", c_bld, todo_count, c_rst);
    printf("Assertions: %s%zu passed%s, %s%zu failed%s\n", c_grn,
           config.assertion_count - config.assertion_failed_count, c_rst,
           config.assertion_failed_count > 0 ? c_red : "", config.assertion_failed_count, c_rst);

    printf("%zu passed, %zu failed, %zu skipped, %zu filtered, %zu todo, %zu assertions. "
           "Finished in %f sec.\n",
           passed_count, config.failed_test_count, skipped_count, filtered_count, todo_count,
           config.assertion_count, ttest_duration__);

    if (config.failed_test_count == 0 && todo_count == 0 &&
        !empty_cases && !empty_filter) {
      printf("%sAll tests passed in %f sec.%s\n\n", c_grn, ttest_duration__, c_rst);
    } else {
      printf("\n");
    }
  }

  /* Generate JUnit XML report if requested - must be done before freeing steps */
  int exit_code = (config.failed_test_count > 0 || empty_cases || empty_filter) ? 1 : 0;
  if (config.junit_file) {
    ttest_result__ junit_result = ttest_generate_junit__(&config, all_steps, total_test_count);
    if (!junit_result.ok) {
      fprintf(stderr, "Error: %s: %s\n", junit_result.message, config.junit_file);
      exit_code = 1;
    }
  }

  for (size_t i = 0; i < all_nodes->size; ++i) {
    ttest_array__ *nodes = TTEST_CAST(ttest_array__ *, all_nodes->values[i]);
    for (size_t j = 0; j < nodes->size; ++j) {
      ttest_node_free__(TTEST_CAST(ttest_node__ *, nodes->values[j]));
    }
    ttest_array_free__(nodes);
    ttest_array_free__(TTEST_CAST(ttest_array__ *, all_stacks->values[i]));
    ttest_node__ *root = TTEST_CAST(ttest_node__ *, all_roots->values[i]);
    root->name = NULL;
    ttest_node_free__(root);
  }
  for (size_t i = 0; i < all_step_arrays->size; ++i) {
    ttest_array_free__(TTEST_CAST(ttest_array__ *, all_step_arrays->values[i]));
  }
  ttest_array_free__(all_roots);
  ttest_array_free__(all_nodes);
  ttest_array_free__(all_stacks);
  ttest_array_free__(all_step_arrays);
  ttest_array_free__(all_specs);
  for (size_t i = 0; i < all_steps->size; ++i) {
    ttest_test_step_free__(TTEST_CAST(ttest_test_step__ *, all_steps->values[i]));
  }
  ttest_array_free__(all_steps);
  ttest_cleanup_specs__();

  return exit_code;
}
