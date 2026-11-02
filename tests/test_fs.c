#include <tinytest.h>
#include <fs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
static int saltscore_legacy_test_fs_c(void) {
  char tmp[1024] = {0}, path[1400] = {0}, name[120] = {0};
  const char body[] = "salts core fs native\n";
  salts_fs_buf_t input = salts_fs_buf_init((char *)body, sizeof(body) - 1u);
  salts_fs_buf_t output = {0};
  salts_fs_root_t *root = NULL;
  salts_fs_root_file_t *file = NULL;
  char scratch[128] = {0};
  int bytes;
#ifdef _WIN32
  unsigned long pid = GetCurrentProcessId();
#else
  unsigned long pid = (unsigned long)getpid();
#endif
  if (salts_fs_get_tmpdir(tmp, sizeof(tmp))) return 1;
  if (snprintf(name, sizeof(name), "saltscore-fs-%lu", pid) < 0) return 2;
  if (salts_fs_path_join(path, sizeof(path), tmp, name)) return 3;
  if (salts_fs_write_file(path, &input)) return 4;
  if (salts_fs_read_file(path, &output)) return 5;
  if (output.len != sizeof(body) - 1u ||
      memcmp(output.base, body, sizeof(body) - 1u)) return 6;
  salts_fs_buf_free(&output);
  if (salts_fs_root_open(tmp, &root) || !root) return 7;
  if (salts_fs_root_file_open(root, name, SALTS_FS_O_RDONLY, 0, &file) || !file)
    return 8;
  bytes = salts_fs_root_file_read(file, scratch, sizeof(scratch));
  if (bytes != (int)(sizeof(body) - 1u) ||
      memcmp(scratch, body, sizeof(body) - 1u)) return 9;
  if (salts_fs_root_file_close(file)) return 10;
  file = NULL;
  if (salts_fs_root_file_open(root, "../forbidden", SALTS_FS_O_RDONLY, 0, &file) == 0 ||
      file != NULL) return 11;
  if (salts_fs_root_close(root)) return 12;
  if (salts_fs_unlink(path)) return 13;
  puts("Salts::FS root ownership and path rejection PASS");
  return 0;
}

spec("Core real FS root and path exclusion") {
  it("runs all original source assertions and preserves exit status") {
    const int result = saltscore_legacy_test_fs_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
