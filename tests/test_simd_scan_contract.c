#include <cmeta_simd_scan.h>
#include <tinytest.h>
#include <string.h>

spec("Canonical bounded byte scanning") {
  it("retains the seven-function scan semantics including NUL and boundaries") {
    const char bytes[] = {'a', '\0', 'b', '{', '}', ' ', '\t', '\r', '\n', 'c'};
    const char *end = bytes + sizeof(bytes);
    check(cmeta_scan_char(bytes, end, '\0') == bytes + 1);
    check(cmeta_scan_char(bytes, end, 'z') == NULL);
    check(cmeta_scan_to_char(bytes, end, '{') == bytes + 3);
    check(cmeta_scan_to_char(bytes, end, 'x') == end);
    check(cmeta_scan_to_any2(bytes, end, '[', '}') == bytes + 4);
    check(cmeta_scan_to_any3(bytes, end, 'x', 'y', 'b') == bytes + 2);
    check(cmeta_scan_skip_sp_tab(bytes + 5, end) == bytes + 7);
    check(cmeta_scan_skip_sp_tab_cr_lf(bytes + 5, end) == bytes + 9);
    check(cmeta_scan_mem(bytes, sizeof(bytes), "b{", 2) == bytes + 2);
    check(cmeta_scan_mem(bytes, sizeof(bytes), "missing", 7) == NULL);
    check(cmeta_scan_mem(bytes, sizeof(bytes), "", 0) == bytes);
    check(cmeta_scan_mem(NULL, 0, "", 0) == NULL);
    char buffer[128];
    memset(buffer, 'a', sizeof(buffer));
    buffer[127] = 'z';
    check(cmeta_scan_char(buffer, buffer + sizeof(buffer), 'z') == buffer + 127);
    check(cmeta_scan_to_any2(buffer, buffer + sizeof(buffer), 'x', 'z') == buffer + 127);
    check(cmeta_scan_to_any3(buffer, buffer + sizeof(buffer), 'x', 'y', 'z') == buffer + 127);
  }
}
