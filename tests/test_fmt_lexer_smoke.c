#include <fmt_lexer.h>
#include <tinytest.h>
#include <string.h>

spec("Original format lexer") {
  it("scans text, specifiers, end markers and escaped braces") {
    const char raw[6] = {'a', '{', ':', '0', '4', '}'};
    const char *cursor = raw;
    vstr tok = vstr_from_buf(NULL, 0);
    check(fmt_scan_v_n(&cursor, raw + sizeof(raw), &tok) == FMT_TOKEN_TEXT &&
          tok.len == 1u && tok.data[0] == 'a');
    check(fmt_scan_v_n(&cursor, raw + sizeof(raw), &tok) == FMT_TOKEN_SPECIFIER &&
          tok.len == 2u && memcmp(tok.data, "04", 2u) == 0);
    check(fmt_scan_v_n(&cursor, raw + sizeof(raw), &tok) == FMT_TOKEN_END);
    const char *input = "{{}}";
    cursor = input;
    check(fmt_scan_v(&cursor, &tok) == FMT_TOKEN_LBRACE_ESC);
    check(fmt_scan_v(&cursor, &tok) == FMT_TOKEN_RBRACE_ESC);
  }
}
