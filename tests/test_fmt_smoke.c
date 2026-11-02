#include <fmt.h>
#include <tinytest.h>
#include <string.h>

spec("Original format rendering and type contracts") {
  it("formats bounded ASCII, counted views and canonical type names") {
    char buffer[64] = {0};
    fmt_arg_t args[] = {fmt_arg_int(7), fmt_arg_uint(15u)};
    check(fmt_print(buffer, sizeof(buffer), "n={} x={:04X}", args, 2) == 10);
    check(strcmp(buffer, "n=7 x=000F") == 0);
    const char bytes[] = {'[', '{', '}', ']'};
    fmt_arg_t item = fmt_arg_int(42);
    check(fmt_print_v(buffer, sizeof(buffer),
          vstr_from_buf(bytes, sizeof(bytes)), &item, 1) == 4);
    check(strcmp(buffer, "[42]") == 0);
    fmt_type_t kind = FMT_TYPE_NONE;
    check(fmt_type_t_from_string("FMT_TYPE_STR", &kind));
    check(kind == FMT_TYPE_STR);
    check(strcmp(fmt_type_t_to_string(kind), "str") == 0);
    tstr text = fmt_print_tstr(NULL, "a={}", args, 1);
    check(text != NULL && strcmp(text, "a=7") == 0);
    tstr_free(text);
  }
}
