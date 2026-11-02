#include <vstr.h>
#include <tinytest.h>
#include <stddef.h>
#include <string.h>

_Static_assert(offsetof(vstr, data) == 0, "borrowed data starts at byte zero");
_Static_assert(offsetof(vstr, len) == sizeof(const char *),
    "view contains only pointer and length");
_Static_assert(sizeof(vstr) == sizeof(const char *) + sizeof(size_t),
    "view has no hidden reflection metadata or owner");

spec("Core borrowed vstr") {
  it("preserves pointer-size layout and validates borrowed views") {
    const char not_terminated[3] = {'a', '\0', 'b'};
    const vstr view = vstr_from_buf(not_terminated, sizeof(not_terminated));
    const vstr empty = vstr_from_cstr(NULL);
    const vstr invalid = vstr_from_buf(NULL, 2u);
    const vstr text = vstr_from_cstr("abc");

    check(vstr_is_valid(view));
    check(view.data == not_terminated);
    check(view.len == sizeof(not_terminated));
    check(memcmp(view.data, not_terminated, view.len) == 0);
    check(vstr_is_valid(empty));
    check(empty.len == 0u);
    check(!vstr_is_valid(invalid));
    check(invalid.len == 2u);
    check(vstr_is_valid(text));
    check(text.len == 3u);
  }
}
