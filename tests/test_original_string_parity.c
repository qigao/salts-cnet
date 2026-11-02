#include <tstr.h>
#include <str.h>
#include <memory_pool.h>
#include <cmeta_buffer.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <tinytest.h>

spec("Original tstr/vstr and memory pool parity") {
  it("retains borrow, allocation, UTF-8, matching, mutation and ownership semantics") {
  const char raw[3] = {'a', 0, 'b'};
  tstr s = tstr_dup_len(raw, sizeof(raw));
  check(s && tstr_len(s) == sizeof(raw));
  check(memcmp(s, raw, sizeof(raw)) == 0);
  vstr view = tstr_view(s);
  check(view.data == s && view.len == 3);
  check(vstr_eq(view, vstr_from_buf(raw, sizeof(raw))));
  check(!vstr_is_valid(vstr_from_buf(NULL, 4u)));
  tstr copy = tstr_clone(s);
  check(copy && copy != s && tstr_len(copy) == 3);
  tstr_free(copy);
  s = tstr_cat_len(s, raw, sizeof(raw));
  check(s && tstr_len(s) == 6 && tstr_find_v(s, vstr_from_buf(raw, 3)) == 0);
  check(tstr_rfind_v(s, vstr_from_buf(raw, 3)) == 3);
  tstr_free(s);

  s = tstr_dup("  AbC abc  ");
  check(s);
  s = tstr_trim(s, " ");
  check(s && strcmp(s, "AbC abc") == 0);
  check(tstr_count_v(s, VSTR_LIT("bc")) == 1);
  tstr_lower(s);
  check(strcmp(s, "abc abc") == 0);
  tstr_upper(s);
  check(strcmp(s, "ABC ABC") == 0);
  s = tstr_replace_all(s, "ABC", "xy");
  check(s && strcmp(s, "xy xy") == 0);
  check(tstr_append(&s, VSTR_LIT("!")) && strcmp(s, "xy xy!") == 0);
  check(tstr_reserve_capacity(&s, 128));
  check(tstr_capacity(s) >= 128);
  check(vstr_ieq(VSTR_LIT("ABC"), VSTR_LIT("aBc")));
  check(vstr_find_any(VSTR_LIT("abc"), VSTR_LIT("xyb")) == 1);
  tstr moved = tstr_move(&s);
  check(!s && moved && strcmp(moved, "xy xy!") == 0);
  tstr_free(moved);

  s = tstr_dup("A\xE2\x82\xAC\xF0\x9F\x8C\x8D");
  check(s && tstr_utf8_valid(s) && tstr_utf8_len(s) == 3);
  check(tstr_utf8_nlen(s, 2) == VSTR_NPOS);
  check(tstr_utf8_find_cp(s, 0x20ACu) == 1);
  tstr subset = tstr_utf8_slice(s, 1, 2);
  check(subset && tstr_utf8_len(subset) == 2);
  tstr_free(subset);
  tstr_free(s);
  s = tstr_dup_len("\xC0\x80", 2);
  check(s && !tstr_utf8_valid(s) && tstr_utf8_invalid_offset(s) == 0);
  tstr_free(s);

  vstr trimmed = vstr_trim(VSTR_LIT("..HELLO.."), ".");
  check(vstr_eq(trimmed, VSTR_LIT("HELLO")));
  vstr input = VSTR_LIT("left:right");
  vstr first = vstr_split_next(&input, VSTR_LIT(":"));
  check(vstr_eq(first, VSTR_LIT("left")) && vstr_eq(input, VSTR_LIT("right")));
  char *heap = vstr_to_cstr(VSTR_LIT("view"));
  check(heap && strcmp(heap, "view") == 0);
  free(heap);
  MemoryPool *pool = pool_create(512);
  check(pool);
  char *pooled = vstr_to_pool(VSTR_LIT("pool"), pool);
  check(pooled && strcmp(pooled, "pool") == 0);
  pool_destroy(pool);
  mem_pool_t *arena = mem_global();
  check(arena);
  char *arena_text = vstr_to_arena(VSTR_LIT("arena"), arena);
  check(arena_text && strcmp(arena_text, "arena") == 0);
  mem_free(arena, arena_text);
  }
}
