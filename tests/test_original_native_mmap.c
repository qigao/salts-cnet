/* Original qigao/salts native mmap contract restored into Salts::Core.
 * This test exercises real file mapping, non-page-aligned ranges, dirty
 * flushes, page accounting, owner closure and contiguous multi-file maps.
 * No CMeta reflection/runtime, fallback provider or mock backing memory.
 */
#include <tinytest.h>
#include "cmeta_mmap.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
  fprintf(stderr, "native mmap FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
  return 1; \
} } while (0)

static int make_file(const char *path, unsigned char first)
{
    FILE *f = fopen(path, "wb");
    unsigned char data[8192];
    size_t i;
    if (!f) return 0;
    for (i = 0u; i < sizeof(data); ++i)
        data[i] = (unsigned char)(first + (unsigned char)(i % 15u));
    if (fwrite(data, 1u, sizeof(data), f) != sizeof(data)) {
        fclose(f);
        return 0;
    }
    return fclose(f) == 0;
}

static int original_mmap_native_contract(void)
{
    const char *one = "saltscore-native-mmap-original-a.bin";
    const char *two = "saltscore-native-mmap-original-b.bin";
    const char *paths[] = { one, two };
    cmeta_mmap_t view;
    cmeta_mmap_group_t group;
    unsigned char result[16];
    FILE *f;
    size_t i;
    size_t page = cmeta_mmap_page_size();
    int lock_result;

    CHECK(page >= 1024u);
    CHECK(cmeta_mmap_page_count(0u) == 0u);
    CHECK(cmeta_mmap_page_count(page + 1u) == 2u);
    CHECK(cmeta_mmap_pages(NULL) == 0u);
    CHECK(cmeta_mmap_open(NULL, one, SALTS_MMAP_READ) == SALTS_MMAP_EINVAL);
    CHECK(cmeta_mmap_open_range(NULL, one, 0, 1u, SALTS_MMAP_READ)
          == SALTS_MMAP_EINVAL);
    CHECK(cmeta_mmap_sync(NULL, false) == SALTS_MMAP_EINVAL);
    CHECK(cmeta_mmap_advise(NULL, SALTS_MMAP_NORMAL) == SALTS_MMAP_EINVAL);
    CHECK(cmeta_mmap_lock(NULL) == SALTS_MMAP_EINVAL);
    CHECK(cmeta_mmap_unlock(NULL) == SALTS_MMAP_EINVAL);
    CHECK(cmeta_mmap_from_fd(NULL, 0, 0, 0u, SALTS_MMAP_READ)
          == SALTS_MMAP_EINVAL);
    CHECK(strcmp(cmeta_mmap_strerror(SALTS_MMAP_EINVAL), "Invalid argument") == 0);
    CHECK(strcmp(cmeta_mmap_strerror(700), "Unknown error") == 0);

    cmeta_mmap_init(&view);
    CHECK(cmeta_mmap_open(&view, "__nonexistent_saltscore_mmap_test_123.bin",
                          SALTS_MMAP_READ) == SALTS_MMAP_ENOENT);
    CHECK(!view.is_mapped);
    CHECK(make_file(one, 0x30u));
    CHECK(make_file(two, 0x50u));

    CHECK(cmeta_mmap_open_range(&view, one, 7, 123u, SALTS_MMAP_READ)
          == SALTS_MMAP_OK);
    CHECK(view.is_mapped && view.length == 123u && view.offset == 7);
    CHECK(((const unsigned char *)view.data)[0] == (unsigned char)(0x30u + 7u));
    CHECK(cmeta_mmap_pages(&view) == 1u);
    CHECK(cmeta_mmap_open_range(&view, two, 0, 1u, SALTS_MMAP_READ)
          == SALTS_MMAP_EEXIST);
    CHECK(cmeta_mmap_sync_range(&view, 0u, 124u, false) == SALTS_MMAP_EINVAL);
    CHECK(cmeta_mmap_advise(&view, SALTS_MMAP_SEQUENTIAL) == SALTS_MMAP_OK);
    lock_result = cmeta_mmap_lock(&view);
    CHECK(lock_result == SALTS_MMAP_OK || lock_result == SALTS_MMAP_EIO);
    if (lock_result == SALTS_MMAP_OK)
        CHECK(cmeta_mmap_unlock(&view) == SALTS_MMAP_OK);
    cmeta_mmap_unmap(&view);
    CHECK(!view.is_mapped);
    CHECK(cmeta_mmap_sync(&view, false) == SALTS_MMAP_EINVAL);
    cmeta_mmap_close(&view);
    cmeta_mmap_close(&view);

    CHECK(cmeta_mmap_open(&view, one, SALTS_MMAP_WRITE) == SALTS_MMAP_OK);
    CHECK(view.length == 8192u);
    CHECK(((unsigned char *)view.data)[11] == (unsigned char)(0x30u + 11u));
    ((unsigned char *)view.data)[11] = (unsigned char)0xEAu;
    CHECK(cmeta_mmap_sync(&view, false) == SALTS_MMAP_OK);
    CHECK(cmeta_mmap_sync_range(&view, 0u, 64u, false) == SALTS_MMAP_OK);
    cmeta_mmap_close(&view);

    f = fopen(one, "rb");
    CHECK(f != NULL);
    CHECK(fseek(f, 11L, SEEK_SET) == 0);
    CHECK(fread(result, 1u, 1u, f) == 1u);
    CHECK(fclose(f) == 0);
    CHECK(result[0] == 0xEAu);

    cmeta_mmap_group_init(&group);
    CHECK(cmeta_mmap_group_open(NULL, paths, 2u, SALTS_MMAP_READ)
          == SALTS_MMAP_EINVAL);
    CHECK(cmeta_mmap_group_open(&group, paths, 0u, SALTS_MMAP_READ)
          == SALTS_MMAP_EINVAL);
#if !defined(_WIN32)
    /* The original Windows MapViewOfFileEx multi-view reservation policy
     * must have separate Windows native parity before being claimed green.
     */
    CHECK(cmeta_mmap_group_open(&group, paths, 2u, SALTS_MMAP_READ)
          == SALTS_MMAP_OK);
    CHECK(group.count == 2u);
    CHECK(group.mappings != NULL && group.data != NULL);
    CHECK(((unsigned char *)group.mappings[0].data)[11] == 0xEAu);
    CHECK(((unsigned char *)group.mappings[1].data)[0] == 0x50u);
    CHECK(group.total_size >= 16384u);
    cmeta_mmap_group_close(&group);
    CHECK(group.count == 0u && group.mappings == NULL);
#else
    /* Never treat an unqualified multi-file Windows placement as proven. */
    cmeta_mmap_group_close(&group);
#endif

    /* Original opaque owner accepts an empty group cleanup. */
    cmeta_mmap_group_close(&group);
    CHECK(remove(one) == 0);
    CHECK(remove(two) == 0);
    for (i = 0u; i < sizeof(result); ++i) result[i] = 0u;
    CHECK(result[0] == 0u);
    puts("PASS original native mmap owner, range, flush, page and group mapping");
    return 0;
}

static int saltscore_original_entry_test_original_native_mmap_c(void) {
    return original_mmap_native_contract();
}

spec("Core real mmap range flush and owner lifetimes") {
  it("preserves the real owner lifecycle and original failure code") {
    const int result = saltscore_original_entry_test_original_native_mmap_c();
    check(result == 0, "native integration returned %d", result);
  }
}
