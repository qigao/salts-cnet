#include <tinytest.h>
#include <cmeta_error.h>
#include <cmeta_zstd.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "Zstd native contract failed at line %d: %s\n", \
            __LINE__, #condition); \
    return 1; \
  } \
} while (0)

static int saltscore_legacy_zstd_native_contract_c(void) {
  /* Standard raw-block frames, constructed from the pinned provider's
   * doc/zstd_compression_format.md. Each payload is exactly 00 80 ff.
   * Unknown-size: no single-segment flag, 1 KiB window, no content size.
   * Known-size: single segment, declared size 3. Block 0x19 is last/raw/3. */
  static const unsigned char unknown_size[] = {
      0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x80, 0xff};
  static const unsigned char known_size[] = {
      0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x03, 0x19, 0x00, 0x00, 0x00, 0x80, 0xff};
  static const unsigned char payload[] = {0x00, 0x80, 0xff};
  /* Eight-byte declared content size 2^32; query it without allocating it. */
  static const unsigned char wide_header[] = {
      0x28, 0xb5, 0x2f, 0xfd, 0xe0,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
  unsigned char destination[8];
  unsigned char concatenated[sizeof(known_size) * 2u];
  size_t result = 91u;

  REQUIRE(cmeta_zstd_frame_content_size(unknown_size, sizeof(unknown_size),
                                        &result) == SALTS_ENOTSUP);
  REQUIRE(result == 91u);
  memset(destination, 0xa5, sizeof(destination));
  REQUIRE(cmeta_zstd_decompress(destination + 1u, sizeof(payload), &result,
                                unknown_size, sizeof(unknown_size)) == SALTS_OK);
  REQUIRE(result == sizeof(payload));
  REQUIRE(memcmp(destination + 1u, payload, sizeof(payload)) == 0);
  REQUIRE(destination[0] == 0xa5 && destination[4] == 0xa5);

  result = 92u;
  REQUIRE(cmeta_zstd_decompress(destination, sizeof(destination), &result,
                                unknown_size, sizeof(unknown_size) - 1u) == SALTS_EPROTO);
  REQUIRE(result == 92u);
  REQUIRE(cmeta_zstd_decompress(destination, 2u, &result,
                                unknown_size, sizeof(unknown_size)) == SALTS_ENOSPC);
  REQUIRE(result == 92u);

  /* This original API reads the frame header; it does not validate the body.
   * Keep that distinction from the decompressor's complete-frame requirement. */
  REQUIRE(cmeta_zstd_frame_content_size(known_size, 6u, &result) == SALTS_OK);
  REQUIRE(result == sizeof(payload));
  result = 93u;
  REQUIRE(cmeta_zstd_decompress(destination, sizeof(destination), &result,
                                known_size, 6u) == SALTS_EPROTO);
  REQUIRE(result == 93u);

  /* Original ZSTD_decompress forwarding also accepts concatenated frames.
   * The content-size query still reports only the first frame's declaration. */
  memcpy(concatenated, known_size, sizeof(known_size));
  memcpy(concatenated + sizeof(known_size), known_size, sizeof(known_size));
  REQUIRE(cmeta_zstd_frame_content_size(concatenated, sizeof(concatenated),
                                        &result) == SALTS_OK);
  REQUIRE(result == sizeof(payload));
  memset(destination, 0xa5, sizeof(destination));
  REQUIRE(cmeta_zstd_decompress(destination + 1u, sizeof(payload) * 2u, &result,
                                concatenated, sizeof(concatenated)) == SALTS_OK);
  REQUIRE(result == sizeof(payload) * 2u);
  REQUIRE(memcmp(destination + 1u, payload, sizeof(payload)) == 0);
  REQUIRE(memcmp(destination + 1u + sizeof(payload), payload, sizeof(payload)) == 0);
  REQUIRE(destination[0] == 0xa5 && destination[7] == 0xa5);

  result = 94u;
#if SIZE_MAX < UINT64_C(4294967296)
  REQUIRE(cmeta_zstd_frame_content_size(wide_header, sizeof(wide_header),
                                        &result) == SALTS_ERANGE);
  REQUIRE(result == 94u);
#else
  REQUIRE(cmeta_zstd_frame_content_size(wide_header, sizeof(wide_header),
                                        &result) == SALTS_OK);
  REQUIRE(result == (size_t)UINT64_C(4294967296));
#endif
  return 0;
}

spec("Core pinned Zstd byte-exact ownership and decompression") {
  it("runs all original source assertions and preserves exit status") {
    const int result = saltscore_legacy_zstd_native_contract_c();
    check(result == 0, "original native contract returned %d", result);
  }
}
