/* Original tn_base64_* contract, plus strict caller-owned counted byte ABI. */
#include <base64_utils.h>
#include <tinytest.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_vectors(void) {
  static const char *const raw[] = {
    "", "f", "fo", "foo", "foob", "fooba", "foobar", "TurboUtils"
  };
  static const char *const canonical[] = {
    "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy",
    "VHVyYm9VdGlscw=="
  };
  for (size_t i = 0u; i < sizeof(raw) / sizeof(raw[0]); ++i) {
    char out[64] = {0};
    char *heap = NULL;
    size_t size = 0u, actual = 0u;
    uint8_t decoded[64] = {0};
    check(tn_base64_encode_buf_ex((const uint8_t *)raw[i], strlen(raw[i]),
                                  out, sizeof(out)) == TN_BASE64_OK);
    check(strcmp(out, canonical[i]) == 0);
    check(tn_base64_encode((const uint8_t *)raw[i], strlen(raw[i]), &heap) == 0);
    check(heap != NULL && strcmp(heap, canonical[i]) == 0);
    free(heap);
    check(tn_base64_decode_buf_ex(canonical[i], strlen(canonical[i]),
                                  NULL, 0u, &size) == TN_BASE64_OK);
    check(size == strlen(raw[i]));
    check(tn_base64_decode_buf_ex(canonical[i], strlen(canonical[i]),
                                  decoded, sizeof(decoded), &actual) == TN_BASE64_OK);
    check(actual == size && memcmp(decoded, raw[i], size) == 0);
    if (i != 0u) {
      uint8_t *allocated = NULL;
      size_t written = 0u;
      check(tn_base64_decode(canonical[i], &allocated, &written) == 0);
      check(allocated != NULL && written == size &&
            memcmp(allocated, raw[i], size) == 0);
      free(allocated);
    }
  }
}

static void test_binary_folding(void) {
  const uint8_t bytes[] = {0u, 255u, 1u, 2u, 0u, 125u};
  char encoded[32] = {0};
  uint8_t decoded[16] = {0};
  size_t len = 0u;
  check(tn_base64_encode_buf(bytes, sizeof(bytes), encoded, sizeof(encoded)) == 0);
  check(tn_base64_decode_buf_ex(encoded, strlen(encoded), decoded,
                                sizeof(decoded), &len) == TN_BASE64_OK);
  check(len == sizeof(bytes) && memcmp(decoded, bytes, len) == 0);
  check(tn_base64_decode_buf_ex(" Zm9v\r\nYmFy \t", sizeof(" Zm9v\r\nYmFy \t") - 1u, decoded,
                                sizeof(decoded), &len) == TN_BASE64_OK);
  check(len == 6u && memcmp(decoded, "foobar", len) == 0);
  check(tn_base64_decode_buf_ex("AA==", 4u, decoded, sizeof(decoded),
                                &len) == TN_BASE64_OK);
  check(len == 1u && decoded[0] == 0u);
}

static void test_rejects_invalid_input_atomically(void) {
  static const char *const invalid[] = {
    "Zg=", "Zg===", "=m9v", "Zg=a", "Zg==Zg==",
    "Zm9v=", "Zh==", "Zm9=", "not valid base64!", "Zg\xFF==",
    "A", "AA", "AAA", "AA=A", "A===", "AAAA\nB"
  };
  for (size_t i = 0u; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    uint8_t buf[32];
    size_t len = 817u;
    memset(buf, 0xA5, sizeof(buf));
    check(tn_base64_decode_buf_ex(invalid[i], strlen(invalid[i]), buf,
                                  sizeof(buf), &len) == TN_BASE64_ERR_INVALID_INPUT);
    check(len == 817u);
    for (size_t j = 0u; j < sizeof(buf); ++j) check(buf[j] == 0xA5);
  }
  {
    const char embedded[] = {'Z', 'g', '\0', '=', '='};
    size_t len = 37u;
    check(tn_base64_decode_buf_ex(embedded, sizeof(embedded), NULL, 0u, &len)
          == TN_BASE64_ERR_INVALID_INPUT);
    check(len == 37u);
  }
}

static void test_errors_no_buffer_mutation(void) {
  unsigned char byte = (unsigned char)'f';
  char output[5] = {'!', '!', '!', '!', '!'};
  size_t written = 777u;
  uint8_t data[5] = {0xDD, 0xDD, 0xDD, 0xDD, 0xDD};
  check(tn_base64_encode_buf_ex(&byte, 1u, output, 4u)
        == TN_BASE64_ERR_BUFFER_TOO_SMALL);
  check(output[0] == '!' && output[4] == '!');
  check(tn_base64_encode_buf_ex(&byte, SIZE_MAX, output, sizeof(output))
        == TN_BASE64_ERR_OVERFLOW);
  check(output[0] == '!');
  check(tn_base64_decode_buf_ex("Zg==", 4u, data, 0u, &written)
        == TN_BASE64_ERR_BUFFER_TOO_SMALL);
  check(written == 777u && data[0] == 0xDD);
  check(tn_base64_decode_buf_ex("Zg==", 4u, NULL, 3u, &written)
        == TN_BASE64_ERR_INVALID_ARG);
  check(tn_base64_decode_buf_ex(NULL, 1u, data, sizeof(data), &written)
        == TN_BASE64_ERR_INVALID_ARG);
  check(tn_base64_decode_buf_ex("Zg==", 4u, data, sizeof(data), NULL)
        == TN_BASE64_ERR_INVALID_ARG);
  check(tn_base64_encode_ex(NULL, 10u).error == TN_BASE64_ERR_INVALID_ARG);
  check(!tn_base64_decode_ex("!!").ok);
  {
    char *encoded = (char *)(uintptr_t)1u;
    uint8_t *decoded = (uint8_t *)(uintptr_t)1u;
    size_t size = 0u;
    check(tn_base64_encode(NULL, 4u, &encoded) == -1 && encoded == NULL);
    check(tn_base64_decode("invalid*data", &decoded, &size) == -1);
    check(decoded == NULL && size == 0u);
  }
  check(tn_base64_encode_buf_ex(NULL, 0u, output, sizeof(output)) == TN_BASE64_OK);
  check(output[0] == '\0');
}

spec("Canonical tn_base64 single owner") {
  it("round-trips the RFC-style canonical string vectors") { test_vectors(); }
  it("round-trips binary bytes and folded encoded input") { test_binary_folding(); }
  it("rejects malformed input without touching output") { test_rejects_invalid_input_atomically(); }
  it("preserves caller buffers on allocation and argument errors") { test_errors_no_buffer_mutation(); }
}
