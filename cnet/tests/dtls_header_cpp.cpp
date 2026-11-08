#include <cnet/dtls.h>
#include <tinytest.hpp>
#include <type_traits>

static_assert(
    std::is_same_v<decltype(&cnet_dtls_destroy), int (*)(cnet_dtls *)>);
static_assert(std::is_same_v<decltype(&crypto_dtls_stream_destroy),
                             int (*)(crypto_dtls_stream *)>);
static_assert(std::is_same_v<decltype(&crypto_dtls_listener_destroy),
                             int (*)(crypto_dtls_listener *)>);

spec("C++17 DTLS declarations and empty-owner lifetime") {
  it("links the C owner and rejects progress on an uninitialized instance") {
    cnet_dtls stream{};
    cnet_dtls_info info{};
    size_t events = 0;
    check_equal(cnet_dtls_destroy(&stream), SALTS_OK);
    check_equal(cnet_dtls_accept(&stream, nullptr, nullptr, 0), SALTS_EINVAL);
    check_equal(cnet_dtls_listener_destroy(nullptr), SALTS_OK);
    check_equal(cnet_dtls_get_info(&stream, &info), SALTS_EINVAL);
    check_equal(cnet_dtls_advance(&stream, 0, &events), SALTS_EINVAL);
    check_equal(cnet_dtls_send(&stream, nullptr, 0, 1), SALTS_EINVAL);
    check_equal(cnet_dtls_abort(&stream), SALTS_EINVAL);
    check_equal(cnet_dtls_destroy(&stream), SALTS_OK);
  }
}
