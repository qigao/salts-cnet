#include <capture.h>
#include <tinytest.hpp>
#include <type_traits>

static_assert(std::is_standard_layout<salts_video_frame_v2_t>::value, "C frame ABI");
static_assert(std::is_standard_layout<salts_video_frame_plane_t>::value, "C plane ABI");

suite("CPU frame C++17 public interface") {
    it("links the additive callback setter through its real C ABI") {
        int (*setter)(salts_capture_t *, salts_video_capture_cb_v2, void *) =
            &salts_video_capture_set_callback_v2;
        check_equal(setter(nullptr, nullptr, nullptr), SALTS_CAPTURE_ERR_FORMAT);
        salts_video_frame_v2_t frame{};
        check_equal(frame.plane_count, 0u);
    }
}
