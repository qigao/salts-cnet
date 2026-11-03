#include <capture.h>
#include <playback.h>
#include <tinytest.h>

suite("single static Media archive") {
  it("links Capture and Playback C11 APIs in the same binary") {
    check_equal(salts_capture_get_state(NULL), SALTS_CAPTURE_STATE_STOPPED);
    check_equal(salts_playback_get_state(NULL), SALTS_PLAYBACK_STATE_ERROR);
    check_equal(salts_capture_start(NULL), -1);
    check_equal(salts_playback_start(NULL), SALTS_PLAYBACK_ERR_FORMAT);
  }
}
