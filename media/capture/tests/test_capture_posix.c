#include <capture.h>
#include <tinytest.h>

suite("POSIX capture integration") {
  it("rejects invalid enumeration buffers") {
    salts_capture_device_t device;

    check_equal(salts_capture_list_audio_devices(NULL, 1), -1);
    check_equal(salts_capture_list_video_devices(NULL, 1), -1);
    check_equal(salts_capture_list_screens(NULL, 1), -1);
    check_equal(salts_capture_list_gpu_devices(NULL, 1), -1);
    check_equal(salts_capture_list_audio_devices(&device, 0), -1);
    check_equal(salts_capture_list_video_devices(&device, 0), -1);
    check_equal(salts_capture_list_screens(&device, 0), -1);
    check_equal(salts_capture_list_gpu_devices(&device, 0), -1);
  }

  it("reports device absence without exceeding caller capacity") {
    salts_capture_device_t devices[SALTS_CAPTURE_MAX_DEVICES];
    int audio_count = salts_capture_list_audio_devices(
        devices, SALTS_CAPTURE_MAX_DEVICES);
    int video_count = salts_capture_list_video_devices(
        devices, SALTS_CAPTURE_MAX_DEVICES);
    int screen_count = salts_capture_list_screens(
        devices, SALTS_CAPTURE_MAX_DEVICES);

    check_greater_equal(audio_count, 0);
    check_less_equal(audio_count, SALTS_CAPTURE_MAX_DEVICES);
    check_greater_equal(video_count, 0);
    check_less_equal(video_count, SALTS_CAPTURE_MAX_DEVICES);
    check_greater_equal(screen_count, 0);
    check_less_equal(screen_count, SALTS_CAPTURE_MAX_DEVICES);
  }

  it("rejects an unknown explicit audio device without fallback") {
    check_null(salts_audio_capture_create("not-a-capture-device", NULL));
  }

  it("rejects unsupported audio PCM formats without coercion") {
    salts_audio_capture_config_t config = {48000, 1, 24, 20};
    check_null(salts_audio_capture_create(NULL, &config));
  }

  it("makes null lifecycle operations safe and deterministic") {
    check_equal(salts_capture_start(NULL), -1);
    check_equal(salts_capture_get_state(NULL), SALTS_CAPTURE_STATE_STOPPED);
    salts_capture_stop(NULL);
    salts_capture_destroy(NULL);
  }
}
