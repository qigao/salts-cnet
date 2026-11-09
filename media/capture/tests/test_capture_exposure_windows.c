/* Test the production entry points without opening or changing a real camera. */
#include "../src/capture_video_win32.c"
#include <tinytest.h>
#include <playback.h>

static const salts_camera_control_t auto_exposure = SALTS_CAMERA_CONTROL_AUTO_EXPOSURE;

static unsigned frame_legacy_count, frame_v2_count, frame_error_count;
static const uint8_t *frame_expected_data;
static void legacy_frame(salts_capture_t *capture, const uint8_t *data, size_t size,
    int w, int h, uint64_t timestamp, void *user) {
    (void)capture; (void)data; (void)size; (void)w; (void)h; (void)timestamp;
    ++*(unsigned *)user;
}
static void described_frame(salts_capture_t *capture, const salts_video_frame_v2_t *frame, void *user) {
    (void)capture;
    ++*(unsigned *)user;
    check(frame->planes[0].data == frame_expected_data);
    check_equal(frame->planes[0].size, 16u);
    check_equal(frame->format, SALTS_VIDEO_FRAME_BGRA);
    check_equal(frame->clock, SALTS_VIDEO_FRAME_CLOCK_MF_PRESENTATION);
}
static void frame_error(salts_capture_t *capture, salts_capture_state_t state, void *user) {
    (void)capture; (void)user;
    check_equal(state, SALTS_CAPTURE_STATE_ERROR);
    ++frame_error_count;
}

typedef struct {
    IAMCameraControl iface;
    long exposure;
    long flags;
    long caps;
    HRESULT range_result;
    HRESULT get_result;
    HRESULT set_result;
    int sets;
} exposure_device_t;

static HRESULT STDMETHODCALLTYPE device_range(IAMCameraControl *iface, long property,
    long *minimum, long *maximum, long *step, long *initial, long *caps) {
    exposure_device_t *device = (exposure_device_t *)iface;
    if (property != CameraControl_Exposure) return E_INVALIDARG;
    if (FAILED(device->range_result)) return device->range_result;
    *minimum = -12; *maximum = -2; *step = 1; *initial = -6; *caps = device->caps;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE device_set(IAMCameraControl *iface, long property,
                                            long value, long flags) {
    exposure_device_t *device = (exposure_device_t *)iface;
    ++device->sets;
    if (property != CameraControl_Exposure || value < -12 || value > -2)
        return E_INVALIDARG;
    if (FAILED(device->set_result)) return device->set_result;
    device->exposure = value;
    device->flags = flags;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE device_get(IAMCameraControl *iface, long property,
                                            long *value, long *flags) {
    exposure_device_t *device = (exposure_device_t *)iface;
    if (property != CameraControl_Exposure) return E_INVALIDARG;
    if (FAILED(device->get_result)) return device->get_result;
    *value = device->exposure; *flags = device->flags;
    return S_OK;
}

static IAMCameraControlVtbl device_vtable = {
    .GetRange = device_range, .Set = device_set, .Get = device_get
};

suite("Windows automatic exposure") {
    static exposure_device_t device;
    static mf_video_capture_ctx_t context;
    static salts_capture_t camera;

    before_each() {
        memset(&device, 0, sizeof(device));
        memset(&context, 0, sizeof(context));
        memset(&camera, 0, sizeof(camera));
        device.iface.lpVtbl = &device_vtable;
        device.exposure = -7;
        device.flags = CameraControl_Flags_Manual;
        device.caps = CameraControl_Flags_Auto | CameraControl_Flags_Manual;
        context.camera_control = &device.iface;
        camera.type = SALTS_CAPTURE_TYPE_VIDEO;
        camera.platform_ctx = &context;
    }

    it("switches both modes while retaining current exposure") {
        int mode = -1;
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 1), SALTS_CAPTURE_OK);
        check_equal(device.flags, (long)CameraControl_Flags_Auto);
        check_equal(device.exposure, -7L);
        check_equal(salts_video_capture_get_control(&camera, auto_exposure, &mode), SALTS_CAPTURE_OK);
        check_equal(mode, 1);
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 0), SALTS_CAPTURE_OK);
        check_equal(device.flags, (long)CameraControl_Flags_Manual);
        check_equal(device.exposure, -7L);
        check_equal(salts_video_capture_get_control(&camera, auto_exposure, &mode), SALTS_CAPTURE_OK);
        check_equal(mode, 0);
    }

    it("reports mode bounds from capabilities and current mode from the driver") {
        salts_camera_control_range_t range;
        device.flags = CameraControl_Flags_Auto;
        check_equal(salts_video_capture_get_control_range(&camera, auto_exposure, &range), SALTS_CAPTURE_OK);
        check_equal(range.min_value, 0);
        check_equal(range.max_value, 1);
        check_equal(range.step, 1);
        check_equal(range.default_value, -1);
        check_equal(range.current_value, 1);
        device.caps = CameraControl_Flags_Auto;
        check_equal(salts_video_capture_get_control_range(&camera, auto_exposure, &range), SALTS_CAPTURE_OK);
        check_equal(range.min_value, 1);
        check_equal(range.max_value, 1);
    }

    it("rejects nonboolean values without writing the driver") {
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, -1), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 2), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(device.sets, 0);
    }

    it("does not silently substitute a mode unsupported by the device") {
        device.caps = CameraControl_Flags_Manual;
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 1), SALTS_CAPTURE_ERR_UNSUPPORTED);
        check_equal(device.sets, 0);
        context.camera_control = NULL;
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 0), SALTS_CAPTURE_ERR_UNSUPPORTED);
    }

    it("propagates driver read and write failures without reporting success") {
        int mode = 99;
        salts_camera_control_range_t range;
        device.get_result = E_FAIL;
        check_equal(salts_video_capture_get_control(&camera, auto_exposure, &mode), SALTS_CAPTURE_ERR_DEVICE);
        check_equal(mode, 99);
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 0), SALTS_CAPTURE_ERR_DEVICE);
        check_equal(device.sets, 0);
        check_equal(salts_video_capture_get_control_range(&camera, auto_exposure, &range), SALTS_CAPTURE_ERR_DEVICE);
        device.get_result = S_OK;
        device.set_result = E_FAIL;
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 1), SALTS_CAPTURE_ERR_DEVICE);
    }

    it("preserves the existing manual exposure value control") {
        device.flags = CameraControl_Flags_Auto;
        check_equal(salts_video_capture_set_control(&camera, SALTS_CAMERA_CONTROL_EXPOSURE, -5), SALTS_CAPTURE_OK);
        check_equal(device.flags, (long)CameraControl_Flags_Manual);
        check_equal(device.exposure, -5L);
    }

    it("distinguishes explicitly unsupported driver operations from device failures") {
        const HRESULT unsupported[] = {E_PROP_ID_UNSUPPORTED, E_PROP_SET_UNSUPPORTED,
            E_NOTIMPL, E_NOINTERFACE, HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)};
        for (size_t index = 0; index < sizeof(unsupported) / sizeof(unsupported[0]); ++index) {
            int mode = 99;
            salts_camera_control_range_t range;
            device.range_result = unsupported[index];
            check_equal(salts_video_capture_get_control_range(&camera, auto_exposure, &range), SALTS_CAPTURE_ERR_UNSUPPORTED);
            check_equal(salts_video_capture_set_control(&camera, auto_exposure, 1), SALTS_CAPTURE_ERR_UNSUPPORTED);
            device.range_result = S_OK;
            device.get_result = unsupported[index];
            check_equal(salts_video_capture_get_control(&camera, auto_exposure, &mode), SALTS_CAPTURE_ERR_UNSUPPORTED);
            check_equal(mode, 99);
            device.get_result = S_OK;
            device.set_result = unsupported[index];
            check_equal(salts_video_capture_set_control(&camera, auto_exposure, 1), SALTS_CAPTURE_ERR_UNSUPPORTED);
        }
    }

    it("reports a manual-only mode range and rejects an empty capability set") {
        salts_camera_control_range_t range;
        device.caps = CameraControl_Flags_Manual;
        check_equal(salts_video_capture_get_control_range(&camera, auto_exposure, &range), SALTS_CAPTURE_OK);
        check_equal(range.min_value, 0);
        check_equal(range.max_value, 0);
        check_equal(range.current_value, 0);
        device.caps = 0;
        check_equal(salts_video_capture_get_control_range(&camera, auto_exposure, &range), SALTS_CAPTURE_ERR_UNSUPPORTED);
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 0), SALTS_CAPTURE_ERR_UNSUPPORTED);
        check_equal(device.sets, 0);
    }

    it("rejects invalid handles and output pointers") {
        int mode = 99;
        check_equal(salts_video_capture_set_control(NULL, auto_exposure, 1), SALTS_CAPTURE_ERR_DEVICE);
        check_equal(salts_video_capture_get_control(&camera, auto_exposure, NULL), SALTS_CAPTURE_ERR_DEVICE);
        check_equal(salts_video_capture_get_control_range(&camera, auto_exposure, NULL), SALTS_CAPTURE_ERR_DEVICE);
        camera.type = SALTS_CAPTURE_TYPE_AUDIO;
        check_equal(salts_video_capture_get_control(&camera, auto_exposure, &mode), SALTS_CAPTURE_ERR_DEVICE);
        check_equal(mode, 99);
        camera.type = SALTS_CAPTURE_TYPE_VIDEO;
        camera.platform_ctx = NULL;
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 1), SALTS_CAPTURE_ERR_DEVICE);
    }

    it("rejects malformed driver state without modifying the mode output or device") {
        int mode = 99;
        device.flags = CameraControl_Flags_Auto | CameraControl_Flags_Manual;
        check_equal(salts_video_capture_get_control(&camera, auto_exposure, &mode), SALTS_CAPTURE_ERR_DEVICE);
        check_equal(mode, 99);
        device.flags = CameraControl_Flags_Manual;
        device.exposure = 0;
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 1), SALTS_CAPTURE_ERR_DEVICE);
        check_equal(device.sets, 0);
        device.range_result = E_FAIL;
        check_equal(salts_video_capture_set_control(&camera, auto_exposure, 0), SALTS_CAPTURE_ERR_DEVICE);
        check_equal(device.sets, 0);
    }

    it("verifies both static Media API owners without opening devices") {
        /* Pull the actual Win32 Capture dispatcher and the PCM Playback owner
         * from the same static archive; do not just inspect target metadata. */
        check_equal(salts_capture_get_state(NULL), SALTS_CAPTURE_STATE_STOPPED);
        check_equal(salts_capture_start(NULL), -1);
        check_equal(salts_playback_get_state(NULL), SALTS_PLAYBACK_STATE_ERROR);
        check_equal(salts_playback_start(NULL), SALTS_PLAYBACK_ERR_FORMAT);
    }

    it("delivers a borrowed V2 frame and restores the untouched legacy registration") {
        uint8_t bytes[16] = {0};
        frame_legacy_count = frame_v2_count = 0u;
        frame_expected_data = bytes;
        context.width = context.height = 2; context.format = SALTS_VIDEO_CAPTURE_FORMAT_BGRA;
        context.source_stride = 8;
        camera.video_cb = legacy_frame; camera.user_data = &frame_legacy_count;
        check_equal(salts_video_capture_set_callback_v2(&camera, described_frame, &frame_v2_count), SALTS_CAPTURE_OK);
        camera.state = SALTS_CAPTURE_STATE_RUNNING;
        check_equal(mf_frame_deliver(&camera, &context, bytes, sizeof(bytes), 42u), SALTS_CAPTURE_OK);
        check_equal(frame_v2_count, 1u); check_equal(frame_legacy_count, 0u);
        check_equal(salts_video_capture_set_callback_v2(&camera, NULL, NULL), SALTS_CAPTURE_ERR_BUSY);
        camera.state = SALTS_CAPTURE_STATE_STOPPED;
        check_equal(salts_video_capture_set_callback_v2(&camera, NULL, NULL), SALTS_CAPTURE_OK);
        check_equal(camera.user_data, &frame_legacy_count);
        check_equal(mf_frame_deliver(&camera, &context, bytes, sizeof(bytes), 43u), SALTS_CAPTURE_OK);
        check_equal(frame_legacy_count, 1u); check_equal(frame_v2_count, 1u);
    }
    it("rejects an unsupported V2 layout and reports invalid frames once") {
        uint8_t bytes[16] = {0};
        frame_v2_count = frame_error_count = 0u; frame_expected_data = bytes;
        context.width = context.height = 2; context.format = SALTS_VIDEO_CAPTURE_FORMAT_BGRA;
        context.source_stride = 8; context.frame_sink.unsupported = 1;
        check_equal(salts_video_capture_set_callback_v2(&camera, described_frame, &frame_v2_count), SALTS_CAPTURE_ERR_UNSUPPORTED);
        context.frame_sink.unsupported = 0; camera.state_cb = frame_error;
        check_equal(salts_video_capture_set_callback_v2(&camera, described_frame, &frame_v2_count), SALTS_CAPTURE_OK);
        camera.state = SALTS_CAPTURE_STATE_RUNNING;
        check_equal(mf_frame_deliver(&camera, &context, bytes, 1u, 0u), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(camera.state, SALTS_CAPTURE_STATE_ERROR);
        check_equal(mf_frame_deliver(&camera, &context, bytes, sizeof(bytes), 0u), SALTS_CAPTURE_ERR_FORMAT);
        check_equal(frame_error_count, 1u); check_equal(frame_v2_count, 0u);
    }
}
