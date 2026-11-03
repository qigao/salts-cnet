/* Test the production entry points without opening or changing a real camera. */
#include "../src/capture_video_win32.c"
#include <tinytest.h>

static const salts_camera_control_t auto_exposure = SALTS_CAMERA_CONTROL_AUTO_EXPOSURE;

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
}
