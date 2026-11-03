/**
 * Android extensions for Salts Capture.
 *
 * MediaProjection permission and VirtualDisplay remain Java-owned. Salts owns
 * the AImageReader and exposes its producer Surface as a JNI local reference.
 */
#ifndef SALTS_CAPTURE_ANDROID_H
#define SALTS_CAPTURE_ANDROID_H

#ifndef __ANDROID__
#error "capture_android.h is available only when targeting Android"
#endif

#include <jni.h>
#include <stdint.h>

#include <capture.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct salts_android_screen_capture_config_s {
  int width;
  int height;
  int framerate;
} salts_android_screen_capture_config_t;

/**
 * Create an Android screen capture backed by AImageReader.
 *
 * @param config Explicit positive dimensions and frame rate.
 * @param out_capture Receives the owned capture on success and NULL on error.
 * @return SALTS_CAPTURE_OK, SALTS_CAPTURE_ERR_FORMAT for invalid arguments,
 *         SALTS_CAPTURE_ERR_NOMEM on allocation failure, or
 *         SALTS_CAPTURE_ERR_DEVICE when the Android backend cannot start.
 */
SALTS_CAPTURE_API int salts_android_screen_capture_create(
    const salts_android_screen_capture_config_t *config,
    salts_capture_t **out_capture);

/**
 * Create a Java Surface for MediaProjection VirtualDisplay attachment.
 *
 * @param env JNI environment for the calling Java thread.
 * @param capture Android screen capture returned by
 *        salts_android_screen_capture_create().
 * @param out_surface Receives a JNI local reference on success and NULL on
 *        error. Java owns the returned reference after the native method
 *        returns; Salts continues to own the underlying AImageReader window.
 * @return SALTS_CAPTURE_OK, SALTS_CAPTURE_ERR_FORMAT for invalid arguments or
 *         capture type, or SALTS_CAPTURE_ERR_DEVICE on JNI conversion failure.
 */
SALTS_CAPTURE_API int salts_android_screen_capture_get_surface(
    JNIEnv *env, salts_capture_t *capture, jobject *out_surface);

/**
 * Read the number of frames successfully converted to I420.
 *
 * @param capture Android screen capture returned by
 *        salts_android_screen_capture_create().
 * @param out_frame_count Receives the current monotonic count on success and
 *        zero on error.
 * @return SALTS_CAPTURE_OK or SALTS_CAPTURE_ERR_FORMAT for invalid arguments
 *         or capture type.
 */
SALTS_CAPTURE_API int salts_android_screen_capture_get_frame_count(
    const salts_capture_t *capture, uint64_t *out_frame_count);

#ifdef __cplusplus
}
#endif

#endif /* SALTS_CAPTURE_ANDROID_H */
