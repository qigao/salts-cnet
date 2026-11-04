# Capture native callback ThreadSanitizer regression

This directory contains a standalone, source-instrumented **Linux C11**
regression for the `media/capture/src/capture_audio_miniaudio.c` private atomic
callback admission introduced by [SaltsUtils #653](https://github.com/qigao/salts-utils/pull/653).

It compiles the **actual repository** Capture Linux production source
(`capture_video.c`, `capture_linux.c`, `capture_video_linux.c`,
`capture_screen_linux.c`, `capture_audio_miniaudio.c` and
`miniaudio_impl.c`) together with pinned upstream miniaudio
`0.11.22` using `-fsanitize=thread`. No `salts_capture_*`
function is stubbed or replaced. The only external native SDK input
is the explicitly pinned installed SaltsCore SDK; standard OS
PipeWire, PulseAudio and X11 libraries remain external.

## Mandatory isolation

The CI runner starts a private, temporary PulseAudio instance with
**only one UNIX socket, one software null sink, its one monitor, and zero
physical audio cards**. It never reads the OS PulseAudio default modules
or opens the default user input/output. C11 tests reject operation
unless `SALTS_CAPTURE_TSAN_VIRTUAL_ONLY=1`, `PULSE_SERVER` is
a private `unix:` URL, the *only* enumerated input is named
`CaptureTsanVirtualAudioSink`, and the explicit device ID is valid.
Only bounded digital-zero PCM is fed into the null sink; no audio is
recorded or persisted.

### What every repeated test proves

- Actual original miniaudio/Pulse native Capture
  `create/start/callback/stop/join/destroy` over **three lifecycle
  cycles**, with exact S16LE mono 16k/20ms PCM and monotonic callback
  timestamps. No callback can run after `stop` returns.
- The **same Capture object is stopped and restarted three times**, proving
  re-opening the private atomic admission gate, a fresh zero-based first
  timestamp on every restart, and zero callbacks after each native join.
  Callback registration remains fixed before the first start.
- The actual native audio callback is **deliberately held in-flight** on
  a bounded pthread condition variable while a different control
  thread calls `salts_capture_stop`. The stop call must remain
  blocked until the callback has been explicitly released and joined,
  or the test fails. The callback has a deadline which releases it on
  timeout to avoid unsafe forced destruction.
- An **active Capture owner can be destroyed without a prior explicit stop**:
  the real native callback is held in-flight while another thread destroys
  the device. Destroy must remain blocked until callback release and join,
  with zero post-destroy callbacks and no borrowed owner use afterward.
- Invalid PCM and unknown explicit device IDs fail closed without an
  implicit system/default-device fallback.

The workflow repeats the test **12 times**, checks all six exact test
markers, and requires the same executable to import its **own
source-built `libsaltscore_media.a`** rather than the uninstrumented
published SDK image. `__tsan_init` must be present in the static Media archive.
`TSAN_OPTIONS=halt_on_error=1:exitcode=66:history_size=7`;
**no sanitizer suppressions**.

The earlier [unmodified-source negative](https://github.com/qigao/TurboAgent/actions/runs/38865018002)
caught the actual public-`capture->state` callback/control data race.
The [single-file private atomic fix](https://github.com/qigao/salts-utils/pull/653)
passed independent [six consecutive original-source TSan tests](https://github.com/qigao/TurboAgent/actions/runs/38865851955).
This upstream regression is separately owned by SaltsUtils, so future
Capture changes cannot quietly reintroduce the same bug without
breaking CI.

**Limits:** This is a software virtual monitor, not permission to use
a physical microphone, any real-human audio recognition, real Whisper/TTS
weights or acoustic AEC. Salts.Native, OS PulseAudio/PipeWire and
X11 dependencies are not rebuilt from source under TSan in this
standalone test. This is not a physical/six-platform device acceptance.
This source regression remains part of Media qualification and must pass at the candidate head, no production fallback or
published SDK changes.
