# Salts::Media

One **static** native C11 owner for the original audio/video/screen Capture and PCM Playback APIs. It is part of SaltsCore, not a second camera driver, player or transcoder.

## Source/target ownership

- The only CMake target is `Salts::Media` (`salts_media STATIC`). The old `Salts::Capture` and `Salts::Playback` shared targets and their archives, exported symbol lists, module-local `original/` trees and module-level `cmake/` helpers are removed. There are no aliases or conditional provider fallbacks.
- The public C function names and installed header spellings `<capture.h>`, `<capture_android.h>`, `<playback.h>` remain unchanged. Their `*_API` macros are no-ops for static linkage.
- `capture/src/miniaudio_impl.c` is the **single** `MINIAUDIO_IMPLEMENTATION` translation unit used by both production subsystems. The duplicate Playback TU was deleted.
- Native producer and device ownership remain in `capture/src/`, the Playback PCM sink remains in `playback/src/`. Tests live in the associated subtrees. Nothing under the old root-level `capture/` or `playback/` paths is built.
- Windows: Media Foundation / DirectShow / DXGI / D3D11; Linux: V4L2, PipeWire, X11; macOS/iOS: AVFoundation plus respective native frameworks; Android: NDK Camera2/Media, OpenSL ES, NativeWindow. iOS unsupported operations are explicit source definitions; no generated C unit.
- Media is a static archive, **not** a guarantee that every vcpkg runtime provider is statically linked into the SDK. Installed consumers must satisfy the explicitly exported static link dependencies. No fallback to a shared Media runtime exists.

## Build

Choose Media explicitly through the canonical preset or with the matching vcpkg feature:

```sh
cmake -S . -B build/media -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg.cmake \
  -DSALTSCORE_BUILD_MEDIA=ON -DVCPKG_MANIFEST_FEATURES=media
cmake --build build/media
```

The installed target is consumed without old target aliases:

```cmake
find_package(SaltsCore CONFIG REQUIRED)
target_link_libraries(app PRIVATE Salts::Media)
```

`Salts::Media` is selectable as one atomic unit, not two independently selectable feature switches. The two legacy CMake options are rejected at configure time. The installed target is verified to be `STATIC_LIBRARY`; a missing required provider makes configuration fail.

## Native ownership and release gates

Capture frames are synchronous **borrowed views** valid only until callback return. Control operations, callbacks, stop/join and destroy retain the original contracts. Playback uses the existing single producer with bounded PCM storage. No compatibility provider, fake production device, queue or decoding fallback is added by this merge.

See `release-blockers.json`: iOS native acceptance, the miniaudio/PulseAudio initialization leak, actual camera/microphone/screen permission and hardware tests, and redistributable static dependency closure remain independent **RED** release conditions. CI build/link success is not proof of real-device capability.

Upstream Frame V2 design (not part of this structural merge): https://github.com/qigao/salts-core/issues/197
