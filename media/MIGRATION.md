# Media consolidation provenance and admission

This module unifies the existing Capture and Playback native owners into one static `Salts::Media` target. The original source inventory is retained unchanged in `tools/migration/original-salts-utils-files.json` and its 2,975-file / 610-public-function global gate remains independent. No old build directories or copied original CMake fixtures are kept inside the module.

Structural changes:

- Source moved from `capture/` to `media/capture/` and from `playback/` to `media/playback/`.
- One `MINIAUDIO_IMPLEMENTATION` source: `media/capture/src/miniaudio_impl.c`. The old Playback duplicate is intentionally not built or retained.
- Root `SALTSCORE_BUILD_MEDIA` and vcpkg `media` feature replace both legacy build switches/features. Old toggles are configuration errors, not aliases.
- Single `salts_media STATIC` exports `Salts::Media` and installs both original public header names with static export macros.
- iOS six previously missing common functions are explicit definitions in `media/capture/src/ios/capture_ios.m`, not configure-time generated source. Unsupported hardware controls remain unsupported, not silently emulated.
- The version-script/export lists and two module root CMake files were removed; static archive symbols are resolved by the final consumer linker. All actual required providers are direct package/link dependencies.
- Original Capture/Playback native CTest sources are retained. The separate source TSan test must use the same static binary identity, not a phantom DSO.

This is structural implementation work, not completed physical-device qualification. See `release-blockers.json`; no release or downstream cutover may proceed on a missing linker dependency or unresolved provider leak.

## Additive CPU camera-frame contract (#197)

The requested Frame V2 is additive to the original C camera ABI. Keep
`salts_capture_t`, the existing callback and format enums unchanged. The native
camera context owns one fixed callback registration; no global registry, queue,
worker or retained frame is introduced. Configure it only while STOPPED, with
exclusive lifecycle ownership. An enabled V2 callback is the one frame consumer;
clearing it restores the existing legacy callback without replacing its user data.

Native backends report their delivered layout, including padded rows, and the
common bounded descriptor builder validates plane spans and checked arithmetic
before publication. I420/NV12 chroma dimensions round up for odd dimensions.
Unknown color/orientation metadata remains explicitly unknown. Timestamp units
are microseconds; clock identity distinguishes host monotonic, Unix wall time,
Android sensor and Media Foundation presentation time rather than claiming they
are mutually synchronized. There is no new per-frame allocation or format fallback.

The descriptor and producer-owned bytes are immutable synchronous borrows until
callback return. A consumer must copy before retaining a frame or handing it to
another thread. It must not reconfigure or destroy the producer inside this
callback. Stop/drain remains owned by each existing native backend. An invalid
new frame latches ERROR and reports through the existing state callback once;
the owner must stop/drain before reconfiguration. No invalid V2 frame is published.

Alternatives rejected: changing the public capture layout breaks existing C
callers; a process-global map obscures ownership; a retained/GPU abstraction
without native fence/drain qualification would expose a partial API. GPU handles
remain M2 and real-device, permission and per-RID release gates remain separate.
Rollback removes only the new registration; the existing callback and native
provider remain available with their original contract.

Windows uses the contiguous buffer layout from
[MF_MT_DEFAULT_STRIDE](https://learn.microsoft.com/en-us/windows/win32/medfound/mf-mt-default-stride-attribute)
or the SDK's documented minimum-stride calculation when that attribute is
absent. Unknown/unsupported layouts are rejected at V2 registration, including
odd-size Windows conversion recipes that the existing converter cannot safely
normalize. Native RGB24 bytes are described as BGR24, and YV12 remains explicitly
Y/V/U. This does not change the existing legacy format enum or callback.
