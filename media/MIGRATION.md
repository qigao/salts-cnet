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
