# Unapplied miniaudio PulseAudio cleanup proposal

**Status: unresolved dependency-owner issue; this proposal is not applied by
any Core build.** The production miniaudio `0.11.22` pin and header remain
unchanged. The Capture sanitizer failure remains a release blocker. A successful
temporary experiment cannot qualify a replacement provider or the SDK.

## Reproduction and ownership

The original `capture_posix_test`, built with ASan/UBSan and
`ASAN_OPTIONS=detect_leaks=1:abort_on_error=1`, reports **41,332 bytes in 28
allocations**. Its failing allocation chain includes:

```text
pa_context_new_with_proplist
ma_init_pa_mainloop_and_pa_context__pulse  miniaudio.h:29772
ma_context_init__pulse                    miniaudio.h:31292
ma_context_init                          miniaudio.h:41793
original Capture enumeration / unknown-device creation
```

`pulse_init_repro.c` isolates that failure from Core and Capture. It selects only
the real PulseAudio backend, supplies an explicitly absent private Unix socket,
and disables server auto-spawn. It neither starts a device nor supplies a fake
backend. A successful initialization would be unexpected and returns exit 2
after normal cleanup.

In the fixed provider, `ma_init_pa_mainloop_and_pa_context__pulse` creates a
Pulse context before connecting. Both the failed-connect and failed-wait
branches free the main loop without releasing the context. These branches
return before publishing that private context through the output pointer.
The outer failed initializer releases its strings and runtime library handle,
but cannot recover the lost local object. Normal `ma_context_uninit__pulse`
does disconnect, unref and main-loop cleanup.

The observed Capture paths already call `ma_context_uninit` after a successful
initialization, including enumeration failure, unknown-device rejection and
device-initialization failure. Calling it on an unsuccessfully initialized
context would violate the provider lifecycle and would not recover this lost
pointer. The correction belongs to the provider's failed-initialization paths.

## Exact temporary experiment

The experiment used GCC `13.3.0` on Linux x64 and the same flags for both
binaries:

```sh
gcc -std=c11 -D_GNU_SOURCE -O1 -g \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I"$MINIAUDIO_HEADER_DIRECTORY" pulse_init_repro.c \
  -ldl -lm -lpthread -o pulse-init-repro
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 ./pulse-init-repro
```

`MINIAUDIO_HEADER_DIRECTORY` points first to the exact original header and then
to an isolated `/tmp` copy with the adjacent proposed patch. The absence of
`/tmp/saltscore-capture-pulse-leak/absent-pulse-server.sock` was deliberate.
LeakSanitizer ran with normal process introspection; no leak suppression,
disabled backend or reduced sanitizer set was used.

| Input | Header SHA-256 | Result |
| --- | --- | --- |
| Original 0.11.22 | `9019743287e443c55e5737a7297f38e5e358561701d6db2d905afb114390c410` | Initializer returns `-203`; LSan reports **20,708 bytes / 14 allocations**; process exit **134** |
| Temporary copy with two added unrefs | `6fc8a4c2b37da54e520ff5045db1eb85451b57d55d4e7d7a765f704dc0dd9458` | Initializer still returns `-203`; ASan/UBSan/LSan exit **0** |

The isolated test exercises one absent-server failure scenario. It does not
independently force both connection-failure branches, prove successful server
interaction, or exercise all backend cleanup interleavings. The two-branch
proposal follows the ownership inspection; its complete qualification is still
pending.

Retained local experiment evidence:

- `/tmp/saltscore-capture-pulse-leak/original.log`, SHA-256
  `1eec11349ef4ffe641aeda46d75c65f7914a5a91d51189ff0ad96c34b1714029`.
- `/tmp/saltscore-capture-pulse-leak/proposed-fix.log`, SHA-256
  `d41a729a61f46f423b1d421b4636dbdccaa569d823bfe3d64cc37cf46e087291`.
- Original Capture failure:
  `/tmp/saltscore-capture-asan-build/Testing/Temporary/LastTest.log`.

## Proposed change and release admission

`miniaudio-0.11.22-pulse-init-unref.patch` adds only this release operation before
each of the two existing failure-path `pa_mainloop_free` calls:

```c
((ma_pa_context_unref_proc)pContext->pulse.pa_context_unref)((ma_pa_context*)pPulseContext);
```

It preserves the original return values and leaves successful initialization
unchanged. It is a review artifact, not a vendored provider update. No CMake
file, workflow, dependency feature or release driver applies it.

The actual dependency owner must review and publish an identifiable provider
revision, with a new verified archive/header identity and license provenance.
That revision must then pass the full Core/Capture sanitizer graph, the original
virtual-audio TSan regression, successful connection and both connection-failure
branches, and the required desktop and six-RID SDK qualification. Capture's
iOS implementation gaps, physical-device/permission acceptance and runtime
dependency closure remain separate open requirements. Neither this temporary
exit 0 nor passing installed null/error/ABI tests closes any of those gates.
