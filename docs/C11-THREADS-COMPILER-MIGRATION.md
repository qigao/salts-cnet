# C11 threads.h and production compiler admission — M2 Draft

Tracking: [SaltsCore #42](https://github.com/qigao/salts-core/issues/42).
Foundational Atomic/Threads and relative timing/TSS are already merged.

## Compiler-independent C11 source facade

The experimental header is
\`include/c11/threads.h\`. Consumers explicitly opt in with
\`SALTS_C11_THREADS_EXPERIMENTAL=1\` and add the
\`<SaltsCore include>/c11\` directory **before** compiler
system include directories; \`#include <threads.h>\` resolves to this
header. This never overwrites the compiler's global \`threads.h\`,
does not define or undefine \`__STDC_NO_THREADS__\`, and does not claim
full C11 conformance.

C11 spellings map at preprocessing to **prefixed**
\`salts_c11_*\` exports of the existing \`Salts::Platform\` DLL/DSO.
The prefix prevents collisions with libc/UCRT native C11 thread symbols.
\`thrd_t\` is a provider-owned opaque pointer, not \`pthread_t\` or
\`HANDLE\`. The provider owns native thread identities, thread
refcounts, run/exit callbacks and synchronization allocation. C clients
can be compiled by TinyCC, MSVC or llvm-mingw without using native
\`_Atomic\` or \`_Thread_local\`.

Included M2 source/API qualification:

- \`thrd_create/join/detach/current/equal/yield/exit/sleep\`, with
  creator/worker references preventing wrapper release before a detached
  worker's callback retires. Early \`thrd_exit\` must retire the
  underlying Platform worker reference and preserve the result for join.
- \`mtx_plain\`, \`mtx_timed\`, \`mtx_lock/trylock/timedlock/unlock/destroy\`
  and \`cnd_init/wait/timedwait/signal/broadcast/destroy\`. C11's
  **absolute TIME_UTC** deadlines are checked/translated against
  \`cmeta_realtime_ms()\` exactly once, then passed to the common
  Platform **relative monotonic** timed wait. No absolute-to-relative
  ABI reinterpretation or silent overflow.
- \`once_flag\`, \`ONCE_FLAG_INIT\`, \`call_once\` shared with the Platform
  owner. All return values use C11 \`thrd_*\` categories.

**Remaining required before a standard header can be generally
enabled:** recursive mutexes (\`mtx_recursive\` currently fail closed
instead of pretending to be plain locks), complete standard TSS
\`tss_create/delete/get/set\` and repeated destructor semantics
(\`salts_platform_tss_destroy\` currently returns BUSY), full
cancellation/close/admission, unload barriers, exact C11
\`thrd_sleep\` interruption policy and ABI/lifetime differential tests.
This header is **not** a hidden fallback for a missing compiler feature.

## Production compiler migration

First production change: Windows \`cmeta_hrtime\` had
\`static volatile uint64_t freq\` read/written concurrently, a C data
race. It now publishes QueryPerformanceFrequency using the SINGLE
\`Salts::Platform\` \`salts_atomic64\` compare/exchange ABI. This is
not a compatibility wrapper, not compiler-native \`_Atomic\`, and does
not duplicate source ownership.

A compiler is admitted for an actual SDK consumer ONLY if it builds
and runs \`platform/tests/test_c11_threads.c\` against the real provider shared
library; cross linking alone is not evidence. Require Windows x86/x64
and native ARM64 TinyCC→llvm-mingw, macOS Intel/ARM64 TinyCC→Clang,
Linux TinyCC→GCC, MSVC compiled Installed SDK C11/C++17, and
GCC TSan plus Clang ASan/UBSan. A separate SDK-prefix installation
gate prevents relying solely on local source recompile.

**No whole-repository production compiler switch yet.** The public
buffer/Readiness/Concurrency fields still rely on C11 \`_Atomic\`
and MSVC \`-experimental:c11atomics\`. Migrate those owners
individually with exact-head performance, ownership, SDK/ABI and
sanitizer evidence, then remove compiler-specific support flags only
after the last producer is converted.

Architecture remains:
\`Salts::Platform (Atomic/Thread/C11 adapter)\` below
\`Salts::Concurrency (queues/RCU/pools)\`; no CMeta/ACE dependency.


## Windows i686 CRT time-layout qualification

The initial Windows x64 direct TinyCC client passed, but true Windows
i686 failed despite the same native Platform/TSS callback tests passing.
The C11 adapter had originally exported parameters of type
\`const struct timespec *\`, which is **not a valid cross-compiler ABI**:
TinyCC and llvm-mingw/UCRT need not agree on \`time_t\` width, structure
member offsets or padding on i686.

The portable header now reads \`timespec\` **inside the client compiler**;
\`thrd_sleep\`, \`mtx_timedlock\` and \`cnd_timedwait\` use prefixed,
fixed-width \`_abi\` exports with uint64/int64 seconds and uint32 nanoseconds.
The implementation never dereferences a client-allocated CRT timespec.
A failing native i686 test is a required regression gate; it is not skipped
or replaced with x64 emulation. The same contract applies on Windows ARM64.
