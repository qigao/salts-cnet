# GmSSL explicit-copy measurements

## Protocol before collection

Continue #189 with the same pinned GmSSL and the same formal TLS workloads.
The optional Linux x64 diagnostic graph counts source-level `memcpy` and
`memmove` in the existing GmSSL target, including calls normally inlined by
the compiler. It does not measure assignments, handwritten copy loops,
compiler-generated copies, libc internals, cryptographic transformations,
kernel traffic or memory-bus activity. Keep diagnostic timings in a separate
cohort; they do not establish overhead or a speedup against ordinary builds.
The [collected report and raw rows](benchmarks/cnet-provider-copies-2026-11-04.md)
record the qualified source and every diagnostic sample.

One fixed C11 thread-local counter object belongs to each calling thread.
Counters are monotonic, saturate on overflow and expose a sticky overflow bit.
Snapshots neither reset counters nor access TLS connection state. The wrapper
performs the original copy once and records only function category, operation
and byte count. It retains no pointers or payload, allocates no memory, takes
no locks and invokes no callbacks. Thread exit ends the counter lifetime.
The existing stream owner, borrowed buffers, admission, cancellation, native
drain and authenticated close contracts remain unchanged.

The three categories are `tls13_gcm_encrypt`, `tls13_gcm_decrypt` and all other
GmSSL functions. Each separates memcpy/memmove calls and bytes. Both formal
transport executables obtain counters through the existing Crypto snapshot;
CNet continues linking its single production Crypto/GmSSL owner.

The diagnostic vcpkg triplet inherits x64-linux and attaches one counter source
and a forced-include wrapper to the existing `gmssl` archive. Hook/header/source
contents participate in the vcpkg ABI hash. There is no replacement TLS library,
new executable or validation project. A strong snapshot symbol and configuration
guards reject a normal GmSSL archive paired with the diagnostic project option.
Ordinary builds keep the option off and do not compile the provider counters.

Run the complete graph with the versioned `gmssl-copy-user` configure/build/test
presets. Manual LLVM CI input `gmssl_copy_profile=true` does this on Linux x64
after the regular native suite. Preserve all 25 rotated fresh-process samples,
their six phase rows, full CTest output, source, compiler and host provenance.
The initial diagnostic package build can miss the ordinary triplet's cache;
its separate ABI must not replace normal package artifacts.

```sh
cmake --preset gmssl-copy-user
cmake --build --preset gmssl-copy-user
ctest --preset gmssl-copy-user
```

Use the normal Linux x64 shared toolchain/host/dependency environment. This
diagnostic profile is for formal measurements, not SDK installation/release.

Correctness remains in the formal cases: forced TLS1.2/TLS1.3 payload delivery,
short pending plaintext, overflow rejection and another owner thread. For
TLS1.3, after transfer plus full bulk drain, encryption must have two explicit
memcpy calls per record (8-byte nonce and input), decryption one (8-byte nonce),
and encrypt bytes minus decrypt bytes must equal delivered application bytes.
These assertions apply only to the actually negotiated TLS1.3 workload, outside
handshake/close. Other provider copies remain directly reported without assuming
their count. No phase may overflow. Preserve existing byte, reference, partial
native write, admission refusal, close and drain assertions.

Upstream mechanisms: [vcpkg triplet options and ABI inputs](https://learn.microsoft.com/en-us/vcpkg/users/triplets),
[CMake project include hook](https://cmake.org/cmake/help/v3.25/variable/CMAKE_PROJECT_PROJECT-NAME_INCLUDE.html),
[deferred target configuration](https://cmake.org/cmake/help/v3.25/command/cmake_language.html#deferring-calls).
