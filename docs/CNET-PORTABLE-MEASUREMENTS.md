# Portable formal TLS measurements

This #189 follow-up reuses the existing direct NativeIO/Crypto and production
CNet TLS TinyTest cases. It adds no executable, consumer/smoke project, CMake
verification script or alternate TLS runtime. CMake registers the 25 actual
measurement cases only when explicitly selected; scenario assertions remain
in the existing test sources.

## Protocol before collection

Keep the [mixed TLS workload](CNET-TLS-MIXED-BENCHMARK.md) and its adapter-memory
contract. Use five rotated repetitions, with one fresh process for each of
direct/native/callback at bulk depth 1 and native/callback at depth 8. A CTest
dependency chain fixes repetition/position order. RUN_SERIAL excludes overlap
with other CTests even when parallel execution is requested. Failed cases
still let later repetitions run, preserving failures as evidence; the suite's
exit status determines qualification.

```sh
cmake --preset native-release-user -DSALTSCORE_CNET_TLS_MIXED_MEASUREMENTS=ON
cmake --build --preset native-release-user
ctest --preset native-release-user -L '^cnet_tls_mixed_measurements$' --verbose
```

The standard unfiltered short suites remain available without their long-case
environment switches. Each new registration sets the matching existing switch
and TinyTest filter. Every selected case warms/drains eight control exchanges,
measures 512, validates actual peer bytes, send/source/capacity/native identities,
and completes authenticated close and native drain. Each has a 65-second CTest
limit in addition to its existing bounded phase/cleanup loops.

The existing LLVM CI workflow accepts `cnet_measurements=true` on manual
dispatch. It still configures/builds the complete graph and runs the full formal
suite. Six unsanitized native lanes add the measurement cases: Windows, Linux
and macOS, each x64/ARM64. Sanitizers retain short correctness cases; Android
remains build-only. No benchmark-only job or direct CI executable invocation
is introduced. Production dependencies and the established caches are unchanged.

Preserve CTest's complete successful output and host/source/compiler provenance
as per-RID workflow artifacts. Do not replace existing correctness evidence
with timing or treat runner hardware/load as controlled. Compare only the
documented configuration cohorts. Preserve every sample, partial native write,
rejection, drain and boundary count; closed-loop paths can do different work.
Compiler provenance is generated from the configured CMake graph; a different
compiler found on the host shell PATH must not be used as the build identity.

## Linux process heap profile

The same manual dispatch then profiles those 25 formal cases on Linux x64,
after the unprofiled results have been preserved. `heaptrack` is an analysis
tool installed on that runner, not a product/vcpkg dependency. Reconfigure the
same full native graph with `SALTSCORE_CNET_TLS_MIXED_HEAPTRACK=ON`, build through
the same preset and select the same CTest label. Missing heaptrack or unsupported
requested configurations fail explicitly. The profiling option requires Linux,
measurements and an unsanitized graph; it never silently falls back.

Heaptrack launches each existing formal executable from startup using its
documented preload mechanism. Record-only mode suppresses GUI startup. Save
each trace, an allocation-size histogram, allocation backtraces/flamegraph
stacks and the CLI report with built-in/embedded leak suppressions disabled.
Also save the profiler version and separate profiled CTest output. The real
formal cases must still pass all transport/lifetime assertions under profiling.

The process scope includes discovery/formatting/runtime setup, TLS handshakes,
warm-up, transfer, drain and teardown; it includes intercepted allocations
inside dynamically linked CNet/Core/NativeIO and statically linked GmSSL.
It is not phase-local allocation evidence. Direct syscalls, custom allocators
that do not reach intercepted functions and allocation before profiler startup
are outside that scope. Outstanding libc/runtime/cache memory at process exit
must not be called a CNet leak without stack/lifetime evidence.

Do not compare profiled timings with unprofiled latency/throughput, infer a
stable overhead from independent runs, or call allocation histograms retained
capacity/RSS. Heaptrack does not measure copies. The precise adapter copy
counters remain separate; provider-internal/compiler-generated copies and
kernel traffic are still outside them.

Upstream contracts: [CTest ordering](https://cmake.org/cmake/help/v3.25/prop_test/DEPENDS.html),
[serial execution](https://cmake.org/cmake/help/v3.25/prop_test/RUN_SERIAL.html),
[heaptrack](https://github.com/KDE/heaptrack).
