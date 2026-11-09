# CNet live TCP loopback qualification (Draft)

Stacked on the provider-enabled CNet extraction PR #15; the source target
continues to use exact pinned GmSSL, KCP, c-ares and SIMDe. This is a new,
**actual TCP transport execution test**, not a substitute for full CNet tests.

## Source under test

`cnet/tests/test_cnet_tcp_loopback.c` creates an OS TCP socket and a CNet
`cnet_listener` bound to ephemeral IPv4 loopback. It accepts the live peer
into a separate, caller-driven CNet client with generation-checked connection
identity and exact single-threaded callback ownership.

After CONNECTED, it sets a retained-slice receive handler and admits
one read. It then sends one byte from the OS peer and requires exactly
one retained `mem_slice_t` callback (and **no borrowed callback**). The
test retains the slice across CNet client close, stop and destroy, checking
that the backing memory is still readable before it releases the last
reference.

In the reverse direction, it admits `cnet_send_buffer()`, immediately
releases the caller's `mem_buffer_t`, and requires exactly one CNet send
completion and matching byte at the OS TCP peer. It then requests close
and checks exactly one terminal callback without failure. The test uses
explicit monotonic bounded progress and socket receive timeouts to avoid
indefinite blocking. All acquired OS/CNet resources and retained slices
are cleaned up on test failure.

## CI / evidence

`SaltsCore CNet pinned-provider qualification` now asserts the
`saltscore.cnet_tcp_loopback` CTest explicitly, in addition to the
GmSSL TLS I/O ABI and ShangMi provider-only KAT tests. This only runs
when the *actual* provider-backed `Salts::CNet` DSO is enabled,
never in the default minimal-Core build.

Successful Linux results establish real TCP acceptance and non-TLS
retained-send/receive/close semantics under loopback conditions.
They do **not** establish independent peer interoperability, TLS CA/SAN
rejection, KCP/UDP/WebSocket end-to-end, Windows IOCP or macOS kqueue
provider-enabled traffic, cross-shard handoff, ASan/TSan/UBSan, or
deployment ABI cutover. Those gates remain open in salts-core#3.
