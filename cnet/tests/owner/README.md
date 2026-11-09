# Original CNet Owner test provenance

This test's C11 source and two small native pipe helpers come from
`qigao/salts` Draft PR #1324 at `fdbcae0b367434ed549fe6a85c1aaf61fe6ef034`. The source is copied
without changing runtime assertions or moving any CNet production
implementation back into Salts.

The test-only CMake configuration compiles actual Core CNet sources in a
**single private** executable owner, with `CNET_INTERNAL_TESTING=1` only
there. The installed `Salts::CNet` DSO is never linked into that test
executable and the profile archive is never exported or installed.

The pooled send regression requires a true NativeIO partial terminal,
retained buffer through observation and cancellation, and precisely once
retirement/reuse; it is not a mocked callback or a production API hook.
This test does not prove that the optional native CNet provider has
already switched to opaque Crypto TLS. Production GmSSL pin is unchanged.
