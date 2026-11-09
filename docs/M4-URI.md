# M4.1: Standalone URI parser (pre-CNet)

Original source pin: `qigao/salts@d6d936a86087a7f9a982126157d154e905580f30`.
Copy of `cnet/uri/include/uri_parser.h`, `cnet/uri/src/uri_parser.c`, `cnet/uri/parser/uri_parser_internal.h`, and `cnet/uri/parser/uri_lexer.re`.

The URI parser is a **mechanism** consumed by the future Core CNet.
It needs no CMeta, CFlow, CSTL, TLS provider or networking library.

## Build/ownership
- `SALTSCORE_BUILD_URI` defaults OFF; enabling it requires a real, explicit
  host `re2c`. Generator absence is a fatal configuration error, never a
  hand-written parser fallback.
- re2c regenerates the original `uri_lexer.re` as a private build source
  with the same `-o` option as the original Salts generator. It is **build-time
  only** and is absent from the installed SDK runtime.
- Independent installed CMake target: `Salts::URI`. Its C11 `uri_t`
  structure and `uri_parse` ABI do not depend on legacy Core or new
  Buffer/NativeIO.
- Other Core targets remain available without re2c or URI.

## Acceptance
- Real URI parse and roundtrip C11/C++17 installed consumers, valid IPv4/IPv6,
  query/fragment/userinfo, presence-bit handling and numeric-port overflow.
- Reject scheme/host truncation and invalid URI syntax; preserve original
  parser semantics, no normalization of DNS/TLS names.
- Next: ensure Windows and macOS generator/build/consumer qualification using
  the same pinned host toolchain. The added URI CI currently runs on Ubuntu.
- No production CNet target or original Salts consumer has switched.
