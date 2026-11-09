# Original native error owner

`Salts::Core` owns the original `cmeta_error` registry and four C functions.
It uses the existing `Salts::Platform` thread owner through `salts/thread.h`.
It has no CMeta dependency and does not create a second registry, synchronization
provider, descriptor system, or conversion layer for reflection.

## Source and retained contract

The source is `qigao/salts` at
`386f81328c656f416d61a6d2ef662f05443e1b4a`. The supplemental inventory records
the original header, implementation, and TinyTest file with these Git blobs:

| Original file | Git blob | Native destination |
| --- | --- | --- |
| `utils/include/cmeta_error.h` | `1b1950be783a3a5bd6559a8f81df8131f189eba2` | `core/include/cmeta_error.h` |
| `utils/src/cmeta_error.c` | `d489ef242ffea3612b32be896f229f6f2828b706` | `core/src/cmeta_error.c` |
| `utils/tests/test_cmeta_error.c` | `b8b407a8bb5d0850c9e9645cf5e5fba3295d12ca` | `core/tests/test_cmeta_error.c` |

The exported functions retain their original signatures:

- `cmeta_strerror(int)` returns the selected message pointer.
- `cmeta_error_info(int)` returns the original code, domain, custom domain ID,
  name, and message without transferring ownership.
- `cmeta_error_register_domain(const cmeta_error_domain_desc_t *)` borrows the
  descriptor, entry table, names, and messages. The descriptor and table must
  remain alive until unregister or process exit. Callers must keep borrowed
  strings alive while reading returned metadata; unregister does not free them.
- `cmeta_error_unregister_domain(int)` removes the registration and leaves
  storage ownership with the caller.

There are 64 registration slots. Domain IDs remain 1 through 32767 and local
codes 1 through 65535. A duplicate domain returns `SALTS_EALREADY`, including
when the registry is full; a new valid domain at capacity returns `SALTS_ENOSPC`.
Invalid descriptors return `SALTS_EINVAL`, and removing a valid absent domain
returns `SALTS_ENOENT`. The original swap-with-last removal and mutex/once
synchronization are retained. Registration does not copy the descriptor or
table. Mutation and reclamation require caller-side quiescence; the registry
mutex does not grant a lifetime lease to a returned pointer.

Resolution order remains success, built-in Salts code, registered custom code,
unregistered encoded custom code, POSIX `strerror`, then Win32 `FormatMessageA`.
The original positive native-code handling is also retained. A recognized POSIX
code wins when a Windows code has the same number. Unknown errors use the
original thread-local 64-byte message buffer; Win32 text uses the original
thread-local 256-byte buffer and trailing-whitespace trimming. These messages
are borrowed and can be overwritten by later calls using the same buffer on
the same thread. Built-in and registered strings retain their original storage.

The original six domain values are a plain C enum, with values 0 through 5 in
the same order: none, Salts, custom, POSIX, Win32, and unknown. The five native
helpers retain their contracts: count, lowercase text conversion, strict text
parsing, validity, and equality. Parsing an invalid string or a null input
returns `-1` without modifying a supplied output. Symbol spellings such as
`SALTS_ERROR_DOMAIN_WIN32` remain invalid for the native parsing helper.

## Defined handling for the reproduced integer overflow

An independent UBSan run of the original implementation reproduced signed
negation overflow for `cmeta_error_info(INT_MIN)` in
`cmeta_find_custom_error_locked` through `SALTS_ERROR_CUSTOM_DOMAIN`.
The later conversion to a positive `int` had the same risk.

The two decoding macros now use unsigned magnitude and return an `int` result.
Before converting to a positive native code, `INT_MIN` returns the original
unknown-message format, preserving the input code, unknown domain, zero custom
domain, and `UNKNOWN` name. No valid encoded custom code, errno value, or Win32
value changes its meaning. The maximum valid custom code remains `-INT_MAX`.
The native contract runs `INT_MIN` through both decoding macros, descriptor
validation, structured metadata, and the message API under UBSan.

Apart from these bounded changes and the threading include, the complete
implementation reverses to its original blob. The inventory lists every
allowed source transformation literally; removing the overflow fix, changing
capacity, changing message storage, or silently accepting an error fails the
source-preservation check.

## Reflection remains an upper-layer obligation

The original mixed enum test contains seven reflection assertions, including
descriptor name/count, symbol conversion, generated string conversion, and
symbol parsing. Their complete original block is retained verbatim in
`tools/migration/original-error-inventory.json` as
`pending-upstream-reflection-acceptance`.

Core keeps all nine original test registrations (one is Windows-only) and all
native assertions. It does not compile the seven reflection assertions and
does not claim that their original mixed case is fully migrated. CMeta must
later supply its genuine metadata for the native enum and execute those
retained assertions above Core. There is no fabricated `cmeta_enum_desc`,
`cmeta_error_domain_t_meta`, generated reflection facade, or native cast.

## Verification and acceptance boundary

The source gate verifies all three frozen source blobs by reversing only the
documented changes. It also verifies the unchanged four declarations in the
610-function baseline. Negative cases remove or change an API, alter registry
behavior, remove the overflow guard or an original native assertion, add a
CMeta dependency, accept or delete the retained reflection block, and truncate
one of the original inventories. Each must fail.

The native contract additionally exercises concurrent first registration and
thread-local output isolation, all 64 slots and reuse, borrowed pointer
identity and caller storage, all built-in error table entries, descriptor
failures, strict six-domain conversion, native-code precedence, integer limits,
and Result wrappers. Independent installed C11 and C++17 executables include
the installed header and call all four functions through `Salts::Core`.

Run the registered tests after building the complete configured graph:

```sh
python3 -B -m unittest discover -s tests -p test_original_error_provenance.py -v
ctest --test-dir BUILD --output-on-failure --no-tests=error \
  -R '^saltscore[.](original_error|error_native_contract|original_error_source_provenance)$'
ctest --test-dir INSTALLED_BUILD --output-on-failure --no-tests=error \
  -R '^sdk[.]error_(c11|cpp17)$'
```

The dedicated workflow registers Linux Release, ASan/UBSan/LSan, TSan, Windows,
and macOS profiles with exact-head checkout. Its results must be observed on
the actual candidate before any cross-platform claim. Local native tests and
source hashes alone do not establish that claim.

The frozen 2,975-file and 610-function records are unchanged. This supplement
accepts zero original file or API obligations; it supplies auditable source
restoration and bounded native tests for later evidence review. The unresolved
reflection obligation remains visible. AC and Levenshtein remain deferred and
pending, and PRs #72 and #94 remain Draft and unmerged. No presence check or
supplemental manifest makes the final `--require-complete` gate pass.
