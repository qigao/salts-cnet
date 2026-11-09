# Original Salts utils/Core migration parity — work in progress

## Full original utils tree (not just include/src/tests)

The original `qigao/salts@codex/finish-1181-session/utils/` Git tree
`9c5b53d7194d142a89be576c3314ee4bfd569a37` contains **175 blob files**
in exactly eight first-level directories, plus two root files. The earlier
claim of 35 headers, 31 implementation files and 69 test tree entries
counted only three subdirectories; it was not a complete migration inventory.

| Original utils directory | Blob files | No same-basename file in this PR HEAD* |
| --- | ---: | ---: |
| `include/` | 35 | 18 |
| `src/` | 31 | 18 |
| `tests/` | 68 | 47 |
| `parser/` | 5 | 0 |
| `benchmarks/` | 11 | 10 |
| `examples/` | 5 | 4 |
| `fuzz/` | 7 | 5 |
| `verification/` | 11 | 10 |
| Root `CMakeLists.txt`, `CRYPTO.md` | 2 | 1 |
| **Total** | **175** | **113** |

*This is an automated **filename-only** preliminary screen against
`salts-core` commit `102fe337`. It is not an audit of completed features:
renamed files can implement the same operations, while identical filenames
can contain missing APIs. The immutable per-file original path, Git SHA,
owner proposal, source-independent destination candidates and unresolved
state are all in `tools/original_utils_full_inventory.json`.

Full acceptance additionally requires exact original-function parity,
behavior, source provenance, module owner, original positive/negative tests,
C11/C++17 consumer, sanitizer and platform evidence. The
`audit_original_utils_tree.py --full` gate **must stay red** until all 175
entries have evidence; a green snapshot inventory check only proves nobody
silently discarded the baseline.

The `benchmarks/`, `fuzz/`, `examples/` and `verification/` material
must also be preserved and migrated to the proper existing source owner
(`qigao/crypto` for Crypto functions, `Salts::FS` for FS,
`Salts::Concurrency` for queue/Disruptor and `Salts::Core` for Core).
Do not duplicate providers, resurrect CMeta dependencies or dismiss
non-production verification assets as expendable.

**Blocking issue:** [#71](https://github.com/qigao/salts-core/issues/71).
**Historical baseline:** `qigao/salts@codex/finish-1181-session`, `utils/` Git tree
`9c5b53d7194d142a89be576c3314ee4bfd569a37`.
The original `utils/include` has **35 headers**, `utils/src` has **30 C files plus one
internal header**, and `utils/tests` has **69 entries including subdirectories**.

This document tracks **functional equivalence**, not just file presence. Nothing
is considered fully migrated until production source, public APIs, ownership,
negative and positive tests, and three-OS CI are verified. Do **not** remove a
function because its old implementation included CMeta reflection.

## Stage A: native string/allocator recovery (candidate, not accepted yet)

| Original source | Destination | Status |
| --- | --- | --- |
| `utils/include/tstr.h`, `utils/src/tstr.c` | `core/include/tstr.h`, `core/src/tstr.c` | C11 port, CI pending |
| `utils/include/vstr.h`, `utils/src/vstr.c` | `core/include/vstr.h`, `core/src/vstr.c` | Original view operations restored; no CMeta reflection, CI pending |
| `utils/include/str.h` | `core/include/str.h` | Same original source, CI pending |
| `utils/include/memory_pool.h`, `utils/src/memory_pool.c` | `core/include/memory_pool.h`, `core/src/memory_pool.c` | Plain C11, CI pending |
| `vendor/sds/{sds.c,sds.h,sdsalloc.h,LICENSE}` | `core/src/sds/` | Original bytes, private Core-owned storage; BSD license retained |
| `utils/tests/test_tstr_v2_contract.c` | `core/tests/test_tstr_v2_contract.c` | Exact original TinyTest case, optional profile |

The old SIMD-only vector operations are replaced with *bounded C11 byte scans*
for independent baseline Core builds; exported behavior is retained but
performance parity is **not yet claimed**. New real C11 and installed C11/C++17
consumers are required. `vstr_from_buf(NULL, n)` preserves the current strict
native invalid-range contract rather than reintroducing old silent truncation.

| `utils/include/object_pool.h`, `utils/src/object_pool.c` | `core/include/object_pool.h`, `core/src/object_pool.c` | Original object pool source and tests, CI pending |

| `utils/include/bucket_priority_queue.h`, `utils/src/bucket_priority_queue.c` | `core/include/bucket_priority_queue.h`, `core/src/bucket_priority_queue.c` | Original FIFO/priority queue source and tests, CI pending |

| `utils/include/ring_buffer_spsc.h`, `utils/src/ring_buffer_spsc.c` | `concurrency/include/ring_buffer_spsc.h`, `concurrency/src/ring_buffer_spsc.c` | Original SPSC facade over the sole native `cmeta_spsc_ring` implementation; CI pending |
| `utils/include/bucket_priority_queue_spsc.h`, `utils/src/bucket_priority_queue_spsc.c` | `concurrency/include/bucket_priority_queue_spsc.h`, `concurrency/src/bucket_priority_queue_spsc.c` | Original fixed capacity SPSC priority queue, CI pending |

| `utils/parser/fmt_lexer.h`, `utils/parser/fmt_lexer.re` | `core/parser/fmt_lexer.h`, `fmt_lexer.re`, `fmt_lexer.c` | Bounded scanner port, original 8-case lexer contract and clean SDK tests, CI pending |

| `utils/include/fmt.h`, `utils/src/fmt.c` | `core/include/fmt.h`, `core/src/fmt.c` | Original typed C11/C++17 renderer, standalone native enum metadata (no CMeta runtime), original tests; CI pending |

| `utils/parser/log_pattern_lexer.h`, `utils/parser/log_pattern_lexer.re` | `core/parser/log_pattern_lexer.h`, `.re`, `.c` | All eight original placeholder tokens and unknown/literal grammar; source and installed tests, CI pending |

| `utils/include/tlog.h`, `utils/src/tlog.c` | `core/include/tlog.h`, `core/src/tlog.c` | Original async Disruptor logger, FS file sinks, native level/entry metadata and original tests, CI pending |
| `utils/include/tlog_helper.h` | `core/include/tlog_helper.h` | Same original C++17 container formatter helpers, CI pending |

| `utils/include/cmeta_uuid.h`, `utils/src/cmeta_uuid.c` | `core/include/cmeta_uuid.h`, `core/src/cmeta_uuid.c` | Original RFC v4/v7 UUID using canonical Platform clock/CSPRNG; C11/C++17 tests, CI pending |

| `utils/include/cmeta_bytes.h`, `utils/src/cmeta_bytes.c` | `core/include/cmeta_bytes.h`, `core/src/cmeta_bytes.c` | Original hard-bounded owning byte accumulator, nine functions, original eight-case TinyTest and installed C11/C++17 tests, CI pending |

| `utils/include/cmeta_simd_scan.h`, `utils/src/cmeta_simd_scan.c` | `core/include/cmeta_simd_scan.h`, `core/src/cmeta_simd_scan.c` | Seven original binary-safe bounded scan functions, source behavior tests and installed SDK; C11 scalar backend, SIMD throughput parity pending |

## Still missing: full original utils functionality

**Not fully accepted, do not mark migration complete or release:**

AC (`ac_automaton`) and Levenshtein (`levenshtein_automaton`) are excluded
from development and acceptance in this iteration at the user's direction.
They remain unresolved in `pending_groups.deferred_by_user`; `--full` still
counts both as pending. Their two original headers, two implementations and
shared `utils/tests/test_string_automata.c` remain in the original inventory,
along with all **26 public functions** (16 AC, 10 Levenshtein). Deferral does
not qualify any of these **5 files** or reduce the **2,975-file / 610-function**
final completeness gate.

The existing byte and UTF-8 behavior, regex error handling and resource
ownership remain unchanged. [PR #72](https://github.com/qigao/salts-core/pull/72)
and [PR #94](https://github.com/qigao/salts-core/pull/94) remain **Draft; do not
merge**. Green structural checks cannot accept unresolved migration work.

- Logging/format: `tlog.h`, `tlog_helper.h`, `tlog.c`; the lexer now has a separate native owner. sync/async sinks and flush
  parity, fatal logging, bounded queue and source capture all remain pending.
- Containers and algorithms: `bucket_priority_queue_mpmc`, `re`, `enum_utils`.
- mmap/UUID/zstd/SIMD/error: original `cmeta_mmap`,
  `cmeta_zstd`, `cmeta_error`.
- Requires a per-symbol difference audit, **not name matching**:
  `base64_utils`, `cmeta_buffer`, `cmeta_bytes`, `cmeta_fs*`,
  `cmeta_process`, `cmeta_thread`, `platform`, crypto ownership,
  `cmeta_cmeta_data`, `cmeta_mdns`.

**Permanent build contract:** Only `Salts::Core` owns these Core functions.
No additional provider, no CMeta runtime dependency, no legacy fallbacks.
Remaining functionality must be implemented in the appropriate source module
and verified with the original tests, ASan/UBSan/TSan, Linux/macOS/Windows, and
installed C11/C++17 consumers. PR #72 and PR #94 stay Draft; exact-HEAD CI
success alone does not close the final completeness gate. Issue #71 stays Open
until every original function is mapped and qualified.
