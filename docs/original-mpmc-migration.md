# Original MPMC priority queue migration

`Salts::Concurrency` owns the original seven public
`bucket_priority_queue_mpmc_*` functions. There is no additional queue library,
CMeta runtime, reactive CFlow dependency or alternate Disruptor implementation.
The queue keeps four priority buckets, FIFO within a bucket, one shared logical
consumer per bucket, caller-owned output storage and the original explicit
initialization / quiescent destruction contract. `max_consumers` retains its
original compatibility meaning. Blocking timeouts keep their original relative
wait semantics; this migration does not change them into absolute deadlines.

## Frozen source inputs

All three inputs are from `qigao/salts`
`386f81328c656f416d61a6d2ef662f05443e1b4a`, already enumerated in the unchanged
2,975-file inventory.

| Original path | Original Git blob | Current owner |
| --- | --- | --- |
| `utils/include/bucket_priority_queue_mpmc.h` | `6179fb4e16f407e00a2ab2bc57e258134f389ae6` | `concurrency/include/bucket_priority_queue_mpmc.h` |
| `utils/src/bucket_priority_queue_mpmc.c` | `ff8e503abbafff7cb952e8c6575c7f6cbb6e1605` | `concurrency/src/bucket_priority_queue_mpmc.c` |
| `utils/tests/test_bucket_priority_queue_mpmc.c` | `5d1498d3f0fd13a9d0619914c644baaaf0bd077e` | `concurrency/tests/test_bucket_priority_queue_mpmc.c` |

The header replaces old umbrella includes with canonical native headers and
plain declarations. The original test body is unchanged; only its thread header
path changes. The implementation uses the same Platform mutex/condition and
Concurrency Disruptor owners as the existing SDK.

## Two reproduced races corrected

The independent four-producer / three-consumer test exposed two separate TSan
failures before this candidate could qualify:

1. `empty()` read `next_read_sequence` concurrently with `pop_locked()` updating
   it. The query now uses the existing notification mutex. It remains an
   approximate query with respect to concurrent publication, while its internal
   read is synchronized.
2. Disruptor's cached `slowest_consumer` cursor was stored with relaxed ordering.
   Another producer could acquire that cache value and reuse a slot without
   inheriting the consumer's completed-read ordering. Its three runtime cache
   stores now release the acquired consumer/completion state to the existing
   acquire loads. Initialization remains relaxed. Slot layout, sequence values,
   public ABI, capacity and scheduling policy are unchanged.

The original MPMC test and independent delivery oracle passed TSan after both
corrections. The eight original Concurrency test programs were then restored
and also passed TSan, including the actual Disruptor broadcast and worker-pool
handoffs, both thread pools, deadline queue, RCU and typed C/C++ primitives.
The ten-test MPMC plus original-Concurrency group passed without suppressions.
The oracle also checks priority,
FIFO, capacity rejection, failed-pop output preservation, timeout, destruction
and all 4,096 unique values. Installed C11 and C++17 consumers run the same
independent contract through the installed shared Concurrency owner.

`.github/workflows/mpmc-native.yml` requires Linux Release, ASan/UBSan, TSan,
Windows and macOS on the candidate SHA. Local success is not a substitute for
those exact-head results. This source addition does not rewrite the frozen
610-function inventory or mark any other pending migration complete.
