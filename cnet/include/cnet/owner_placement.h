#ifndef CNET_OWNER_PLACEMENT_H
#define CNET_OWNER_PLACEMENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNET_OWNER_PLACEMENT_VERSION 1u

/*
 * Pure server-side selection of a fixed final network Owner.  Called only at
 * connection admission, never for an established stream or each TCP packet.
 * Owner indices are the stable [0, owner_count) shard indices.  Their order
 * MUST be identical among listeners for STRICT_KEY deterministic placement.
 *
 * This is a decision ONLY, not a capacity reservation.  The host must still
 * commit against cnet_handoff_reserve() for remote Owners or
 * cnet_manager_reserve() + real CNet admission on the local Owner.
 * A pressure snapshot may be stale; returned success never promises credits.
 * No thread, queue, backend, allocation, connection move or retry is created.
 */

typedef enum cnet_owner_placement_kind {
  CNET_OWNER_PLACE_EXPLICIT = 1,
  CNET_OWNER_PLACE_ROUND_ROBIN = 2,
  CNET_OWNER_PLACE_LOWEST_PRESSURE = 3,
  CNET_OWNER_PLACE_STRICT_KEY = 4,
  CNET_OWNER_PLACE_CUSTOM
} cnet_owner_placement_kind;

typedef struct cnet_owner_placement_hint {
  /* Advisory only; actual reserve remains authoritative. */
  bool eligible;
  /* Lower is better. Caller computes comparable owner-local pressure. */
  uint64_t pressure;
} cnet_owner_placement_hint;

/* Custom selection is evaluated synchronously against the same validated
 * immutable snapshot as built-ins. It creates no reservation or I/O. Returned
 * indices are checked for range and eligibility before publishing a result. */
struct cnet_owner_placement_input;
typedef int (*cnet_owner_placement_input_fn)(void *user, const struct cnet_owner_placement_input *input, size_t *out_index);
typedef struct cnet_owner_placement_input {
  size_t size;
  uint32_t version;
  cnet_owner_placement_kind kind;
  /* Immutable for the duration of one call; indexed by final SG Owner. */
  const cnet_owner_placement_hint *owners;
  size_t owner_count;
  /* Used by EXPLICIT only. An out-of-range id is a configuration error. */
  size_t explicit_owner;
  /* RR start and LOWEST_PRESSURE tie-break. Host provides monotonic ticket. */
  uint64_t sequence;
  /* STRICT_KEY uses key_hash % owner_count; no implicit fallback on FULL. */
  uint64_t key_hash;
  bool key_known;
  cnet_owner_placement_input_fn choose;
  void *choose_user;
} cnet_owner_placement_input;

/*
 * Returns SALTS_OK and selected [0, owner_count) Owner on success.
 * Returns EINVAL on missing/unsupported configuration or unknown strict key;
 * ENOBUFS when no eligible Owner, including pinned strict-key FULL.
 * out_owner is SIZE_MAX on all failures.
 *
 * EXPLICIT / STRICT_KEY: O(1) with no alternative Owner.
 * ROUND_ROBIN / LOWEST_PRESSURE: O(owner_count) over a bounded host topology.
 * No global policy state, locks or actor scheduler are involved.
 */
int cnet_owner_placement_choose(const cnet_owner_placement_input *input,
                                size_t *out_owner);

#ifdef __cplusplus
}
#endif

#endif
