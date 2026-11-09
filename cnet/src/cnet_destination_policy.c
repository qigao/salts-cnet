#include <cnet/destination_policy.h>
#include <core/error_codes.h>

int cnet_destination_validate(const cnet_destination_hint *endpoints, size_t count) {
  if (endpoints == NULL || count == 0u) return SALTS_EINVAL;
  for (size_t i = 0u; i < count; ++i) {
    if (endpoints[i].endpoint_id == 0u || endpoints[i].weight == 0u ||
        (i != 0u && endpoints[i - 1u].endpoint_id >= endpoints[i].endpoint_id))
      return SALTS_EINVAL;
  }
  return SALTS_OK;
}

static size_t next_index(size_t index, size_t count) {
  return index + 1u == count ? 0u : index + 1u;
}

/* Deterministic 64-bit avalanche permutation (odd multipliers, xor-shifts).
 * Each endpoint_id scores independently; removing an unrelated endpoint
 * cannot change the winning eligible/pinned identity for a given key.
 */
static uint64_t cnet_destination_mix64(uint64_t value) {
  value ^= value >> 30u;
  value *= UINT64_C(0xbf58476d1ce4e5b9);
  value ^= value >> 27u;
  value *= UINT64_C(0x94d049bb133111eb);
  return value ^ (value >> 31u);
}

static uint64_t cnet_destination_rendezvous_score(uint64_t key_hash, uint64_t endpoint_id) {
  const uint64_t key = cnet_destination_mix64(key_hash ^ UINT64_C(0x9e3779b97f4a7c15));
  const uint64_t remote = cnet_destination_mix64(endpoint_id ^ UINT64_C(0xd6e8feb86659fd93));
  return cnet_destination_mix64(key ^ remote);
}

int cnet_destination_choose(const cnet_destination_selection *selection,
                            cnet_destination_result *out) {
  size_t index, best;
  uint64_t total = 0u, offset, best_score = 0u;
  if (out == NULL) return SALTS_EINVAL;
  *out = (cnet_destination_result){0u, 0u, SIZE_MAX};
  if (selection == NULL || selection->size != sizeof(*selection) ||
      selection->version != CNET_DESTINATION_POLICY_VERSION ||
      selection->snapshot_generation == 0u ||
      cnet_destination_validate(selection->endpoints, selection->endpoint_count) != SALTS_OK)
    return SALTS_EINVAL;
  if (selection->expires_at_ms != UINT64_MAX &&
      selection->now_ms >= selection->expires_at_ms)
    return SALTS_ETIMEDOUT;

  switch (selection->kind) {
    case CNET_DESTINATION_CUSTOM: {
      if (selection->choose == NULL) return SALTS_EINVAL;
      index = SIZE_MAX;
      int status = selection->choose(selection->choose_user, selection, &index);
      if (status != SALTS_OK) return status;
      if (index >= selection->endpoint_count) return SALTS_EINVAL;
      if (!selection->endpoints[index].eligible) return SALTS_ENOBUFS;
      goto selected;
    }

    case CNET_DESTINATION_EXPLICIT:
      for (index = 0u; index < selection->endpoint_count; ++index) {
        if (selection->endpoints[index].endpoint_id ==
            selection->explicit_endpoint_id) {
          if (!selection->endpoints[index].eligible) return SALTS_ENOBUFS;
          goto selected;
        }
      }
      return SALTS_ENOENT;

    case CNET_DESTINATION_STRICT_KEY:
      if (!selection->key_known) return SALTS_EINVAL;
      /*
       * Hash stable IDs, not snapshot indices. Include ineligible endpoints
       * in the contest, then reject if the winner is unavailable: skipping
       * them would silently move a strict key to a different remote.
       */
      best = SIZE_MAX;
      for (index = 0u; index < selection->endpoint_count; ++index) {
        const uint64_t score = cnet_destination_rendezvous_score(
            selection->key_hash, selection->endpoints[index].endpoint_id);
        if (best == SIZE_MAX || score > best_score) {
          best = index;
          best_score = score;
        }
      }
      if (!selection->endpoints[best].eligible) return SALTS_ENOBUFS;
      index = best;
      goto selected;

    case CNET_DESTINATION_ROUND_ROBIN:
      index = (size_t)(selection->sequence % selection->endpoint_count);
      for (size_t i = 0u; i < selection->endpoint_count; ++i) {
        if (selection->endpoints[index].eligible) goto selected;
        index = next_index(index, selection->endpoint_count);
      }
      return SALTS_ENOBUFS;

    case CNET_DESTINATION_LEAST_INFLIGHT:
      best = SIZE_MAX;
      index = (size_t)(selection->sequence % selection->endpoint_count);
      for (size_t i = 0u; i < selection->endpoint_count; ++i) {
        if (selection->endpoints[index].eligible &&
            (best == SIZE_MAX ||
             selection->endpoints[index].inflight < selection->endpoints[best].inflight))
          best = index;
        index = next_index(index, selection->endpoint_count);
      }
      if (best == SIZE_MAX) return SALTS_ENOBUFS;
      index = best;
      goto selected;

    case CNET_DESTINATION_WEIGHTED_RR:
      for (index = 0u; index < selection->endpoint_count; ++index) {
        const cnet_destination_hint *hint = &selection->endpoints[index];
        if (!hint->eligible) continue;
        if (total > UINT64_MAX - hint->weight) return SALTS_ERANGE;
        total += hint->weight;
      }
      if (total == 0u) return SALTS_ENOBUFS;
      offset = selection->sequence % total;
      for (index = 0u; index < selection->endpoint_count; ++index) {
        const cnet_destination_hint *hint = &selection->endpoints[index];
        if (!hint->eligible) continue;
        if (offset < hint->weight) goto selected;
        offset -= hint->weight;
      }
      return SALTS_EPROTO; /* validated total and weights must select a slot */

    default:
      return SALTS_EINVAL;
  }

selected:
  out->snapshot_generation = selection->snapshot_generation;
  out->endpoint_id = selection->endpoints[index].endpoint_id;
  out->index = index;
  return SALTS_OK;
}
