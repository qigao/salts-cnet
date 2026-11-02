#include <cnet/owner_placement.h>

#include <error_codes.h>

static size_t cnet_owner_placement_next(size_t index, size_t count) {
  return index + 1u == count ? 0u : index + 1u;
}

int cnet_owner_placement_choose(const cnet_owner_placement_input *input,
                                size_t *out_owner) {
  size_t index;
  size_t best;
  if (out_owner == NULL) return SALTS_EINVAL;
  *out_owner = SIZE_MAX;
  if (input == NULL || input->size != sizeof(*input) ||
      input->version != CNET_OWNER_PLACEMENT_VERSION ||
      input->owners == NULL || input->owner_count == 0u)
    return SALTS_EINVAL;

  switch (input->kind) {
    case CNET_OWNER_PLACE_CUSTOM: {
      if (input->choose == NULL) return SALTS_EINVAL;
      index = SIZE_MAX;
      int status = input->choose(input->choose_user, input, &index);
      if (status != SALTS_OK) return status;
      if (index >= input->owner_count) return SALTS_EINVAL;
      if (!input->owners[index].eligible) return SALTS_ENOBUFS;
      *out_owner = index;
      return SALTS_OK;
    }

    case CNET_OWNER_PLACE_EXPLICIT:
      if (input->explicit_owner >= input->owner_count) return SALTS_EINVAL;
      index = input->explicit_owner;
      if (!input->owners[index].eligible) return SALTS_ENOBUFS;
      *out_owner = index;
      return SALTS_OK;

    case CNET_OWNER_PLACE_STRICT_KEY:
      if (!input->key_known) return SALTS_EINVAL;
      index = (size_t)(input->key_hash % input->owner_count);
      if (!input->owners[index].eligible) return SALTS_ENOBUFS;
      *out_owner = index;
      return SALTS_OK;

    case CNET_OWNER_PLACE_ROUND_ROBIN:
      index = (size_t)(input->sequence % input->owner_count);
      for (size_t examined = 0u; examined < input->owner_count; ++examined) {
        if (input->owners[index].eligible) {
          *out_owner = index;
          return SALTS_OK;
        }
        index = cnet_owner_placement_next(index, input->owner_count);
      }
      return SALTS_ENOBUFS;

    case CNET_OWNER_PLACE_LOWEST_PRESSURE:
      index = (size_t)(input->sequence % input->owner_count);
      best = SIZE_MAX;
      for (size_t examined = 0u; examined < input->owner_count; ++examined) {
        if (input->owners[index].eligible &&
            (best == SIZE_MAX ||
             input->owners[index].pressure < input->owners[best].pressure))
          best = index;
        index = cnet_owner_placement_next(index, input->owner_count);
      }
      if (best == SIZE_MAX) return SALTS_ENOBUFS;
      *out_owner = best;
      return SALTS_OK;

    default:
      return SALTS_EINVAL;
  }
}
