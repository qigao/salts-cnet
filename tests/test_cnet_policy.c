#include <cnet/destination_policy.h>
#include <cnet/owner_placement.h>
#include <cnet/recovery_policy.h>
#include <error_codes.h>
#include <stddef.h>
#include <stdint.h>
#include <tinytest.h>

static void destination_contract(void) {
  cnet_destination_hint nodes[] = {
    {10u, 1u, 4u, true}, {20u, 3u, 2u, true}, {30u, 2u, 1u, true}};
  cnet_destination_selection s = {0};
  cnet_destination_result out = {0};
  s.size = sizeof s;
  s.version = CNET_DESTINATION_POLICY_VERSION;
  s.kind = CNET_DESTINATION_EXPLICIT;
  s.endpoints = nodes;
  s.endpoint_count = 3u;
  s.snapshot_generation = 1u;
  s.expires_at_ms = UINT64_MAX;
  s.explicit_endpoint_id = 20u;
  check(cnet_destination_validate(nodes, 3u) == SALTS_OK);
  check(cnet_destination_choose(&s, &out) == SALTS_OK);
  check(out.endpoint_id == 20u && out.index == 1u &&
        out.snapshot_generation == 1u);
  nodes[1].eligible = false;
  check(cnet_destination_choose(&s, &out) == SALTS_ENOBUFS);
  check(out.index == SIZE_MAX && out.endpoint_id == 0u);
  nodes[1].eligible = true;
  s.expires_at_ms = 50u;
  s.now_ms = 50u;
  check(cnet_destination_choose(&s, &out) == SALTS_ETIMEDOUT);
  s.expires_at_ms = UINT64_MAX;
  s.kind = CNET_DESTINATION_WEIGHTED_RR;
  s.sequence = 2u;
  check(cnet_destination_choose(&s, &out) == SALTS_OK);
  check(out.index == 1u && out.endpoint_id == 20u);
  s.kind = CNET_DESTINATION_STRICT_KEY;
  s.key_known = true;
  s.key_hash = UINT64_C(0x123456789);
  check(cnet_destination_choose(&s, &out) == SALTS_OK);
  const size_t strict_winner = out.index;
  nodes[strict_winner].eligible = false;
  check(cnet_destination_choose(&s, &out) == SALTS_ENOBUFS);
  check(out.index == SIZE_MAX); /* no alternative peer / security downgrade */
  nodes[strict_winner].eligible = true;
  nodes[1].endpoint_id = 10u;
  check(cnet_destination_validate(nodes, 3u) == SALTS_EINVAL);
  check(cnet_destination_choose(&s, &out) == SALTS_EINVAL);
}

static void owner_contract(void) {
  cnet_owner_placement_hint owners[] = {{true, 3u}, {true, 1u}, {true, 2u}};
  cnet_owner_placement_input input = {0};
  size_t selected = SIZE_MAX;
  input.size = sizeof input;
  input.version = CNET_OWNER_PLACEMENT_VERSION;
  input.owners = owners;
  input.owner_count = 3u;
  input.kind = CNET_OWNER_PLACE_LOWEST_PRESSURE;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_OK);
  check(selected == 1u);
  input.kind = CNET_OWNER_PLACE_STRICT_KEY;
  input.key_known = true;
  input.key_hash = 5u;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_OK);
  check(selected == 2u);
  owners[2].eligible = false;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_ENOBUFS);
  check(selected == SIZE_MAX);
  input.kind = CNET_OWNER_PLACE_EXPLICIT;
  input.explicit_owner = 1u;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_OK);
  check(selected == 1u);
  input.version = 999u;
  check(cnet_owner_placement_choose(&input, &selected) == SALTS_EINVAL);
  check(selected == SIZE_MAX);
}

static void recovery_contract(void) {
  cnet_reconnect_config config = {0};
  cnet_reconnect_state state = {0};
  cnet_reconnect_ticket first = {0}, second = {0};
  cnet_reconnect_snapshot snapshot = {0};
  uint64_t wait_ms = 0u;
  config.size = sizeof config;
  config.version = CNET_RECOVERY_POLICY_VERSION;
  config.max_attempts = 2u;
  config.deadline_ms = 1000u;
  config.initial_backoff_ms = 10u;
  config.maximum_backoff_ms = 100u;
  config.jitter_seed = 17u;
  check(cnet_reconnect_init(&state, &config) == SALTS_OK);
  check(cnet_reconnect_begin(&state, 10u, &first, &wait_ms) == SALTS_OK);
  check(first.generation != 0u && first.state == (uintptr_t)&state);
  check(cnet_reconnect_connected(&state, first, 11u) == SALTS_OK);
  check(cnet_reconnect_protocol_ready(&state, first, 12u) == SALTS_OK);
  check(cnet_reconnect_get_snapshot(&state, &snapshot) == SALTS_OK);
  check(snapshot.protocol_ready && snapshot.attempts == 0u);
  check(cnet_reconnect_lost(&state, first, CNET_RECONNECT_TRANSIENT,
                            20u, 2000u) == SALTS_OK);
  check(cnet_reconnect_get_snapshot(&state, &snapshot) == SALTS_OK);
  check(snapshot.next_attempt_ms > 20u && snapshot.next_attempt_ms < 2000u);
  check(cnet_reconnect_begin(&state, 20u, &second, &wait_ms) == SALTS_EBUSY);
  check(second.generation == 0u && wait_ms != 0u);
  check(cnet_reconnect_begin(&state, snapshot.next_attempt_ms,
                             &second, &wait_ms) == SALTS_OK);
  check(second.generation > first.generation);
  check(cnet_reconnect_failed(&state, second, CNET_RECONNECT_SECURITY,
                               snapshot.next_attempt_ms) == SALTS_OK);
  check(cnet_reconnect_begin(&state, snapshot.next_attempt_ms,
                             &second, &wait_ms) == SALTS_ESHUTDOWN);
  check(second.generation == 0u);
}

spec("CNet policy without a provider") {
  it("preserves destination policy validation and strict-key no-downgrade") {
    destination_contract();
  }
  it("preserves owner placement selection and version rejection") {
    owner_contract();
  }
  it("preserves reconnect lifecycle, deadlines and security shutdown") {
    recovery_contract();
  }
}
