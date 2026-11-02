/* Failure-atomic fake Readiness backend against the real copied state
 * machine in the single Salts::Platform shared owner. No OS descriptor,
 * old Salts library, test adapter or provider fallback is involved.
 */
#include "../platform/src/readiness_internal.h"
#include <error_codes.h>
#include <readiness.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <tinytest.h>

typedef struct fake_backend {
  uint64_t token;
  uint64_t arm_token;
  unsigned register_calls;
  unsigned arm_calls;
  unsigned unarm_calls;
  unsigned close_calls;
  unsigned shutdown_calls;
  unsigned destroy_calls;
  unsigned fail_register;
  unsigned fail_arm;
  unsigned fail_unarm;
  unsigned fail_close;
  unsigned fail_shutdown;
  int resource_owned_by_caller;
} fake_backend;

typedef struct callback_observer {
  unsigned calls;
  cmeta_readiness_events events;
  int status;
} callback_observer;

static void observe(void *user, cmeta_readiness_events events, int status) {
  callback_observer *observer = (callback_observer *)user;
  ++observer->calls;
  observer->events = events;
  observer->status = status;
}

static int fake_register(void *user, intptr_t native_resource, uint64_t token) {
  fake_backend *fake = (fake_backend *)user;
  ++fake->register_calls;
  if (fake->fail_register) {
    --fake->fail_register;
    return SALTS_EIO;
  }
  (void)native_resource;
  fake->token = token;
  return SALTS_OK;
}

static int fake_arm(void *user, uint64_t token, uint64_t arm_token,
                    cmeta_readiness_events interests) {
  fake_backend *fake = (fake_backend *)user;
  ++fake->arm_calls;
  if (fake->fail_arm) {
    --fake->fail_arm;
    return SALTS_EIO;
  }
  (void)interests;
  if (token != fake->token) return SALTS_EINVAL;
  fake->arm_token = arm_token;
  return SALTS_OK;
}

static int fake_unarm(void *user, uint64_t token) {
  fake_backend *fake = (fake_backend *)user;
  ++fake->unarm_calls;
  if (fake->fail_unarm) {
    --fake->fail_unarm;
    return SALTS_EIO;
  }
  return token == fake->token ? SALTS_OK : SALTS_EINVAL;
}

static int fake_close(void *user, uint64_t token) {
  fake_backend *fake = (fake_backend *)user;
  ++fake->close_calls;
  if (fake->fail_close) {
    --fake->fail_close;
    return SALTS_EIO;
  }
  return token == fake->token ? SALTS_OK : SALTS_EINVAL;
}

static int fake_shutdown(void *user) {
  fake_backend *fake = (fake_backend *)user;
  ++fake->shutdown_calls;
  if (fake->fail_shutdown) {
    --fake->fail_shutdown;
    return SALTS_EIO;
  }
  return SALTS_OK;
}

static void fake_destroy(void *user) {
  fake_backend *fake = (fake_backend *)user;
  ++fake->destroy_calls;
  /* This fixture is caller-owned; destroying a backend cannot free it. */
  fake->resource_owned_by_caller = 1;
}

static const cmeta_readiness_backend_ops fake_ops = {
    fake_register, fake_arm, fake_unarm, fake_close,
    fake_shutdown, fake_destroy
};

static void test_fault_rollback_and_reuse(void) {
  fake_backend fake = {0};
  cmeta_readiness_backend_ops invalid = fake_ops;
  cmeta_readiness_config config = {1u, 1u};
  cmeta_readiness_reactor reactor = {0};
  cmeta_readiness_registration reg = {0}, rejected = {0};
  cmeta_readiness_stats stats = {0};
  callback_observer observe_result = {0};
  uint64_t first_generation_token, current_arm;

  invalid.arm = NULL;
  check(cmeta_readiness_reactor_init_backend(
      &reactor, &config, &invalid, &fake) == SALTS_EINVAL);
  check(reactor.impl == NULL);
  check(cmeta_readiness_reactor_init_backend(
      &reactor, &config, &fake_ops, &fake) == SALTS_OK);
  fake.fail_register = 1u;
  check(cmeta_readiness_register(&reactor, 101, &reg) == SALTS_EIO);
  check(reg.impl == NULL);
  check(cmeta_readiness_reactor_stats(&reactor, &stats) == SALTS_OK);
  check(stats.registered_count == 0u);
  check(cmeta_readiness_register(&reactor, 101, &reg) == SALTS_OK);
  check(fake.token != 0u && reg.impl != NULL);
  check(cmeta_readiness_register(&reactor, 102, &rejected) == SALTS_ENOBUFS);
  check(rejected.impl == NULL);
  first_generation_token = fake.token;

  fake.fail_arm = 1u;
  check(cmeta_readiness_arm(&reg, SALTS_READINESS_EVENT_READ,
                            observe, &observe_result) == SALTS_EIO);
  check(reg.impl != NULL);
  check(cmeta_readiness_reactor_stats(&reactor, &stats) == SALTS_OK);
  check(stats.armed_count == 0u);
  check(cmeta_readiness_arm(&reg, SALTS_READINESS_EVENT_READ,
                            observe, &observe_result) == SALTS_OK);
  check(fake.arm_token != 0u);
  current_arm = fake.arm_token;
  check(cmeta_readiness_backend_dispatch_generation(
      &reactor, fake.token, current_arm + 1u,
      SALTS_READINESS_EVENT_READ, SALTS_OK) == SALTS_OK);
  check(observe_result.calls == 0u);
  check(cmeta_readiness_backend_dispatch_generation(
      &reactor, fake.token, current_arm,
      SALTS_READINESS_EVENT_READ, SALTS_OK) == SALTS_OK);
  check(observe_result.calls == 1u &&
        observe_result.events == SALTS_READINESS_EVENT_READ &&
        observe_result.status == SALTS_OK);
  check(cmeta_readiness_backend_dispatch_generation(
      &reactor, fake.token, current_arm,
      SALTS_READINESS_EVENT_READ, SALTS_OK) == SALTS_OK);
  check(observe_result.calls == 1u);

  check(cmeta_readiness_arm(&reg, SALTS_READINESS_EVENT_READ,
                            observe, &observe_result) == SALTS_OK);
  fake.fail_unarm = 1u;
  check(cmeta_readiness_unarm(&reg) == SALTS_EIO);
  check(cmeta_readiness_reactor_stats(&reactor, &stats) == SALTS_OK);
  check(stats.armed_count == 1u);
  check(cmeta_readiness_unarm(&reg) == SALTS_OK);
  check(cmeta_readiness_reactor_stats(&reactor, &stats) == SALTS_OK);
  check(stats.armed_count == 0u);

  check(cmeta_readiness_arm(&reg, SALTS_READINESS_EVENT_READ,
                            observe, &observe_result) == SALTS_OK);
  fake.fail_close = 1u;
  check(cmeta_readiness_close(&reg) == SALTS_EIO);
  check(reg.impl != NULL);
  check(cmeta_readiness_reactor_stats(&reactor, &stats) == SALTS_OK);
  check(stats.registered_count == 1u);
  check(cmeta_readiness_close(&reg) == SALTS_OK);
  check(reg.impl == NULL);
  check(cmeta_readiness_reactor_stats(&reactor, &stats) == SALTS_OK);
  check(stats.registered_count == 0u && stats.armed_count == 0u);
  check(stats.rejected_full == 1u && stats.stale_events == 1u &&
        stats.duplicate_events == 1u);

  /* A new slot incarnation cannot accept old generation events. */
  check(cmeta_readiness_register(&reactor, 103, &reg) == SALTS_OK);
  check(fake.token != first_generation_token);
  check(cmeta_readiness_arm(&reg, SALTS_READINESS_EVENT_READ,
                            observe, &observe_result) == SALTS_OK);
  check(cmeta_readiness_backend_dispatch(
      &reactor, first_generation_token, SALTS_READINESS_EVENT_READ,
      SALTS_OK) == SALTS_OK);
  check(observe_result.calls == 1u);
  check(cmeta_readiness_backend_dispatch_generation(
      &reactor, fake.token, fake.arm_token,
      SALTS_READINESS_EVENT_READ, SALTS_OK) == SALTS_OK);
  check(observe_result.calls == 2u);
  check(cmeta_readiness_close(&reg) == SALTS_OK);

  check(cmeta_readiness_reactor_destroy(&reactor) == SALTS_EBUSY);
  fake.fail_shutdown = 1u;
  check(cmeta_readiness_reactor_shutdown(&reactor) == SALTS_EIO);
  check(reactor.impl != NULL);
  check(cmeta_readiness_reactor_shutdown(&reactor) == SALTS_OK);
  check(cmeta_readiness_reactor_shutdown(&reactor) == SALTS_EALREADY);
  check(cmeta_readiness_reactor_destroy(&reactor) == SALTS_OK);
  check(reactor.impl == NULL && fake.destroy_calls == 1u);
  check(fake.resource_owned_by_caller == 1);
}

static void test_terminal_delivery_and_shutdown_cleanup(void) {
  fake_backend fake = {0};
  cmeta_readiness_reactor reactor = {0};
  cmeta_readiness_config config = {1u, 1u};
  cmeta_readiness_registration reg = {0};
  callback_observer callback = {0};
  check(cmeta_readiness_reactor_init_backend(
      &reactor, &config, &fake_ops, &fake) == SALTS_OK);
  check(cmeta_readiness_register(&reactor, 203, &reg) == SALTS_OK);
  check(cmeta_readiness_arm(&reg, SALTS_READINESS_EVENT_READ,
                            observe, &callback) == SALTS_OK);
  check(cmeta_readiness_reactor_shutdown(&reactor) == SALTS_OK);
  check(callback.calls == 1u);
  check(callback.events == 0u && callback.status == SALTS_ESHUTDOWN);
  check(cmeta_readiness_close(&reg) == SALTS_OK);
  check(cmeta_readiness_reactor_destroy(&reactor) == SALTS_OK);
  check(fake.destroy_calls == 1u);
}

static void test_backend_fatal_terminal_once(void) {
  fake_backend fake = {0};
  cmeta_readiness_reactor reactor = {0};
  cmeta_readiness_config config = {1u, 1u};
  cmeta_readiness_registration reg = {0};
  callback_observer callback = {0};
  check(cmeta_readiness_reactor_init_backend(
      &reactor, &config, &fake_ops, &fake) == SALTS_OK);
  check(cmeta_readiness_register(&reactor, 303, &reg) == SALTS_OK);
  check(cmeta_readiness_arm(&reg, SALTS_READINESS_EVENT_READ,
                            observe, &callback) == SALTS_OK);
  check(cmeta_readiness_backend_fail(&reactor, SALTS_EIO) == SALTS_OK);
  check(callback.calls == 1u && callback.events == 0u &&
        callback.status == SALTS_EIO);
  check(cmeta_readiness_backend_fail(&reactor, SALTS_EIO) == SALTS_EALREADY);
  check(cmeta_readiness_reactor_shutdown(&reactor) == SALTS_OK);
  check(callback.calls == 1u);
  check(cmeta_readiness_close(&reg) == SALTS_OK);
  check(cmeta_readiness_reactor_destroy(&reactor) == SALTS_OK);
  check(fake.destroy_calls == 1u);
}

spec("Platform Readiness fault-atomic owner") {
  it("rolls back failed registration, arm, unarm and close operations") {
    test_fault_rollback_and_reuse();
  }
  it("delivers one terminal shutdown callback and destroys once") {
    test_terminal_delivery_and_shutdown_cleanup();
  }
  it("delivers one terminal fatal-backend callback") {
    test_backend_fatal_terminal_once();
  }
}
