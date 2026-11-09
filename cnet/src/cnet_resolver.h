#ifndef CNET_RESOLVER_H
#define CNET_RESOLVER_H

#include <salts/error_codes.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { CNET_RESOLVER_HOST_CAPACITY = 256, CNET_RESOLVER_ADDRESS_CAPACITY = 128 };

typedef struct cnet_resolver {
  void *impl;
} cnet_resolver;

typedef struct cnet_resolver_query {
  uint32_t slot;
  uint32_t generation;
} cnet_resolver_query;

typedef struct cnet_resolver_config {
  size_t query_capacity;
} cnet_resolver_config;

typedef struct cnet_resolver_result {
  cnet_resolver_query query;
  uintptr_t user_data;
  int status;
  int native_status;
  int timeouts;
  size_t address_length;
  unsigned char address[CNET_RESOLVER_ADDRESS_CAPACITY];
} cnet_resolver_result;

bool cnet_resolver_query_valid(cnet_resolver_query query);
int cnet_resolver_init(cnet_resolver *resolver, const cnet_resolver_config *config);

/**
 * Starts one bounded asynchronous query. The hostname is copied before return.
 * SOCK_STREAM and SOCK_DGRAM are the only accepted socket types.
 */
int cnet_resolver_submit(cnet_resolver *resolver, const char *host, uint16_t port, int socket_type,
                         uintptr_t user_data, cnet_resolver_query *out_query);

#if defined(CNET_INTERNAL_TESTING)
/** Test-only pure regression for provider-independent IPv4/IPv6 port order.
 * Never installed or exported from production Salts::CNet. */
int cnet_resolver_test_apply_requested_port(void *address, size_t address_length,
                                            int family, uint16_t port);
#endif

/** Nonblocking caller-owned c-ares socket and timeout progress. */
int cnet_resolver_poll(cnet_resolver *resolver);

/** True while a query or untaken result retains one bounded slot. */
bool cnet_resolver_has_pending(cnet_resolver *resolver);

/** Logical per-query cancellation; the stable slot is recycled only by take. */
int cnet_resolver_cancel(cnet_resolver *resolver, cnet_resolver_query query);

/** Single-owner nonblocking result take; empty-open returns SALTS_ETIMEDOUT. */
int cnet_resolver_take(cnet_resolver *resolver, cnet_resolver_result *out_result);

/** Stops admission and synchronously cancels all c-ares channel queries. */
int cnet_resolver_close(cnet_resolver *resolver, uint32_t timeout_ms);

/** Requires closed admission and every result to have been taken. */
int cnet_resolver_destroy(cnet_resolver *resolver);

#endif /* CNET_RESOLVER_H */
