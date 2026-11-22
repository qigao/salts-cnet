#ifndef CNET_NAME_LOOKUP_H
#define CNET_NAME_LOOKUP_H

#include <cnet/export.h>
#include <cnet/cnet.h>
#ifdef __cplusplus
extern "C" {
#endif
#define CNET_NAME_LOOKUP_API_VERSION 1u
typedef struct cnet_name_lookup { void *impl; } cnet_name_lookup;
typedef struct cnet_name_query { uint64_t owner; uint32_t slot, generation; } cnet_name_query;
typedef struct cnet_ip_address { cnet_datagram_address_family family; uint8_t address[16]; } cnet_ip_address;
typedef struct cnet_name_lookup_config {
  size_t size;
  uint32_t version;
  size_t query_capacity, results_per_query, max_name_bytes;
  uint32_t timeout_ms;
  /** Optional copied c-ares numeric server CSV for deterministic/private DNS.
   * NULL uses the system DNS configuration. No event thread is created. */
  const char *servers_csv;
} cnet_name_lookup_config;
SALTS_CNET_EXPORT
void cnet_name_lookup_config_init(cnet_name_lookup_config *config);
/** Single serialized owner. Copies config; query/result storage has hard bounds.
 * Acquires the module itself. Init errors publish no owner. No worker thread. */
SALTS_CNET_EXPORT
int cnet_name_lookup_init(cnet_name_lookup *lookup, const cnet_name_lookup_config *config);
/** Accepts numeric IPv4/IPv6 and ASCII LDH hostnames only. Labels are
 * 1..63 bytes, max 253 bytes excluding optional final dot; uppercase ASCII
 * is lowercased. Existing Punycode A-labels pass through as ASCII but are
 * NOT decoded or IDNA-validated. Raw non-ASCII/UTF-8 names fail closed.
 * Unicode domain conversion belongs to the caller's independently owned
 * IDNA validation layer. Supply only the resulting ASCII to DNS/TLS; this
 * standalone Core implementation never links an IDNA provider.
 * No partial output on error. Buffer needs 256 bytes. Numeric addresses
 * remain unchanged; mapped IPv6 produces an IPv4 result. out_numeric and
 * out_address are optional; other output pointers are required. */
SALTS_CNET_EXPORT
int cnet_name_lookup_normalize(cnet_name_lookup *lookup, const char *name, size_t size,
                              char *ascii, size_t capacity, size_t *out_size,
                              bool *out_numeric, cnet_ip_address *out_address);
/** Copies input before admission. Numeric queries become ready immediately;
 * DNS uses the existing c-ares owner. ENOBUFS consumes no query. */
SALTS_CNET_EXPORT
int cnet_name_lookup_submit(cnet_name_lookup *lookup, const char *name, size_t size, cnet_name_query *out);
/** Nonblocking c-ares progress and timeout/cancellation retirement. */
SALTS_CNET_EXPORT
int cnet_name_lookup_advance(cnet_name_lookup *lookup);
SALTS_CNET_EXPORT
int cnet_name_lookup_next_timeout(cnet_name_lookup *lookup, uint32_t max_wait_ms, uint32_t *out);
SALTS_CNET_EXPORT
int cnet_name_lookup_ready(cnet_name_lookup *lookup, cnet_name_query query, bool *out);
/** Ordered unique unmapped IPv4/IPv6 results. ETIMEDOUT means pending; EOF means
 * exhausted. EAI_AGAIN is a query deadline; other EAI errors preserve DNS cause.
 * Overflow returns ENOBUFS and never delivers a truncated success list. */
SALTS_CNET_EXPORT
int cnet_name_lookup_next(cnet_name_lookup *lookup, cnet_name_query query, cnet_ip_address *out);
/** Ready results win cancellation (EALREADY). Logical cancellation does not
 * recycle callback storage; a dropped active query retires only after c-ares'
 * actual terminal. Queries are scoped to their owner and never wrap generation. */
SALTS_CNET_EXPORT
int cnet_name_lookup_cancel(cnet_name_lookup *lookup, cnet_name_query query);
SALTS_CNET_EXPORT
int cnet_name_lookup_query_drop(cnet_name_lookup *lookup, cnet_name_query *query);
/** Stops admission and cancels the c-ares channel with real callback terminals.
 * Drop every owned query, then destroy. Destroy while queries live returns EBUSY. */
SALTS_CNET_EXPORT
int cnet_name_lookup_close(cnet_name_lookup *lookup);
SALTS_CNET_EXPORT
int cnet_name_lookup_destroy(cnet_name_lookup *lookup);
#ifdef __cplusplus
}
#endif
#endif
