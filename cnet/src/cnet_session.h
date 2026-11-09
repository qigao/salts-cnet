#ifndef CNET_SESSION_H
#define CNET_SESSION_H
#include <cnet/resources.h>

#include <core/error_codes.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct cnet_session_table {
  void *impl;
} cnet_session_table;

typedef struct cnet_session_handle {
  uint32_t slot;
  uint32_t generation;
} cnet_session_handle;

typedef enum cnet_session_state {
  CNET_SESSION_FREE = 0,
  CNET_SESSION_RESERVED,
  CNET_SESSION_RESOLVING,
  CNET_SESSION_TRANSPORT_CONNECTING,
  CNET_SESSION_PROTOCOL_HANDSHAKING,
  CNET_SESSION_OPEN,
  CNET_SESSION_DRAINING,
  CNET_SESSION_TERMINAL,
  CNET_SESSION_RETIRED
} cnet_session_state;

typedef enum cnet_session_stage {
  CNET_SESSION_STAGE_NONE = 0,
  CNET_SESSION_STAGE_RESOLVE,
  CNET_SESSION_STAGE_CONNECT,
  CNET_SESSION_STAGE_HANDSHAKE,
  CNET_SESSION_STAGE_READ,
  CNET_SESSION_STAGE_WRITE,
  CNET_SESSION_STAGE_SHUTDOWN,
  CNET_SESSION_STAGE_CALLBACK
} cnet_session_stage;

typedef enum cnet_session_terminal_kind {
  CNET_SESSION_TERMINAL_NONE = 0,
  CNET_SESSION_TERMINAL_CLOSED,
  CNET_SESSION_TERMINAL_FAILED
} cnet_session_terminal_kind;

typedef struct cnet_session_terminal {
  cnet_session_terminal_kind kind;
  int status;
  cnet_session_stage stage;
} cnet_session_terminal;

bool cnet_session_handle_valid(cnet_session_handle handle);

int cnet_session_table_init(cnet_session_table *table, size_t capacity);
int cnet_session_table_init_with_storage(cnet_session_table *table, size_t capacity, const cnet_allocator *storage);
int cnet_session_table_destroy(cnet_session_table *table);

/**
 * Thread-safe admission reservation. Post-reservation lifecycle transitions
 * remain owned by exactly one CNet shard; state queries are thread-safe.
 */
int cnet_session_table_reserve(cnet_session_table *table, cnet_session_handle *out_handle);
/** Rolls back RESERVED admission without emitting a terminal notification. */
int cnet_session_table_release_reservation(cnet_session_table *table, cnet_session_handle handle);
int cnet_session_table_state(const cnet_session_table *table, cnet_session_handle handle,
                             cnet_session_state *out_state);
int cnet_session_table_transition(cnet_session_table *table, cnet_session_handle handle,
                                  cnet_session_state next);
int cnet_session_table_begin_close(cnet_session_table *table, cnet_session_handle handle);
int cnet_session_table_finish_close(cnet_session_table *table, cnet_session_handle handle);
int cnet_session_table_fail(cnet_session_table *table, cnet_session_handle handle, int status,
                            cnet_session_stage stage);
int cnet_session_table_take_terminal(cnet_session_table *table, cnet_session_handle handle,
                                     cnet_session_terminal *out_terminal);
int cnet_session_table_recycle(cnet_session_table *table, cnet_session_handle handle);

#endif /* CNET_SESSION_H */
