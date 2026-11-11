#ifndef CNET_IPC_INTERNAL_H
#define CNET_IPC_INTERNAL_H

#include <cnet/ipc.h>

typedef struct cnet_ipc_child {
  cnet_ipc_accepted descriptor;
  native_io_endpoint attached_pipe;
} cnet_ipc_child;

int cnet_ipc_listener_take_external(cnet_ipc_listener *listener, native_io_backend *backend,
                                     cnet_ipc_child *out_child);
int cnet_ipc_child_close(cnet_ipc_child *child, native_io_backend *backend);

#endif
