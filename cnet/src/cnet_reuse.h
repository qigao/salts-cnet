#ifndef CNET_REUSE_INTERNAL_H
#define CNET_REUSE_INTERNAL_H

#include <cnet/manager.h>

/* Owner-local admission snapshot, not a reservation or application READY.
 * OK: live OPEN transport; EBUSY: opening/handshaking; ESHUTDOWN: closing,
 * final send, directional shutdown or stopped owner; ENOENT: stale identity.
 * No progress, callbacks or allocation. Existing leases are unaffected. */
int cnet_client_reuse_status(cnet_client *client, cnet_connection connection);
int cnet_manager_reuse_status(cnet_manager *manager, cnet_managed_connection managed);

#endif
