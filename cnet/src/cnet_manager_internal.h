#ifndef CNET_MANAGER_INTERNAL_H
#define CNET_MANAGER_INTERNAL_H

#include <cnet/manager.h>

/* Check the initializing Owner and exact borrowed client wrapper. */
int cnet_manager_validate_client(cnet_manager *manager, cnet_client *client);

#endif
