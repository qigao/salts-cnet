#ifndef CNET_URI_H
#define CNET_URI_H

#include <salts/error_codes.h>

#include <stdint.h>

enum { CNET_URI_MAX_BYTES = 1280, CNET_URI_HOST_CAPACITY = 254, CNET_URI_PATH_CAPACITY = 1025 };

typedef enum cnet_uri_scheme {
  CNET_URI_NONE = 0,
  CNET_URI_TCP,
  CNET_URI_TLS,
  CNET_URI_UDP,
  CNET_URI_PIPE,
  CNET_URI_VSOCK,
  CNET_URI_IPC
} cnet_uri_scheme;

typedef struct cnet_uri {
  cnet_uri_scheme scheme;
  char host[CNET_URI_HOST_CAPACITY];
  char path[CNET_URI_PATH_CAPACITY];
  uint16_t port;
  uint32_t vsock_cid;
  uint32_t vsock_port;
} cnet_uri;

int cnet_uri_parse(const char *text, cnet_uri *out_uri);

#endif /* CNET_URI_H */
