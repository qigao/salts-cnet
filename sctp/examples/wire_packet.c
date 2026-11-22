#include <sctp_wire.h>

#include <stdio.h>
#include <stdlib.h>

int main(void) {
  enum { SHUTDOWN_ACK = 8 };
  const cnet_sctp_wire_chunk outgoing = { .type = SHUTDOWN_ACK };
  uint8_t packet[64];
  size_t packet_size;
  cnet_sctp_wire_header header;
  cnet_sctp_wire_decoder decoder;
  cnet_sctp_wire_chunk incoming;

  if (cnet_sctp_wire_encode(5000, 5001, 42, &outgoing, 1, packet,
                           sizeof(packet), &packet_size) != CNET_SCTP_WIRE_OK) {
    fputs("Could not encode the SCTP packet.\n", stderr);
    return EXIT_FAILURE;
  }

  if (cnet_sctp_wire_decode(packet, packet_size, &header, &decoder) !=
      CNET_SCTP_WIRE_OK) {
    fputs("Could not decode the SCTP packet.\n", stderr);
    return EXIT_FAILURE;
  }

  printf("SCTP %u -> %u: %zu bytes, %zu chunks\n",
         (unsigned)header.source_port, (unsigned)header.destination_port,
         packet_size, header.chunk_count);

  cnet_sctp_wire_status status;
  while ((status = cnet_sctp_wire_next_chunk(&decoder, &incoming)) ==
         CNET_SCTP_WIRE_OK) {
    printf("Chunk %u: %zu payload bytes\n", (unsigned)incoming.type,
           incoming.value_size);
  }
  if (status != CNET_SCTP_WIRE_END) {
    fputs("Could not read the SCTP chunks.\n", stderr);
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
