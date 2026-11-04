#define MINIAUDIO_IMPLEMENTATION
#include "miniaudio.h"
#include <stdio.h>

int main(void) {
  ma_context context;
  ma_context_config config = ma_context_config_init();
  ma_backend backend = ma_backend_pulseaudio;
  config.pulse.pServerName = "unix:/tmp/saltscore-capture-pulse-leak/absent-pulse-server.sock";
  config.pulse.tryAutoSpawn = MA_FALSE;
  ma_result result = ma_context_init(&backend, 1, &config, &context);
  fprintf(stderr, "Exact miniaudio 0.11.22 isolated Pulse init returned %d\n", (int)result);
  if (result == MA_SUCCESS) {
    ma_context_uninit(&context);
    return 2;
  }
  return 0;
}
