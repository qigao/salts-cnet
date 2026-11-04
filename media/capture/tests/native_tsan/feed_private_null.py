#!/usr/bin/env python3
"""Generate bounded digital-zero PCM for one software PulseAudio null sink.

No model data, recording, file output, physical microphone or speaker.
A deterministic null sink monitor is the only native Capture device.
"""
import sys
import time

FRAME = bytes(640)  # exact 16 kHz, mono S16LE, 20ms
def main() -> int:
    try:
        for _ in range(12000):
            sys.stdout.buffer.write(FRAME)
            sys.stdout.buffer.flush()
            time.sleep(0.01)
    except BrokenPipeError:
        return 0
    return 0

if __name__ == "__main__":
    sys.exit(main())
