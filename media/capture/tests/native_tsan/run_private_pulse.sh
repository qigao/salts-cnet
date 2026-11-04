#!/usr/bin/env bash
set -euo pipefail
umask 077

# CTest supplies the root-graph executable and Python interpreter.
if [[ "$#" != 2 ]]; then
  echo 'expected Capture test executable and Python interpreter' >&2
  exit 2
fi
exe="$1"
python="$2"
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
private="$(mktemp -d "${RUNNER_TEMP:-/tmp}/salts-capture-tsan.XXXXXX")"
export XDG_RUNTIME_DIR="$private/xdg"
export PULSE_RUNTIME_PATH="$private/pulse"
export PULSE_SERVER="unix:$private/only-null-monitor.sock"
export SALTS_CAPTURE_TSAN_VIRTUAL_ONLY=1
export TSAN_OPTIONS="halt_on_error=1:exitcode=66:history_size=7"
mkdir -p "$XDG_RUNTIME_DIR" "$PULSE_RUNTIME_PATH"
chmod 700 "$XDG_RUNTIME_DIR" "$PULSE_RUNTIME_PATH"

server_pid=""
feed_pid=""
cleanup() {
  if [[ -n "$feed_pid" ]]; then
    pkill -P "$feed_pid" 2>/dev/null || true
    kill "$feed_pid" 2>/dev/null || true
    wait "$feed_pid" 2>/dev/null || true
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$private"
}
trap cleanup EXIT

# A private -n PulseAudio server never reads a host default.pa module, ALSA,
# udev, TCP/network endpoint or physical audio device. It has ONE software
# null sink, and its monitor is the only input.
pulseaudio --daemonize=no --exit-idle-time=-1 --disallow-exit \
  --log-target=stderr --log-level=error -n \
  -L "module-native-protocol-unix socket=$private/only-null-monitor.sock auth-anonymous=1" \
  -L "module-null-sink sink_name=capture_tsan_sink sink_properties=device.description=CaptureTsanVirtualAudioSink" \
  >"$private/pulse.log" 2>&1 &
server_pid="$!"
for _ in $(seq 1 60); do
  if pactl info >"$private/server-info.txt" 2>&1; then break; fi
  kill -0 "$server_pid" || { cat "$private/pulse.log" >&2; exit 1; }
  sleep 0.1
done
pactl info
sources="$(pactl list short sources | awk '{print $2}')"
sinks="$(pactl list short sinks | awk '{print $2}')"
if [[ "$sources" != "capture_tsan_sink.monitor" ||
      "$sinks" != "capture_tsan_sink" ||
      -n "$(pactl list short cards)" ]]; then
  echo 'refusing non-virtual/extra audio devices in native Capture TSan' >&2
  pactl list short sources >&2
  pactl list short sinks >&2
  pactl list short cards >&2
  exit 1
fi
pactl set-default-sink capture_tsan_sink
pactl set-default-source capture_tsan_sink.monitor
pactl list sources | grep -F 'CaptureTsanVirtualAudioSink'
echo 'PASS CI-owned software null monitor only, no physical audio cards'

(
  "$python" -u "$root/media/capture/tests/native_tsan/feed_private_null.py" |
    pacat --playback --device=capture_tsan_sink \
      --format=s16le --rate=16000 --channels=1 > /dev/null 2>&1
) &
feed_pid="$!"
sleep 1
streams="$(pactl list short sink-inputs | awk 'NF {n++} END {print n+0}')"
test "$streams" = 1 || {
  echo "refusing missing or extra synthetic PCM stream: $streams" >&2
  exit 1
}

# One invocation of the formal TinyTest suite. CTest owns status and timeout;
# this fixture only owns the private virtual device and synthetic PCM feeder.
"$exe"
