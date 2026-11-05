package shangmiinterop

import (
	"fmt"
	"testing"
)

// Assert exact record order at and across repeated local thresholds. The
// independent peer never initiates rotation, only answers native requests.
func (p *recordPeer) localRotation(nativeServer bool, limit uint64) error {
	for round := uint64(0); round < 5; round++ {
		if nativeServer {
			if err := p.send(23, []byte{'F'}); err != nil {
				return err
			}
		}
		if limit != 0 && round != 0 && round%limit == 0 {
			if err := p.receiveKeyUpdateRequest(1); err != nil {
				return fmt.Errorf("rotation before record %d: %w", round+1, err)
			}
			if err := p.sendKeyUpdate(0); err != nil {
				return err
			}
		}
		data := byte('F')
		if nativeServer {
			data = 'G'
		}
		if err := p.expect(23, []byte{data}); err != nil {
			return err
		}
		if !nativeServer {
			if err := p.send(23, []byte("ok")); err != nil {
				return err
			}
		}
	}
	if nativeServer {
		if err := p.send(21, []byte{1, 0}); err != nil {
			return err
		}
	}
	if err := p.expect(21, []byte{1, 0}); err != nil {
		return err
	}
	if !nativeServer {
		return p.send(21, []byte{1, 0})
	}
	return nil
}

func localRotationLimit(scenario string) uint64 {
	switch scenario {
	case "rotate1":
		return 1
	case "rotate2":
		return 2
	case "rotatemax":
		return 1 << 20
	default:
		return 0
	}
}

func TestShangMiKeyUpdate(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	f := credentials(t, nil)
	client := clientCredentials(t, nil)
	for _, scenario := range []string{"rotateoff", "rotate1", "rotate2", "rotatemax"} {
		t.Run("native_server_"+scenario, func(t *testing.T) { runNativeServer(t, f, scenario, scenario) })
		t.Run("native_client_"+scenario, func(t *testing.T) { runNativeClient(t, f, "localhost", true, scenario) })
		t.Run("native_mtls_server_"+scenario, func(t *testing.T) { runNativeServerWithClient(t, f, &client, scenario, scenario) })
	}
	for _, scenario := range []string{"key_update_one_way", "key_update_requested", "key_update_coalesced"} {
		t.Run("native_server_"+scenario, func(t *testing.T) { runNativeServer(t, f, "close", scenario) })
		t.Run("native_client_"+scenario, func(t *testing.T) { runNativeClient(t, f, "localhost", true, scenario) })
		t.Run("native_mtls_server_"+scenario, func(t *testing.T) { runNativeServerWithClient(t, f, &client, "close", scenario) })
	}
	for _, scenario := range []string{"key_update_bad_value", "key_update_bad_length", "key_update_bad_stale_key"} {
		t.Run(scenario, func(t *testing.T) { runNativeServer(t, f, "keyupdate-fail", scenario) })
		t.Run("mtls_"+scenario, func(t *testing.T) { runNativeServerWithClient(t, f, &client, "keyupdate-fail", scenario) })
	}
}
