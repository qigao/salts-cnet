package shangmiinterop

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

func (p *recordPeer) peerUpdateLimit(nativeServer bool, scenario string, waitSent func() error) error {
	failure := strings.Contains(scenario, "fail")
	for round := 0; round < 2; round++ {
		if !nativeServer {
			if round == 1 && !failure {
				if err := p.receiveKeyUpdate(); err != nil {
					return err
				}
			}
			if err := p.expect(23, []byte{'F'}); err != nil {
				return err
			}
		}
		updates := 2
		if scenario == "limit-off" || failure {
			updates = 3
		}
		if failure && round == 0 {
			updates = 0
		}
		for i := 0; i < updates; i++ {
			request := byte(1)
			if !nativeServer && round == 1 {
				request = 0
			}
			if failure {
				request = byte(i % 2)
			}
			if err := p.sendKeyUpdate(request); err != nil {
				return err
			}
			if scenario == "limit-empty-fail" && i == 1 {
				if err := p.send(23, nil); err != nil {
					return err
				}
			}
		}
		if failure && round == 1 {
			kind, _, err := p.record()
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				return err
			}
			if err == nil && kind != 21 {
				return errors.New("update limit delivered data instead of failing")
			}
			return nil // The native peer separately requires FAILED/EPROTO/read.
		}
		if nativeServer {
			if err := p.send(23, []byte{'F'}); err != nil {
				return err
			}
			if updates != 0 {
				if err := p.receiveKeyUpdate(); err != nil {
					return err
				}
			}
			if err := p.expect(23, []byte{'G'}); err != nil {
				return err
			}
			if failure && round == 0 {
				if err := waitSent(); err != nil {
					return err
				}
			}
		} else if err := p.send(23, []byte("ok")); err != nil {
			return err
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
	for _, scenario := range []string{"limit", "limit-off", "limit-fail", "limit-empty-fail"} {
		t.Run("native_server_"+scenario, func(t *testing.T) { runNativeServer(t, f, scenario, scenario) })
		t.Run("native_client_"+scenario, func(t *testing.T) { runNativeClient(t, f, "localhost", true, scenario) })
		t.Run("native_mtls_server_"+scenario, func(t *testing.T) { runNativeServerWithClient(t, f, &client, scenario, scenario) })
	}
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
