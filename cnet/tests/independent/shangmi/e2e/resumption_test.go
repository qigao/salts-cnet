package shangmiinterop

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	peerx509 "github.com/iuboy/pollux-go/smx509"
	"github.com/iuboy/pollux-go/tls13gm"
)

func TestShangMiSessionResumption(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	f := credentials(t, nil)
	for _, mode := range []string{"enabled", "disabled", "server-refuses"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := listener.SetDeadline(time.Now().Add(35 * time.Second)); err != nil {
				t.Fatal(err)
			}
			key := make([]byte, 16)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			finished := make(chan error, 1)
			go func() {
				for i := 0; i < 3; i++ {
					raw, err := listener.Accept()
					if err != nil {
						finished <- err
						return
					}
					err = func() error {
						defer raw.Close()
						if err := raw.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
							return err
						}
						if mode == "server-refuses" && i != 0 {
							if _, err := rand.Read(key); err != nil {
								return err
							}
						}
						p := &recordPeer{Conn: raw}
						defer p.clearSecrets()
						config := tls13gm.ServerConfig{DCID: []byte("formal TCP session peer"), Certificate: f.leaf, PrivateKey: f.key, SessionTicketKeys: func() [][]byte { return [][]byte{key} }}
						if err := p.serverWithSession(config, "", func(h *tls13gm.ServerHandshaker, reused bool) error {
							want := i != 0 && mode == "enabled"
							if reused != want {
								return fmt.Errorf("connection %d reused=%v want=%v", i, reused, want)
							}
							if mode == "disabled" {
								return nil
							}
							ticket, err := h.NewSessionTicket(60, 0xfffffff0)
							if err != nil {
								return err
							}
							return p.send(22, ticket)
						}); err != nil {
							return fmt.Errorf("connection %d handshake: %w", i, err)
						}
						if err := p.expect(23, []byte{'F'}); err != nil {
							return err
						}
						if err := p.send(23, []byte("ok")); err != nil {
							return err
						}
						if err := p.expect(21, []byte{1, 0}); err != nil {
							return err
						}
						return p.send(21, []byte{1, 0})
					}()
					if err != nil {
						finished <- err
						return
					}
				}
				finished <- nil
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
			output, runErr := exec.CommandContext(ctx, *native, "--tls-resumption", port, "shangmi13", "localhost", f.caPath, mode).CombinedOutput()
			listener.Close()
			peerErr := <-finished
			if runErr != nil || peerErr != nil {
				t.Fatalf("native=%v peer=%v\n%s", runErr, peerErr, output)
			}
		})
	}
}

func TestShangMiServerTickets(t *testing.T) {
	if *native == "" {
		t.Fatal("-native is required")
	}
	f := credentials(t, nil)
	roots := peerx509.NewCertPool()
	roots.AddCert(f.root)
	for _, mode := range []string{"enabled", "disabled", "binder", "unknown", "age", "ticket-expired"} {
		t.Run(mode, func(t *testing.T) {
			expected := "011"
			if mode == "disabled" || mode == "ticket-expired" {
				expected = "000"
			}
			if mode == "binder" || mode == "unknown" || mode == "age" {
				expected = "001"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			ready := filepath.Join(t.TempDir(), "ready")
			cmd := exec.CommandContext(ctx, *native)
			cmd.Env = append(os.Environ(), "SALTS_TICKET_READY="+ready, "SALTS_TICKET_CERT="+f.certPath, "SALTS_TICKET_KEY="+f.keyPath, "SALTS_TICKET_MODE="+mode, "SALTS_TICKET_EXPECTED="+expected, "SALTS_TICKET_PROFILE=shangmi13")
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			complete := false
			defer func() {
				if !complete {
					cancel()
				}
				if err := cmd.Wait(); err != nil {
					t.Errorf("native=%v\n%s", err, output.String())
				}
				cancel()
			}()
			var address string
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
				b, err := os.ReadFile(ready)
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				if strings.HasSuffix(string(b), "\n") {
					port, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 16)
					if err != nil || port == 0 {
						t.Fatalf("invalid ready port: %v", err)
					}
					address = net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10))
					break
				}
				time.Sleep(time.Millisecond)
			}
			if address == "" {
				t.Fatal("server did not publish port")
			}
			var ticket, psk []byte
			var ageAdd uint32
			var received time.Time
			defer func() { clear(psk) }()
			for round := range 3 {
				if mode == "ticket-expired" && round != 0 {
					time.Sleep(1100 * time.Millisecond)
				}
				raw, err := net.DialTimeout("tcp", address, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				err = func() error {
					defer raw.Close()
					if err := raw.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
						return err
					}
					p := &recordPeer{Conn: raw}
					defer p.clearSecrets()
					cfg := tls13gm.ClientConfig{DCID: []byte("formal TCP ticket client"), Roots: roots, ServerName: "localhost", ResumptionIdentity: bytes.Clone(ticket), ResumptionPSK: bytes.Clone(psk)}
					if len(ticket) != 0 {
						cfg.ResumptionObfuscatedTicketAge = ageAdd + uint32(time.Since(received).Milliseconds())
					}
					if mode == "unknown" && round == 1 {
						cfg.ResumptionIdentity[0] ^= 1
					}
					if mode == "age" && round == 1 {
						cfg.ResumptionObfuscatedTicketAge = ageAdd + 60000
					}
					corrupt := ""
					if mode == "binder" && round == 1 {
						corrupt = "psk_binder"
					}
					err := p.clientWithSession(cfg, corrupt, func(h *tls13gm.ClientHandshaker, reused bool) error {
						if reused != (expected[round] == '1') {
							return fmt.Errorf("round %d reused=%v want=%c", round, reused, expected[round])
						}
						if mode == "disabled" {
							return nil
						}
						msg, err := p.handshake()
						if err != nil {
							return err
						}
						if msg[0] != 4 {
							return errors.New("missing NST")
						}
						identity, secret, age, err := h.HandleNewSessionTicket(msg[4:])
						if err != nil {
							return err
						}
						clear(psk)
						ticket, psk, ageAdd, received = bytes.Clone(identity), bytes.Clone(secret), age, time.Now()
						clear(secret)
						if len(ticket) != 32 || len(psk) != 32 {
							return errors.New("invalid owned ticket size")
						}
						return nil
					})
					if corrupt != "" {
						var timeout net.Error
						if !p.altered || err == nil || errors.As(err, &timeout) && timeout.Timeout() {
							return fmt.Errorf("missing prompt binder rejection: %v", err)
						}
						return nil
					}
					if err != nil {
						return err
					}
					if err := p.send(23, []byte{'F'}); err != nil {
						return err
					}
					if err := p.expect(23, []byte{'G'}); err != nil {
						return err
					}
					if err := p.send(21, []byte{1, 0}); err != nil {
						return err
					}
					return p.expect(21, []byte{1, 0})
				}()
				if err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
			}
			complete = true
		})
	}
}
