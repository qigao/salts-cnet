package tickets

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	pioncurve "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/logging"
)

func TestDTLSNativeServer(t *testing.T) {
	for _, mode := range []string{"owned", "external"} {
		for _, variant := range []string{"server", "rsa", "mtls", "reject", "missing", "untrusted", "sni", "alpn", "ems", "data-reject", "abort-write", "abort-write-pending", "backpressure", "backpressure-empty", "deferred-reject"} {
			scenario := variant
			if scenario == "deferred-reject" {
				scenario = "data-reject"
			}
			t.Run(mode+"/"+variant, func(t *testing.T) {
				server := credentials(t, false, "")
				if scenario == "rsa" {
					server = dtlsRSA(t)
				}
				client := credentials(t, false, "")
				trust := client
				if scenario == "untrusted" {
					trust = credentials(t, false, "")
				}
				udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				n := startDTLS(t, udp.LocalAddr().(*net.UDPAddr).Port, mode, "server-"+variant, trust, &server)
				if st, _ := n.rpc('I', nil); st != 0 || n.state != 0 {
					t.Fatal("listener created stream before address proof")
				}
				if _, err := udp.WriteToUDP([]byte("bad"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(n.port)}); err != nil {
					t.Fatal(err)
				}
				if st, _ := n.rpc('P', nil); st != 0 || n.state != 0 || n.flags&3 != 0 {
					t.Fatal("malformed datagram admitted server state")
				}
				if st, body := n.rpc('H', nil); st != 0 || len(body) != 4 || binary.BigEndian.Uint32(body) != 0 {
					t.Fatal("malformed datagram elicited cookie reply")
				}
				if mode == "external" {
					if st, _ := n.rpc('N', nil); st != 0 {
						t.Fatal(st)
					}
				}
				base := logging.NewDefaultLoggerFactory()
				base.DefaultLogLevel = logging.LogLevelDisabled
				base.Writer = io.Discard
				observed := &dtlsAlertFactory{base: base, wanted: "Alert Fatal: HandshakeFailure"}
				switch scenario {
				case "reject":
					observed.wanted = "Alert Fatal: AccessDenied"
				case "untrusted":
					observed.wanted = "Alert Fatal: CertificateUnknown"
				case "data-reject":
					observed.wanted = "Alert Fatal: InternalError"
				}
				suite := dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
				if scenario == "rsa" {
					suite = dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				}
				cfg := &dtls.Config{RootCAs: server.roots, ServerName: "localhost", CipherSuites: []dtls.CipherSuiteID{suite},
					SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PKCS1WithSHA256},
					EllipticCurves:   []pioncurve.Curve{pioncurve.P256}, ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
					SupportedProtocols: []string{"test"}, MTU: 512, FlightInterval: 150 * time.Millisecond, LoggerFactory: observed}
				if scenario == "mtls" || scenario == "reject" || scenario == "untrusted" {
					cfg.Certificates = []tls.Certificate{client.cert}
				}
				if scenario == "sni" {
					cfg.ServerName = "other.local"
				}
				if scenario == "alpn" {
					cfg.SupportedProtocols = []string{"other"}
				}
				if scenario == "ems" {
					cfg.ExtendedMasterSecret = dtls.DisableExtendedMasterSecret
				}
				connection, err := dtls.Client(udp, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(n.port)}, cfg)
				if err != nil {
					t.Fatal(err)
				}
				finished := make(chan error, 1)
				exported := make(chan []byte, 1)
				done := make(chan struct{})
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				t.Cleanup(func() {
					cancel()
					_ = connection.Close()
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("client did not drain")
					}
				})
				failure := scenario == "reject" || scenario == "missing" || scenario == "untrusted" || scenario == "sni" || scenario == "alpn" || scenario == "ems" || scenario == "data-reject"
				go func() {
					defer close(done)
					e := connection.HandshakeContext(ctx)
					if failure && scenario != "data-reject" {
						if e == nil || !observed.seen.Load() {
							finished <- fmt.Errorf("missing independently decoded handshake fatal: %v", e)
						} else {
							finished <- nil
						}
						return
					}
					if e != nil {
						finished <- e
						return
					}
					if strings.HasPrefix(scenario, "abort-write") {
						if scenario == "abort-write-pending" {
							buffer := make([]byte, 1500)
							size, e := connection.Read(buffer)
							if e != nil || size != 1163 {
								finished <- fmt.Errorf("actual aborted native send: %d %v", size, e)
								return
							}
						}
						finished <- nil
						return
					}
					state, ok := connection.ConnectionState()
					if !ok {
						finished <- fmt.Errorf("no verified connection state")
						return
					}
					material, e := state.ExportKeyingMaterial("EXPERIMENTAL-cnet", nil, 65)
					if e != nil {
						finished <- e
						return
					}
					exported <- material
					if e = connection.SetDeadline(time.Now().Add(7 * time.Second)); e != nil {
						finished <- e
						return
					}
					buffer := make([]byte, 1500)
					size, e := connection.Read(buffer)
					if e != nil || size != 1163 || !bytes.Equal(buffer[:size], bytes.Repeat([]byte{'x'}, 1163)) {
						finished <- fmt.Errorf("native maximum message: %d %v", size, e)
						return
					}
					if _, e = connection.Write(buffer[:size]); e != nil {
						finished <- e
						return
					}
					size, e = connection.Read(buffer)
					if scenario == "data-reject" {
						if e != io.EOF || !observed.seen.Load() {
							finished <- fmt.Errorf("missing decoded encrypted fatal: %v", e)
						} else {
							finished <- nil
						}
						return
					}
					if e != nil || size != 0 {
						finished <- fmt.Errorf("empty native datagram: %d %v", size, e)
						return
					}
					if _, e = connection.Write(nil); e != nil {
						finished <- e
						return
					}
					size, e = connection.Read(buffer)
					if e != io.EOF || size != 0 {
						finished <- fmt.Errorf("native close_notify: %d %v", size, e)
						return
					}
					finished <- nil
				}()
				wrote, empty, closed, leaseChecked, neighborFailed := false, false, false, false, false
				aborted := false
				deadline := time.Now().Add(9 * time.Second)
				for time.Now().Before(deadline) {
					st, payload := n.rpc('P', nil)
					if st < 0 && !failure {
						t.Fatalf("server progress %d state=%d alert=%d wire=%d", st, n.state, n.localAlert, n.wire)
					}
					if n.state != 0 && !leaseChecked {
						if k, _ := n.rpc('K', nil); k != dtlsBusy {
							t.Fatalf("listener reclaimed with stream lease: %d", k)
						}
						leaseChecked = true
					}
					if n.state == 5 {
						// A post-cookie reject may be admitted during this observe.
						// Its first bridge error/fatal is consumed by the next advance.
						if st == 0 {
							continue
						}
						expected := int32(-4042)
						if scenario == "data-reject" {
							expected = -4006
						}
						if st != expected {
							t.Fatalf("first server error lost: %d want %d", st, expected)
						}
						if refused, _ := n.rpc('W', []byte("no retry")); refused != expected {
							t.Fatal("terminal admission returned retryable error")
						}
						if mode == "external" && !neighborFailed {
							if k, _ := n.rpc('N', nil); k != 0 {
								t.Fatal(k)
							}
							neighborFailed = true
						}
						if n.flags&3 == 0 {
							break
						}
						continue
					}
					if n.state == 2 && !wrote {
						if st, _ := n.rpc('W', make([]byte, 1164)); st != -4016 {
							t.Fatalf("oversize %d", st)
						}
						if st, _ := n.rpc('W', bytes.Repeat([]byte{'x'}, 1163)); st != 0 || n.flags&3 != 2 || n.sent != 0 {
							t.Fatal("server admission/completion mismatch")
						}
						if st, _ := n.rpc('W', []byte("second")); st != dtlsBusy {
							t.Fatal("second application admitted")
						}
						wrote = true
						if strings.HasPrefix(scenario, "abort-write") {
							submitted := scenario == "abort-write-pending"
							before := n.wire
							if submitted {
								if st, _ := n.rpc('T', nil); st != 0 || n.flags&3 != 3 {
									t.Fatal("no native pending server send")
								}
							}
							if st, _ := n.rpc('C', nil); st != dtlsBusy {
								t.Fatal("admitted server tag reclaimed")
							}
							want := int32(0)
							if submitted {
								want = dtlsBusy
							}
							if st, _ := n.rpc('A', nil); st != want {
								t.Fatalf("abort %d want %d", st, want)
							}
							for i := 0; i < 20 && n.flags&2 != 0; i++ {
								if st, _ := n.rpc('P', nil); st < 0 {
									t.Fatal(st)
								}
							}
							if n.flags&3 != 0 || n.sent != 1 {
								t.Fatal("server output/tag did not settle")
							}
							st, last := n.rpc('L', nil)
							want = -4006
							delta := uint32(0)
							if submitted {
								want = 0
								delta = 1
							}
							if st != 0 || len(last) != 4 || int32(binary.BigEndian.Uint32(last)) != want || n.wire != before+delta {
								t.Fatal("server abort lost actual terminal or resubmitted")
							}
							aborted = true
							break
						}
					}
					for len(payload) != 0 {
						if len(payload) < 2 {
							t.Fatal("truncated message header")
						}
						size := int(binary.BigEndian.Uint16(payload))
						payload = payload[2:]
						if size > len(payload) {
							t.Fatal("truncated message")
						}
						value := payload[:size]
						payload = payload[size:]
						if !empty {
							if len(value) != 1163 || !bytes.Equal(value, bytes.Repeat([]byte{'x'}, 1163)) {
								t.Fatal("server application boundary")
							}
							st, material := n.rpc('E', nil)
							if st != 0 {
								t.Fatal(st)
							}
							select {
							case other := <-exported:
								equal := bytes.Equal(material, other)
								clear(other)
								if !equal {
									t.Fatal("server exporter mismatch")
								}
							case <-time.After(time.Second):
								t.Fatal("client exporter missing")
							}
							clear(material)
							if st, _ := n.rpc('W', nil); st != 0 {
								t.Fatal(st)
							}
							empty = true
						} else {
							if len(value) != 0 || n.sent != 2 {
								t.Fatal("empty message/send terminal")
							}
							if st, _ := n.rpc('O', nil); st != 0 {
								t.Fatal(st)
							}
							closed = true
						}
					}
					if n.state == 4 {
						break
					}
				}
				if failure {
					if n.state != 5 || n.flags&3 != 0 || !leaseChecked {
						t.Fatal("server rejection did not drain")
					}
				} else if !aborted && (n.state != 4 || !wrote || !empty || !closed || n.received != 2 || n.sent != 2) {
					t.Fatalf("server incomplete state=%d rx=%d tx=%d wire=%d flags=%x checks=%d", n.state, n.received, n.sent, n.wire, n.flags, n.checks)
				}
				select {
				case err = <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("independent client did not finish")
				}
				if st, body := n.rpc('H', nil); st != 0 || len(body) != 4 || binary.BigEndian.Uint32(body) == 0 {
					t.Fatal("no actual cookie send terminal")
				}
				if st, _ := n.rpc('C', nil); st != 0 {
					t.Fatal("bridge destroy", st)
				}
				if st, _ := n.rpc('K', nil); st != 0 || n.refs != 0 {
					t.Fatal("listener destroy", st, n.refs)
				}
				if mode == "external" {
					// Count admitted probes: a preceding failure probe may still
					// have its independent send/receive completions in flight.
					before := uint32(1) // The initial external-backend probe.
					if neighborFailed {
						before++
					}
					if st, _ := n.rpc('N', nil); st != 0 {
						t.Fatal(st)
					}
					// Send and loopback receive are independent native terminals.
					// A send completion alone does not establish receive progress.
					for i := 0; i < 20 && (n.neighborSent <= before || n.neighborReceived <= before); i++ {
						if st, _ := n.rpc('P', nil); st < 0 {
							t.Fatal(st)
						}
					}
					if n.neighborSent != before+1 || n.neighborReceived != before+1 {
						t.Fatalf("listener teardown neighbor incomplete: before=%d sent=%d received=%d", before, n.neighborSent, n.neighborReceived)
					}
				}
			})
		}
	}
}
