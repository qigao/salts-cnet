package tickets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	pioncurve "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/logging"
)

var dtlsNative = flag.String("dtls-native", "", "production CNet DTLS client peer")

const dtlsBusy int32 = -4005

type dtlsProcess struct {
	t                                                    *testing.T
	cmd                                                  *exec.Cmd
	in                                                   io.WriteCloser
	out                                                  io.ReadCloser
	log                                                  string
	state, flags, localAlert, checks, refs               byte
	received, sent, wire, neighborReceived, neighborSent uint32
	port                                                 uint16
}

func startDTLS(t *testing.T, port int, mode, policy string, trust identity, client *identity) *dtlsProcess {
	t.Helper()
	if *dtlsNative == "" {
		t.Fatal("missing native DTLS peer")
	}
	args := []string{strconv.Itoa(port), mode, policy, trust.caFile}
	if client != nil {
		args = append(args, client.certFile, client.keyFile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, *dtlsNative, args...)
	logPath := filepath.Join(t.TempDir(), "native.log")
	file, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = file
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	n := &dtlsProcess{t: t, cmd: cmd, in: in, out: out, log: logPath}
	t.Cleanup(func() {
		_ = in.Close()
		err := cmd.Wait()
		cancel()
		_ = out.Close()
		_ = file.Close()
		if err != nil {
			data, _ := os.ReadFile(logPath)
			t.Errorf("native DTLS cleanup: %v\n%s", err, data)
		}
	})
	return n
}
func (n *dtlsProcess) rpc(op byte, data []byte) (int32, []byte) {
	n.t.Helper()
	header := make([]byte, 5)
	header[0] = op
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	if _, err := n.in.Write(append(header, data...)); err != nil {
		n.t.Fatal(err)
	}
	var response [36]byte
	if _, err := io.ReadFull(n.out, response[:]); err != nil {
		log, _ := os.ReadFile(n.log)
		n.t.Fatalf("native response: %v\n%s", err, log)
	}
	status := int32(binary.BigEndian.Uint32(response[:4]))
	n.state = response[4]
	n.localAlert = response[5]
	n.flags = response[7]
	n.received = binary.BigEndian.Uint32(response[8:12])
	n.sent = binary.BigEndian.Uint32(response[12:16])
	n.wire = binary.BigEndian.Uint32(response[16:20])
	n.neighborReceived = binary.BigEndian.Uint32(response[20:24])
	n.neighborSent = binary.BigEndian.Uint32(response[24:28])
	n.checks = response[30]
	n.refs = response[31]
	n.port = binary.BigEndian.Uint16(response[28:30])
	size := binary.BigEndian.Uint32(response[32:])
	if size > 32768 {
		n.t.Fatal("invalid native response size")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(n.out, body); err != nil {
		n.t.Fatal(err)
	}
	if n.flags&8 == 0 {
		n.t.Fatal("callback reentry contract failed")
	}
	return status, body
}

// Reuse the existing CNet credential fixture except for the RSA server variant.
func dtlsRSA(t *testing.T) identity {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DTLS RSA root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := identity{caFile: filepath.Join(dir, "ca.pem"), certFile: filepath.Join(dir, "cert.pem"), keyFile: filepath.Join(dir, "key.pem"), cert: tls.Certificate{Certificate: [][]byte{cert}, PrivateKey: key}}
	parsedRoot, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	f.roots = x509.NewCertPool()
	f.roots.AddCert(parsedRoot)
	for path, block := range map[string]*pem.Block{f.caFile: {Type: "CERTIFICATE", Bytes: rootDER}, f.certFile: {Type: "CERTIFICATE", Bytes: cert}, f.keyFile: {Type: "PRIVATE KEY", Bytes: private}} {
		if err = os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

type dtlsAlertLog struct {
	logging.LeveledLogger
	seen   *atomic.Bool
	wanted string
}

func (l *dtlsAlertLog) Tracef(format string, args ...interface{}) {
	if format == "%s: <- %s" && len(args) == 2 {
		if text, ok := args[1].(string); ok && text == l.wanted {
			l.seen.Store(true)
		}
	}
}

type dtlsAlertFactory struct {
	base   logging.LoggerFactory
	seen   atomic.Bool
	wanted string
}

func (f *dtlsAlertFactory) NewLogger(scope string) logging.LeveledLogger {
	return &dtlsAlertLog{f.base.NewLogger(scope), &f.seen, f.wanted}
}
func TestDTLSNativeInterop(t *testing.T) {
	for _, mode := range []string{"owned", "external"} {
		for _, variant := range []string{"server", "mtls", "rsa", "reject", "data-reject", "abort-write", "abort-write-pending", "backpressure", "backpressure-empty", "deferred-reject"} {
			scenario := variant
			if scenario == "deferred-reject" {
				scenario = "data-reject"
			}
			t.Run(mode+"/"+variant, func(t *testing.T) {
				server := credentials(t, false, "")
				if scenario == "rsa" {
					server = dtlsRSA(t)
				}
				var client *identity
				pool := x509.NewCertPool()
				auth := dtls.NoClientCert
				if scenario == "mtls" {
					c := credentials(t, false, "")
					client = &c
					pool = c.roots
					auth = dtls.RequireAndVerifyClientCert
				}
				base := logging.NewDefaultLoggerFactory()
				base.DefaultLogLevel = logging.LogLevelDisabled
				base.Writer = io.Discard
				observed := &dtlsAlertFactory{base: base, wanted: "Alert Fatal: AccessDenied"}
				if scenario == "data-reject" {
					observed.wanted = "Alert Fatal: InternalError"
				}
				suite := dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
				if scenario == "rsa" {
					suite = dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				}
				listener, err := dtls.Listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &dtls.Config{Certificates: []tls.Certificate{server.cert}, ClientAuth: auth, ClientCAs: pool,
					CipherSuites: []dtls.CipherSuiteID{suite}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PKCS1WithSHA256},
					EllipticCurves: []pioncurve.Curve{pioncurve.P256}, ExtendedMasterSecret: dtls.RequireExtendedMasterSecret, SupportedProtocols: []string{"test"}, MTU: 512, FlightInterval: 150 * time.Millisecond, LoggerFactory: observed})
				if err != nil {
					t.Fatal(err)
				}
				finished := make(chan error, 1)
				exported := make(chan []byte, 1)
				done := make(chan struct{})
				var connectionOwner sync.Mutex
				var accepted net.Conn
				closing := false
				t.Cleanup(func() {
					connectionOwner.Lock()
					closing = true
					connection := accepted
					connectionOwner.Unlock()
					_ = listener.Close()
					if connection != nil {
						_ = connection.Close()
					}
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("peer goroutine did not stop")
					}
				})
				go func() {
					defer close(done)
					connection, e := listener.Accept()
					if e != nil {
						finished <- e
						return
					}
					defer connection.Close()
					connectionOwner.Lock()
					accepted = connection
					stop := closing
					connectionOwner.Unlock()
					if stop {
						finished <- net.ErrClosed
						return
					}
					if e = connection.SetDeadline(time.Now().Add(8 * time.Second)); e != nil {
						finished <- e
						return
					}
					buffer := make([]byte, 1500)
					n, e := connection.Read(buffer)
					if scenario == "reject" {
						if e == io.EOF && observed.seen.Load() {
							finished <- nil
						} else {
							finished <- fmt.Errorf("missing decoded fatal: %v", e)
						}
						return
					}
					if e != nil || n != 1163 || !bytes.Equal(buffer[:n], bytes.Repeat([]byte{'x'}, 1163)) {
						finished <- fmt.Errorf("application boundary: n=%d err=%v", n, e)
						return
					}
					state, ok := connection.(*dtls.Conn).ConnectionState()
					if !ok {
						finished <- fmt.Errorf("no authenticated state")
						return
					}
					material, e := state.ExportKeyingMaterial("EXPERIMENTAL-cnet", nil, 65)
					if e != nil {
						finished <- e
						return
					}
					exported <- material
					if _, e = connection.Write([]byte("pion-to-native")); e != nil {
						finished <- e
						return
					}
					n, e = connection.Read(buffer)
					if scenario == "data-reject" {
						if e == io.EOF && observed.seen.Load() {
							finished <- nil
						} else {
							finished <- fmt.Errorf("missing callback-failure fatal: %v", e)
						}
						return
					}
					if e != nil || n != 0 {
						finished <- fmt.Errorf("empty datagram: n=%d err=%v", n, e)
						return
					}
					if _, e = connection.Write(nil); e != nil {
						finished <- e
						return
					}
					n, e = connection.Read(buffer)
					if n != 0 || e != io.EOF {
						finished <- fmt.Errorf("close_notify: n=%d err=%v", n, e)
						return
					}
					finished <- nil
				}()
				policy := "accept"
				if scenario == "reject" {
					policy = "reject"
				}
				if scenario == "data-reject" {
					policy = "data-reject"
				}
				if strings.HasPrefix(variant, "backpressure") || variant == "deferred-reject" {
					policy = variant
				}
				n := startDTLS(t, listener.Addr().(*net.UDPAddr).Port, mode, policy, server, client)
				if st, _ := n.rpc('I', nil); st != 0 || n.state != 1 || n.checks != 0 {
					t.Fatal("early readiness")
				}
				intruder, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(n.port)})
				if e != nil {
					t.Fatal(e)
				}
				_, e = intruder.Write([]byte("foreign source"))
				_ = intruder.Close()
				if e != nil {
					t.Fatal(e)
				}
				if mode == "owned" && scenario == "server" {
					if st, _ := n.rpc('U', nil); st != 0 {
						t.Fatalf("bounded input admission %d", st)
					}
				}
				if mode == "external" {
					if st, _ := n.rpc('N', nil); st != 0 {
						t.Fatalf("neighbor submit %d", st)
					}
					if st, _ := n.rpc('T', nil); st != 0 || n.flags&2 == 0 || n.wire != 0 {
						t.Fatalf("non-admitted backpressure st=%d flags=%x wire=%d", st, n.flags, n.wire)
					}
				}
				first, empty, closed := false, false, false
				neighborDuringFailure := false
				failedAdmissionChecked := false
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					st, payload := n.rpc('P', nil)
					if st < 0 && scenario != "reject" && scenario != "data-reject" {
						t.Fatalf("native progress %d state=%d", st, n.state)
					}
					if n.state == 5 && !failedAdmissionChecked {
						expected := int32(-4042)
						if scenario == "data-reject" {
							expected = -4006
						}
						if refusal, _ := n.rpc('W', []byte("must not replay")); refusal != expected {
							t.Fatalf("terminal admission became retryable: %d", refusal)
						}
						failedAdmissionChecked = true
					}
					if scenario == "reject" {
						if mode == "external" && n.state == 5 && !neighborDuringFailure {
							if st, _ = n.rpc('N', nil); st != 0 {
								t.Fatal(st)
							}
							neighborDuringFailure = true
						}
						if n.state == 5 && n.flags&3 == 0 && n.localAlert == 49 {
							break
						}
						continue
					}
					if scenario == "data-reject" && n.state == 5 {
						if st != -4006 {
							t.Fatalf("callback error was replaced: %d", st)
						}
						if mode == "external" && !neighborDuringFailure {
							if st, _ = n.rpc('N', nil); st != 0 {
								t.Fatal(st)
							}
							neighborDuringFailure = true
						}
						if n.flags&3 == 0 && n.localAlert == 80 {
							break
						}
						continue
					}
					if n.state == 2 && !first {
						if n.checks != 1 || n.sent != 0 {
							t.Fatal("protocol readiness or send callback mismatch")
						}
						if st, _ = n.rpc('W', make([]byte, 1164)); st != -4016 {
							t.Fatalf("oversized admission %d", st)
						}
						if st, _ = n.rpc('W', bytes.Repeat([]byte{'x'}, 1163)); st != 0 {
							t.Fatal(st)
						}
						if n.sent != 0 || n.flags&3 != 2 {
							t.Fatal("application admission became completion or disappeared from usage")
						}
						if st, _ = n.rpc('W', []byte("blocked")); st != dtlsBusy {
							t.Fatal("admitted a second application write")
						}
						if strings.HasPrefix(scenario, "abort-write") {
							submitted := scenario == "abort-write-pending"
							before := n.wire
							if submitted {
								if st, _ = n.rpc('T', nil); st != 0 || n.flags&3 != 3 || n.sent != 0 {
									t.Fatal("application output was not retained")
								}
							}
							if st, _ = n.rpc('C', nil); st != dtlsBusy {
								t.Fatal("destroy discarded an admitted application tag")
							}
							want := int32(0)
							if submitted {
								want = dtlsBusy
							}
							if st, _ = n.rpc('A', nil); st != want {
								t.Fatalf("application abort %d want %d", st, want)
							}
							for i := 0; i < 20 && n.flags&2 != 0; i++ {
								if st, _ = n.rpc('P', nil); st < 0 {
									t.Fatal(st)
								}
							}
							if n.sent != 1 || n.flags&3 != 0 {
								t.Fatal("application tag or native output did not settle")
							}
							st, last := n.rpc('L', nil)
							want = -4006
							if submitted {
								want = 0
							}
							if st != 0 || len(last) != 4 || int32(binary.BigEndian.Uint32(last)) != want {
								t.Fatal("wrong application terminal")
							}
							delta := uint32(0)
							if submitted {
								delta = 1
							}
							if n.wire != before+delta {
								t.Fatal("application resubmitted or lost its real terminal")
							}
							if st, _ = n.rpc('C', nil); st != 0 || n.refs != 0 {
								t.Fatal("aborted application did not release policy")
							}
							if mode == "external" {
								if st, _ = n.rpc('N', nil); st != 0 {
									t.Fatal(st)
								}
								for i := 0; i < 10 && n.neighborSent < 2; i++ {
									if st, _ = n.rpc('P', nil); st < 0 {
										t.Fatal(st)
									}
								}
								if n.neighborSent != 2 {
									t.Fatal("application abort stopped shared backend")
								}
							}
							return
						}
						first = true
					}
					if len(payload) > 0 {
						at := 0
						for at < len(payload) {
							if len(payload)-at < 2 {
								t.Fatal("truncated message")
							}
							size := int(binary.BigEndian.Uint16(payload[at : at+2]))
							at += 2
							if size > len(payload)-at {
								t.Fatal("truncated callback")
							}
							value := payload[at : at+size]
							at += size
							if !empty {
								if !bytes.Equal(value, []byte("pion-to-native")) {
									t.Fatal("bad callback payload")
								}
								st, material := n.rpc('E', nil)
								if st != 0 {
									t.Fatal("exporter refusal")
								}
								select {
								case expected := <-exported:
									if !bytes.Equal(material, expected) {
										t.Fatal("exporter mismatch")
									}
								case <-time.After(time.Second):
									t.Fatal("peer exporter missing")
								}
								if st, _ = n.rpc('W', nil); st != 0 {
									t.Fatalf("empty admission %d", st)
								}
								empty = true
							} else {
								if len(value) != 0 || n.sent != 2 {
									t.Fatal("empty boundary or tagged send settlement")
								}
								if st, _ = n.rpc('O', nil); st != 0 {
									t.Fatal(st)
								}
								closed = true
							}
						}
					}
					if n.state == 4 {
						break
					}
				}
				if scenario == "reject" {
					if n.state != 5 || n.localAlert != 49 || n.checks != 1 || n.received != 0 || n.sent != 0 || n.flags&3 != 0 {
						t.Fatalf("failed admission state=%d alert=%d flags=%x", n.state, n.localAlert, n.flags)
					}
				} else if scenario == "data-reject" {
					if n.state != 5 || n.localAlert != 80 || n.checks != 1 || n.received != 1 || n.sent != 1 || n.flags&3 != 0 {
						t.Fatal("callback failure was not drained")
					}
				} else if n.state != 4 || !first || !empty || !closed || n.received != 2 || n.sent != 2 {
					t.Fatalf("incomplete native data/close state=%d rx=%d tx=%d", n.state, n.received, n.sent)
				}
				select {
				case err = <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("peer failed to drain")
				}
				expectedNeighbors := uint32(1)
				if neighborDuringFailure {
					expectedNeighbors = 2
				}
				if mode == "external" && (n.neighborReceived != expectedNeighbors || n.neighborSent != expectedNeighbors) {
					t.Fatal("shared backend starved neighbor")
				}
				if st, _ := n.rpc('C', nil); st != 0 || n.refs != 0 {
					t.Fatalf("destroy %d refs=%d", st, n.refs)
				}
				if mode == "external" {
					if st, _ := n.rpc('N', nil); st != 0 {
						t.Fatal("neighbor stopped with protocol")
					}
					for i := 0; i < 10 && n.neighborSent < expectedNeighbors+1; i++ {
						if st, _ := n.rpc('P', nil); st < 0 {
							t.Fatal(st)
						}
					}
					if n.neighborSent != expectedNeighbors+1 {
						t.Fatal("shared backend did not survive destroy")
					}
				}
			})
		}
	}
}
func TestDTLSNativeAbortDrain(t *testing.T) {
	trust := credentials(t, false, "")
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	for _, mode := range []string{"owned", "external"} {
		for _, pending := range []bool{false, true} {
			if mode == "owned" && !pending {
				continue
			}
			t.Run(fmt.Sprintf("%s/submitted_%t", mode, pending), func(t *testing.T) {
				n := startDTLS(t, peer.LocalAddr().(*net.UDPAddr).Port, mode, "accept", trust, nil)
				if !pending {
					if st, _ := n.rpc('N', nil); st != 0 {
						t.Fatal(st)
					}
				}
				if st, _ := n.rpc('T', nil); st != 0 || n.flags&3 != 3 || n.wire != 0 {
					t.Fatalf("prepare %d flags=%x wire=%d", st, n.flags, n.wire)
				}
				if st, _ := n.rpc('C', nil); st != dtlsBusy {
					t.Fatalf("destroy before real terminal %d", st)
				}
				expected := int32(0)
				if pending {
					expected = dtlsBusy
				}
				if st, _ := n.rpc('A', nil); st != expected {
					t.Fatalf("abort %d expected %d", st, expected)
				}
				for i := 0; i < 10 && n.flags&2 != 0; i++ {
					if st, _ := n.rpc('P', nil); st < 0 {
						t.Fatal(st)
					}
				}
				if n.flags&3 != 0 {
					t.Fatal("native borrow did not settle")
				}
				if pending && n.wire != 1 {
					t.Fatal("actual send terminal was lost")
				}
				if !pending && n.wire != 0 {
					t.Fatal("non-admitted wire was sent")
				}
				if st, _ := n.rpc('C', nil); st != 0 || n.refs != 0 {
					t.Fatal("drain did not release policy")
				}
				if mode == "external" {
					if pending {
						if st, _ := n.rpc('N', nil); st != 0 {
							t.Fatal(st)
						}
					}
					for i := 0; i < 10 && n.neighborSent == 0; i++ {
						n.rpc('P', nil)
					}
					if n.neighborSent != 1 || n.neighborReceived != 1 {
						t.Fatal("neighbor did not survive protocol abort")
					}
				}
			})
		}
	}
}
