package independent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	pioncurve "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/logging"
)

var endpoint = flag.String("dtls-client", "", "native private DTLS client endpoint")

type nativeClient struct {
	t       *testing.T
	command *exec.Cmd
	in      io.WriteCloser
	out     io.ReadCloser
	log     string
	start   time.Time
	phase   byte
	flags   byte
	checks  uint16
	refs    int32
}

func newClient(t *testing.T, root []byte, identity ...tls.Certificate) *nativeClient {
	return newClientExporter(t, root, false, identity...)
}
func newClientExporter(t *testing.T, root []byte, exporter bool, identity ...tls.Certificate) *nativeClient {
	return newClientPolicy(t, root, exporter, "accept", identity...)
}
func newClientPolicy(t *testing.T, root []byte, exporter bool, policy string, identity ...tls.Certificate) *nativeClient {
	args := []string{"localhost", policy, "test"}
	if exporter {
		args = append(args, "exporter")
	}
	n := startEndpoint(t, *endpoint, args...)
	op, body := byte('I'), root
	if len(identity) != 0 {
		private, err := x509.MarshalPKCS8PrivateKey(identity[0].PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		chain := bytes.Join(identity[0].Certificate, nil)
		body = make([]byte, 13)
		body[0] = 1 // Credential object is released before first network progress.
		binary.BigEndian.PutUint32(body[1:5], uint32(len(root)))
		binary.BigEndian.PutUint32(body[5:9], uint32(len(chain)))
		binary.BigEndian.PutUint32(body[9:13], uint32(len(private)))
		body = append(body, root...)
		body = append(body, chain...)
		body = append(body, private...)
		op = 'J'
	}
	status, _ := n.rpc(op, body)
	if status != 0 || n.refs != 1 {
		t.Fatalf("init status=%d refs=%d\n%s", status, n.refs, n.diagnostics())
	}
	return n
}
func exportedMaterial(connection *dtls.Conn) ([]byte, error) {
	state, ok := connection.ConnectionState()
	if !ok {
		return nil, fmt.Errorf("missing DTLS peer state")
	}
	return state.ExportKeyingMaterial("EXPERIMENTAL-salts-dtls", nil, 65)
}
func nativeExport(t *testing.T, n *nativeClient, enabled bool, expected []byte) {
	t.Helper()
	label := []byte("EXPERIMENTAL-salts-dtls")
	request := make([]byte, 7)
	binary.BigEndian.PutUint16(request[1:3], uint16(len(label)))
	binary.BigEndian.PutUint16(request[5:7], 65)
	status, value := n.rpc('E', append(request, label...))
	if !enabled {
		if status != -5 || len(value) != 0 {
			t.Fatal("disabled exporter admitted")
		}
		return
	}
	if status != 0 || !bytes.Equal(value, expected) {
		t.Fatal("native/Pion exporter mismatch")
	}
}
func sendNativeFatal(t *testing.T, n *nativeClient, failure int32, epoch uint16, send func([]byte) (int, error)) {
	t.Helper()
	status, wire := n.rpc('N', nil)
	if status != 0 || len(wire) < 15 || len(wire) > 39 || wire[0] != 21 || binary.BigEndian.Uint16(wire[3:5]) != epoch || n.flags&8 == 0 {
		t.Fatalf("fatal prepare status=%d size=%d flags=%x", status, len(wire), n.flags)
	}
	if status, _ = n.rpc('N', nil); status != 2 {
		t.Fatal("prepared fatal did not retain its native borrow")
	}
	if status, _ = n.rpc('C', nil); status != 2 {
		t.Fatal("cleared a pending fatal")
	}
	count, err := send(wire)
	success := byte(0)
	if err == nil && count == len(wire) {
		success = 1
	}
	if status, _ = n.rpc('S', []byte{success}); status != failure {
		t.Fatal("fatal send replaced the original failure")
	}
	if err != nil || success == 0 {
		t.Fatalf("fatal UDP send count=%d err=%v", count, err)
	}
	if status, _ = n.rpc('N', nil); status != failure {
		t.Fatal("fatal was retried")
	}
}

// Pion reports post-handshake fatal as EOF to Read. Observe only its decoded
// alert classification through the existing logger API, without retaining or
// printing packet/key data; EOF alone is never evidence of a fatal alert.
type fatalObserver struct {
	base logging.LoggerFactory
	seen atomic.Bool
}
type fatalObserverLog struct {
	logging.LeveledLogger
	seen *atomic.Bool
}

func newFatalObserver() *fatalObserver {
	base := logging.NewDefaultLoggerFactory()
	base.DefaultLogLevel = logging.LogLevelDisabled
	base.Writer = io.Discard
	return &fatalObserver{base: base}
}
func (f *fatalObserver) NewLogger(scope string) logging.LeveledLogger {
	return &fatalObserverLog{LeveledLogger: f.base.NewLogger(scope), seen: &f.seen}
}
func (l *fatalObserverLog) Tracef(format string, args ...interface{}) {
	if format == "%s: <- %s" && len(args) == 2 {
		if text, ok := args[1].(string); ok && text == "Alert Fatal: AccessDenied" {
			l.seen.Store(true)
		}
	}
}
func awaitPeerFatal(t *testing.T, finished <-chan error, observed ...*atomic.Bool) {
	t.Helper()
	select {
	case err := <-finished:
		var alert interface{ IsFatalOrCloseNotify() bool }
		if len(observed) != 0 && observed[0].Load() && errors.Is(err, io.EOF) {
			return
		}
		if !errors.As(err, &alert) || !alert.IsFatalOrCloseNotify() {
			t.Fatalf("peer did not receive fatal alert: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not receive fatal alert")
	}
}
func startEndpoint(t *testing.T, executable string, args ...string) *nativeClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	cmd := exec.CommandContext(ctx, executable, args...)
	log := filepath.Join(t.TempDir(), "native.log")
	file, err := os.Create(log)
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
	n := &nativeClient{t: t, command: cmd, in: in, out: out, log: log, start: time.Now()}
	t.Cleanup(func() {
		_ = in.Close()
		err := cmd.Wait()
		cancel()
		_ = out.Close()
		_ = file.Close()
		if err != nil {
			t.Errorf("native endpoint: %v\n%s", err, n.diagnostics())
		}
	})
	return n
}
func (n *nativeClient) diagnostics() string { data, _ := os.ReadFile(n.log); return string(data) }
func (n *nativeClient) rpc(op byte, body []byte) (int32, []byte) {
	n.t.Helper()
	request := make([]byte, 13+len(body))
	request[0] = op
	binary.BigEndian.PutUint64(request[1:9], uint64(time.Since(n.start).Milliseconds()))
	binary.BigEndian.PutUint32(request[9:13], uint32(len(body)))
	copy(request[13:], body)
	if _, err := n.in.Write(request); err != nil {
		n.t.Fatal(err)
	}
	var response [24]byte
	if _, err := io.ReadFull(n.out, response[:]); err != nil {
		n.t.Fatalf("native response: %v\n%s", err, n.diagnostics())
	}
	status := int32(binary.BigEndian.Uint32(response[:4]))
	n.phase = response[4]
	n.flags = response[5]
	n.checks = binary.BigEndian.Uint16(response[6:8])
	n.refs = int32(binary.BigEndian.Uint32(response[8:12]))
	size := binary.BigEndian.Uint32(response[20:24])
	if size > 32768 {
		n.t.Fatalf("invalid native length %d", size)
	}
	result := make([]byte, size)
	if _, err := io.ReadFull(n.out, result); err != nil {
		n.t.Fatal(err)
	}
	if status < 0 {
		n.t.Logf("native status=%d phase=%d verify=%d index=%d", status, n.phase, binary.BigEndian.Uint32(response[12:16]), binary.BigEndian.Uint32(response[16:20]))
	}
	return status, result
}

func identity(t *testing.T, rsaLeaf bool) ([]byte, tls.Certificate) {
	return roleIdentity(t, rsaLeaf, false, false)
}
func roleIdentity(t *testing.T, rsaLeaf, client, padded bool) ([]byte, tls.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DTLS test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	var key crypto.Signer
	if rsaLeaf {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if client {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if padded { // A legitimate noncritical extension forces certificate fragmentation.
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: append([]byte{4, 0x82, 4, 0}, make([]byte, 1024)...)}}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return rootDER, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}
}

func TestDTLSClientAgainstPion(t *testing.T) {
	if *endpoint == "" {
		t.Fatal("missing native DTLS client endpoint")
	}
	for _, rsaLeaf := range []bool{false, true} {
		for _, loss := range []bool{false, true} {
			for _, clientKind := range []string{"none", "ec", "rsa", "reject"} {
				t.Run(fmt.Sprintf("rsa_%t/drop_finished_%t/client_%s", rsaLeaf, loss, clientKind), func(t *testing.T) {
					root, cert := identity(t, rsaLeaf)
					var clientCertificate []tls.Certificate
					clientAuth := dtls.NoClientCert
					clientRoots := x509.NewCertPool()
					if clientKind != "none" && clientKind != "reject" {
						clientRoot, certificate := roleIdentity(t, clientKind == "rsa", true, true)
						parsed, err := x509.ParseCertificate(clientRoot)
						if err != nil {
							t.Fatal(err)
						}
						clientRoots.AddCert(parsed)
						clientCertificate = []tls.Certificate{certificate}
						clientAuth = dtls.RequireAndVerifyClientCert
					}
					suite := dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
					observer := newFatalObserver()
					if rsaLeaf {
						suite = dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
					}
					listener, err := dtls.Listen("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &dtls.Config{
						Certificates: []tls.Certificate{cert}, CipherSuites: []dtls.CipherSuiteID{suite},
						SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PKCS1WithSHA256},
						ClientAuth:       clientAuth, ClientCAs: clientRoots,
						LoggerFactory:  observer,
						EllipticCurves: []pioncurve.Curve{pioncurve.P256}, ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
						SupportedProtocols: []string{"test"}, MTU: 512, FlightInterval: 150 * time.Millisecond,
					})
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					var accepted net.Conn
					var acceptedMu sync.Mutex
					closing := false
					defer func() {
						acceptedMu.Lock()
						closing = true
						connection := accepted
						acceptedMu.Unlock()
						if connection != nil {
							_ = connection.Close()
						}
					}()
					finished := make(chan error, 1)
					exported := make(chan []byte, 1)
					go func() {
						connection, e := listener.Accept()
						if e != nil {
							finished <- e
							return
						}
						defer connection.Close()
						acceptedMu.Lock()
						if closing {
							acceptedMu.Unlock()
							finished <- net.ErrClosed
							return
						}
						accepted = connection
						acceptedMu.Unlock()
						if e = connection.SetDeadline(time.Now().Add(7 * time.Second)); e != nil {
							finished <- e
							return
						}
						buffer := make([]byte, 1500)
						size, e := connection.Read(buffer)
						if e != nil {
							finished <- e
							return
						}
						if !bytes.Equal(buffer[:size], []byte("native-to-pion")) {
							finished <- fmt.Errorf("wrong native application payload")
							return
						}
						material, e := exportedMaterial(connection.(*dtls.Conn))
						if e != nil {
							finished <- e
							return
						}
						exported <- material
						if _, e = connection.Write([]byte("pion-to-native")); e != nil {
							finished <- e
							return
						}
						size, e = connection.Read(buffer)
						if size != 0 || e != io.EOF {
							finished <- fmt.Errorf("close_notify: size=%d err=%v", size, e)
							return
						}
						finished <- nil
					}()
					raw, err := net.DialUDP("udp4", nil, listener.Addr().(*net.UDPAddr))
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					policy := "accept"
					if clientKind == "reject" {
						policy = "reject"
					}
					n := newClientPolicy(t, root, loss, policy, clientCertificate...)
					nativeExport(t, n, false, nil) // Not READY, even if enabled.
					sentApplication, echo, dropped, fragmented := false, false, false, false
					deadline := time.Now().Add(9 * time.Second)
					for time.Now().Before(deadline) && n.phase != 9 {
						for {
							status, wire := n.rpc('N', nil)
							if status == 1 {
								break
							}
							if status != 0 {
								t.Fatalf("next status=%d phase=%d\n%s", status, n.phase, n.diagnostics())
							}
							if len(wire) > 25 && wire[0] == 22 && wire[3] == 0 && wire[4] == 0 && wire[13] == 11 {
								fragmented = fragmented || !bytes.Equal(wire[14:17], wire[22:25])
							}
							if n.phase == 6 && n.flags&64 == 0 {
								t.Fatal("client signing key survived final-flight construction")
							}
							if loss && !dropped && len(wire) >= 13 && wire[0] == 22 && binary.BigEndian.Uint16(wire[3:5]) == 1 {
								dropped = true // Simulated network loss after successful local send.
							} else if _, err = raw.Write(wire); err != nil {
								t.Fatal(err)
							}
							if status, _ = n.rpc('S', []byte{1}); status != 0 {
								t.Fatalf("send terminal %d", status)
							}
						}
						if n.phase == 9 {
							break
						}
						if n.phase == 7 && !sentApplication {
							if n.checks != 1 {
								t.Fatalf("peer policy checks=%d", n.checks)
							}
							if status, _ := n.rpc('W', []byte("native-to-pion")); status != 0 {
								t.Fatalf("application admission %d", status)
							}
							sentApplication = true
							continue
						}
						if err = raw.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
							t.Fatal(err)
						}
						packet := make([]byte, 16421)
						size, e := raw.Read(packet)
						if e != nil {
							if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
								continue
							}
							t.Fatal(e)
						}
						status, payload := n.rpc('R', packet[:size])
						if status < 0 && clientKind == "reject" {
							if n.phase != 10 || n.checks != 1 || n.flags&8 == 0 {
								t.Fatal("policy rejection published readiness or retained keys")
							}
							sendNativeFatal(t, n, status, 1, raw.Write)
							awaitPeerFatal(t, finished, &observer.seen)
							if status, _ = n.rpc('C', nil); status != 0 || n.refs != 0 {
								t.Fatal("failed client did not clear")
							}
							return
						}
						if status != 0 && status != 3 {
							t.Fatalf("receive status=%d phase=%d\n%s", status, n.phase, n.diagnostics())
						}
						if len(payload) > 0 {
							if len(payload) < 2 || int(binary.BigEndian.Uint16(payload[:2])) != len(payload)-2 || !bytes.Equal(payload[2:], []byte("pion-to-native")) {
								t.Fatalf("wrong native callback payload")
							}
							echo = true
							select {
							case material := <-exported:
								nativeExport(t, n, loss, material)
							case <-time.After(time.Second):
								t.Fatal("missing peer exporter")
							}
							if (n.flags&32 != 0) == loss {
								t.Fatal("exporter master retention mismatch")
							}
							if status, _ = n.rpc('O', nil); status != 0 {
								t.Fatalf("close admission %d", status)
							}
							nativeExport(t, n, false, nil)
							if n.flags&32 == 0 {
								t.Fatal("master survived close admission")
							}
						}
					}
					if n.phase != 9 || !sentApplication || !echo || (loss && !dropped) {
						t.Fatalf("incomplete exchange phase=%d sent=%t echo=%t dropped=%t\n%s", n.phase, sentApplication, echo, dropped, n.diagnostics())
					}
					if clientKind != "none" && (!fragmented || n.flags&128 == 0) {
						t.Fatal("client authentication or certificate fragmentation was not exercised")
					}
					select {
					case err = <-finished:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("Pion did not finish authenticated close")
					}
					if status, _ := n.rpc('C', nil); status != 0 || n.refs != 0 {
						t.Fatalf("clear status=%d references=%d", status, n.refs)
					}
				})
			}
		}
	}
}
