package secure

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/pion/dtls/v3"
	curve "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/sctp"
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
)

var native = flag.String("native", "", "formal secure SCTP native peer")

type identity struct {
	cert         tls.Certificate
	roots        *x509.CertPool
	ca, crt, key string
}

// Coalesce two independently encrypted application records into one real UDP
// datagram. One bounded pair, no key or packet rewriting.
type coalescer struct {
	net.PacketConn
	mu       sync.Mutex
	armed    bool
	held     []byte
	combined atomic.Uint32
}

func (c *coalescer) arm() { c.mu.Lock(); c.armed = true; c.mu.Unlock() }
func (c *coalescer) WriteTo(p []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.armed && len(p) > 13 && p[0] == 23 {
		if len(c.held) == 0 {
			c.held = append([]byte(nil), p...)
			return len(p), nil
		}
		wire := append(c.held, p...)
		c.held = nil
		c.armed = false
		n, e := c.PacketConn.WriteTo(wire, a)
		if e != nil {
			return 0, e
		}
		if n != len(wire) {
			return 0, io.ErrShortWrite
		}
		c.combined.Add(1)
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, a)
}

func credentials(t *testing.T) identity {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "secure SCTP CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rd, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(rd)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	id := identity{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots: x509.NewCertPool(), ca: filepath.Join(dir, "ca.pem"), crt: filepath.Join(dir, "cert.pem"), key: filepath.Join(dir, "key.pem")}
	id.roots.AddCert(parsed)
	for path, b := range map[string]*pem.Block{id.ca: {Type: "CERTIFICATE", Bytes: rd}, id.crt: {Type: "CERTIFICATE", Bytes: der}, id.key: {Type: "PRIVATE KEY", Bytes: kd}} {
		if err = os.WriteFile(path, pem.EncodeToMemory(b), 0600); err != nil {
			t.Fatal(err)
		}
	}
	clear(kd)
	return id
}

type snapshot struct {
	status, err                          int32
	state, flags, refs, checks, neighbor byte
	messages, acks, sends, neighborSends uint32
	generation                           uint64
	port                                 int
}
type process struct {
	t   *testing.T
	in  io.WriteCloser
	out io.ReadCloser
	log string
}

func start(t *testing.T, mode string, server, client identity, ports []int) *process {
	t.Helper()
	if *native == "" {
		t.Fatal("missing formal native SCTP executable")
	}
	args := []string{mode, client.ca, server.crt, server.key}
	for _, p := range ports {
		args = append(args, strconv.Itoa(p))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	cmd := exec.CommandContext(ctx, *native, args...)
	path := filepath.Join(t.TempDir(), "native.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = f
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
	t.Cleanup(func() {
		_ = in.Close()
		e := cmd.Wait()
		cancel()
		_ = out.Close()
		_ = f.Close()
		if e != nil {
			log, _ := os.ReadFile(path)
			t.Errorf("native cleanup: %v %s", e, log)
		}
	})
	return &process{t, in, out, path}
}
func (p *process) rpc(op byte, index int) (snapshot, []byte) {
	p.t.Helper()
	if _, err := p.in.Write([]byte{op, byte(index)}); err != nil {
		p.t.Fatal(err)
	}
	var b [40]byte
	if _, err := io.ReadFull(p.out, b[:]); err != nil {
		log, _ := os.ReadFile(p.log)
		p.t.Fatalf("native reply: %v %s", err, log)
	}
	s := snapshot{status: int32(binary.BigEndian.Uint32(b[:4])), state: b[4], flags: b[5], refs: b[6], checks: b[7], messages: binary.BigEndian.Uint32(b[8:]), acks: binary.BigEndian.Uint32(b[12:]), generation: binary.BigEndian.Uint64(b[16:]), port: int(binary.BigEndian.Uint16(b[24:])), neighbor: b[27], err: int32(binary.BigEndian.Uint32(b[28:])), neighborSends: binary.BigEndian.Uint32(b[32:]), sends: binary.BigEndian.Uint32(b[36:])}
	var proof []byte
	if (op == 'M' || op == 'F') && s.status == 0 {
		proof = make([]byte, 32)
		if _, err := io.ReadFull(p.out, proof); err != nil {
			p.t.Fatal(err)
		}
	}
	return s, proof
}
func TestSCTPOverNativeDTLS(t *testing.T) {
	for _, mode := range []string{"owned", "external", "owned-client", "external-client"} {
		nativeClient := strings.HasSuffix(mode, "-client")
		external := strings.HasPrefix(mode, "external")
		cases := []struct {
			count int
			mixed bool
		}{{1, false}, {4, true}, {8, true}, {8, false}}
		if nativeClient {
			cases = cases[:1]
		}
		for _, scenario := range cases {
			count, mixed := scenario.count, scenario.mixed
			t.Run(fmt.Sprintf("%s/%d/mixed_%t", mode, count, mixed), func(t *testing.T) {
				server, client, bad := credentials(t), credentials(t), credentials(t)
				sockets := make([]*net.UDPConn, count)
				ports := make([]int, count)
				for i := range sockets {
					u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					sockets[i] = u
					ports[i] = u.LocalAddr().(*net.UDPAddr).Port
					t.Cleanup(func() { _ = u.Close() })
				}
				localIdentity, trust := server, client
				if nativeClient {
					localIdentity, trust = client, server
				}
				p := start(t, mode, localIdentity, trust, ports)
				initial, _ := p.rpc('I', 0)
				if initial.status != 0 || (!nativeClient && initial.state != 0) || (nativeClient && initial.state != 1) || initial.refs != 1 {
					t.Fatal("invalid listener startup")
				}
				if external {
					s, _ := p.rpc('N', 0)
					if s.status != 0 {
						t.Fatal(s.status)
					}
				}
				done := make(chan int, count)
				problems := make(chan error, count)
				stop := make(chan struct{})
				release := make(chan struct{})
				var workers sync.WaitGroup
				var ready atomic.Bool
				material := make(chan []byte, 1)
				connections := make([]*dtls.Conn, count)
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				for i := 0; i < count; i++ {
					id := client
					if mixed && i == 0 {
						id = bad
					}
					transport := &coalescer{PacketConn: sockets[i]}
					peerConfig := &dtls.Config{Certificates: []tls.Certificate{id.cert}, RootCAs: server.roots, ServerName: "localhost", CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, EllipticCurves: []curve.Curve{curve.P256}, ExtendedMasterSecret: dtls.RequireExtendedMasterSecret, SupportedProtocols: []string{"test"}, MTU: 512, FlightInterval: 150 * time.Millisecond}
					var conn *dtls.Conn
					var err error
					if nativeClient {
						peerConfig.Certificates = []tls.Certificate{server.cert}
						peerConfig.ServerName = ""
						peerConfig.ClientAuth = dtls.RequireAndVerifyClientCert
						peerConfig.ClientCAs = client.roots
						conn, err = dtls.Server(transport, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: initial.port}, peerConfig)
					} else {
						conn, err = dtls.Client(transport, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: initial.port}, peerConfig)
					}
					if err != nil {
						t.Fatal(err)
					}
					connections[i] = conn
					workers.Add(1)
					go func(i int, c *dtls.Conn) {
						defer workers.Done()
						fail := func(err error) { problems <- fmt.Errorf("client %d: %w", i, err); done <- i }
						if e := c.HandshakeContext(ctx); e != nil {
							if mixed && i == 0 && strings.Contains(e.Error(), "CertificateUnknown") {
								done <- i
								select {
								case <-release:
								case <-ctx.Done():
								}
								return
							}
							fail(e)
							return
						}
						if mixed && i == 0 {
							fail(fmt.Errorf("untrusted identity authenticated"))
							return
						}
						if i == count-1 {
							state, ok := c.ConnectionState()
							if !ok {
								fail(fmt.Errorf("no verified state"))
								return
							}
							key, e := state.ExportKeyingMaterial("EXPERIMENTAL-SCTP-cookie", nil, 32)
							if e != nil {
								fail(e)
								return
							}
							h := hmac.New(sha256.New, key)
							_, _ = h.Write([]byte("cookie-proof"))
							proof := h.Sum(nil)
							clear(key)
							material <- proof
						}
						var association *sctp.Association
						var e error
						if nativeClient {
							association, e = sctp.ServerWithOptions(sctp.WithNetConn(c), sctp.WithMaxMessageSize(24576), sctp.WithEnableInterleaving(true))
						} else {
							association, e = sctp.ClientWithOptions(sctp.WithNetConn(c), sctp.WithMaxMessageSize(24576), sctp.WithEnableInterleaving(true))
						}
						if e != nil {
							fail(e)
							return
						}
						defer association.Close()
						meta, ok := association.Metadata()
						if !ok || !meta.MessageInterleavingEnabled {
							fail(fmt.Errorf("I-DATA not negotiated"))
							return
						}
						sid := uint16(0)
						if nativeClient {
							sid = 1
						}
						stream, e := association.OpenStream(sid, sctp.PayloadTypeWebRTCDCEP)
						if e != nil {
							fail(e)
							return
						}
						_ = stream.SetReadDeadline(time.Now().Add(20 * time.Second))
						if _, e = stream.WriteSCTP([]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, sctp.PayloadTypeWebRTCDCEP); e != nil {
							fail(e)
							return
						}
						buffer := make([]byte, 24576)
						n, ppi, e := stream.ReadSCTP(buffer)
						if e != nil || ppi != sctp.PayloadTypeWebRTCDCEP || n != 1 || buffer[0] != 2 {
							fail(fmt.Errorf("DCEP ACK %d %d %v", n, ppi, e))
							return
						}
						if mixed && i == 1 {
							ready.Store(true)
							select {
							case <-stop:
							case <-ctx.Done():
								fail(ctx.Err())
								return
							}
							done <- i
							return
						}
						for _, size := range []int{1, 1024, 24576, 0} {
							if size == 24576 {
								transport.arm()
							}
							payload := bytes.Repeat([]byte{byte(31 + i)}, size)
							kind := sctp.PayloadTypeWebRTCBinary
							if size == 0 {
								payload = []byte{0}
								kind = sctp.PayloadTypeWebRTCBinaryEmpty
							}
							if _, e = stream.WriteSCTP(payload, kind); e != nil {
								fail(e)
								return
							}
							n, ppi, e = stream.ReadSCTP(buffer)
							if e != nil || ppi != kind || !bytes.Equal(buffer[:n], payload) {
								fail(fmt.Errorf("message size=%d received=%d ppid=%d err=%v", size, n, ppi, e))
								return
							}
						}
						if transport.combined.Load() != 1 {
							fail(fmt.Errorf("coalesced record tail was not exercised"))
							return
						}
						done <- i
						select {
						case <-release:
						case <-ctx.Done():
						}
					}(i, conn)
				}
				t.Cleanup(func() {
					close(release)
					cancel()
					for _, c := range connections {
						if c != nil {
							_ = c.Close()
						}
						joined := make(chan struct{})
						go func() { workers.Wait(); close(joined) }()
						select {
						case <-joined:
						case <-time.After(2 * time.Second):
							t.Error("secure SCTP workers did not drain")
						}
					}
				})
				snapshots := make([]snapshot, count)
				finished := make([]bool, count)
				got := 0
				aborted := false
				proofChecked := false
				ownerChecked := false
				deadline := time.Now().Add(27 * time.Second)
				for time.Now().Before(deadline) {
					i := 0
					s, _ := p.rpc('P', i)
					if s.status != 0 {
						t.Fatal("host route error", s.status)
					}
					for i = 0; i < count; i++ {
						s, _ = p.rpc('I', i)
						snapshots[i] = s
						if s.err != 0 && !(mixed && i == 0) && !(mixed && i == 1 && aborted) {
							t.Fatalf("association %d error %d state %d", i, s.err, s.state)
						}
					}
					for {
						select {
						case i := <-done:
							if finished[i] {
								t.Fatal("duplicate client terminal")
							}
							finished[i] = true
							got++
						default:
							goto drained
						}
					}
				drained:
					select {
					case err := <-problems:
						t.Fatal(err)
					default:
					}
					if mixed && ready.Load() && !aborted {
						s, _ = p.rpc('A', 1)
						if s.status != 0 && s.status != -4005 {
							t.Fatal("abort", s.status)
						}
						close(stop)
						aborted = true
					}
					if !ownerChecked && snapshots[count-1].generation != 0 {
						s, _ = p.rpc('V', count-1)
						if s.status != -4040 {
							t.Fatal("owner refusal", s.status)
						}
						ownerChecked = true
					}
					if !proofChecked && snapshots[count-1].generation != 0 {
						select {
						case expected := <-material:
							s, proof := p.rpc('M', count-1)
							equal := hmac.Equal(proof, expected)
							privateStatus, cookieProof := p.rpc('F', count-1)
							if privateStatus.status != 0 || hmac.Equal(cookieProof, expected) {
								t.Fatal("SCTP cookie proof used only the shared exporter")
							}
							clear(cookieProof)
							clear(proof)
							clear(expected)
							if s.status != 0 || !equal {
								t.Fatal("GmSSL exporter HMAC mismatch")
							}
							proofChecked = true
						default:
						}
					}
					complete := got == count && proofChecked && ownerChecked
					for i, s := range snapshots {
						if mixed && i < 2 {
							continue
						}
						if s.messages != 4 || s.acks != 4 {
							complete = false
						}
					}
					if complete {
						break
					}
				}
				if got != count || !proofChecked || !ownerChecked {
					t.Fatalf("incomplete clients=%d/%d proof=%v owner=%v", got, count, proofChecked, ownerChecked)
				}
				for i, s := range snapshots {
					if mixed && i < 2 {
						continue
					}
					if s.messages != 4 || s.acks != 4 {
						t.Fatalf("peer %d message/ACK mismatch %d/%d err=%d flags=%x", i, s.messages, s.acks, s.err, s.flags)
					}
				}
				var s snapshot
				if !nativeClient {
					s, _ = p.rpc('K', 0)
					if s.status != -4005 {
						t.Fatal("listener destroyed before leases", s.status)
					}
				}
				if count == 1 {
					for i := 0; i < 50; i++ {
						s, _ = p.rpc('R', 0)
						if s.status != -4005 {
							break
						}
						_, _ = p.rpc('P', 0)
					}
					if s.status != -4042 {
						t.Fatal("stale Session advanced after DTLS replacement", s.status)
					}
				}
				for i := range snapshots {
					if !(mixed && i == 1) {
						s, _ = p.rpc('A', i)
						if s.status != 0 && s.status != -4005 {
							t.Fatal("abort", s.status)
						}
					}
				}
				for round := 0; round < 50; round++ {
					_, _ = p.rpc('P', 0)
					pending := false
					for i := range snapshots {
						s, _ = p.rpc('I', i)
						if s.flags&7 != 0 {
							pending = true
						}
					}
					if !pending {
						break
					}
				}
				for i := range snapshots {
					s, _ = p.rpc('C', i)
					if s.status != 0 {
						t.Fatal("destroy before settlement", i, s.status)
					}
				}
				s, _ = p.rpc('K', 0)
				if s.status != 0 || s.refs != 0 {
					t.Fatal("listener leak", s.status, s.refs)
				}
				if external {
					s, _ = p.rpc('N', 0)
					if s.status != 0 {
						t.Fatal(s.status)
					}
					for i := 0; i < 30; i++ {
						s, _ = p.rpc('P', 0)
						if s.status != 0 {
							t.Fatal(s.status)
						}
						if s.neighborSends == 2 && s.neighbor != 0 {
							break
						}
					}
					if s.neighborSends != 2 || s.neighbor == 0 {
						t.Fatal("shared backend neighbor stopped")
					}
				}
				cancel()
			})
		}
	}
}
