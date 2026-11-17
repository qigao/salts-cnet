package tls_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"testing"
	"time"
)

var privateNative = flag.String("private-native", "", "existing private CNet test executable")
var pluginLoader = flag.String("plugin-loader", "", "existing two-plugin loader")
var pluginA = flag.String("plugin-a", "", "existing plugin A")
var pluginB = flag.String("plugin-b", "", "existing plugin B")
var peerProtocol = flag.String("protocol", "", "pinned TLS peer version")
var pinnedFixtures = flag.String("fixtures", "", "pinned test certificate directory")

type peerIdentity struct {
	cert              *x509.Certificate
	key               crypto.Signer
	certPath, keyPath string
	tls               tls.Certificate
}
type peerFixtures struct {
	root, intermediate peerIdentity
	identities         map[string]peerIdentity
}

func peerKey(t *testing.T, ec bool) crypto.Signer {
	t.Helper()
	if ec {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
func peerCert(t *testing.T, name string, key crypto.Signer, parent *peerIdentity, change func(*x509.Certificate), corrupt bool) peerIdentity {
	t.Helper()
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if change != nil {
		change(template)
	}
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if corrupt {
		der[len(der)-1] ^= 1
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if corrupt && cert.CheckSignatureFrom(issuer) == nil {
		t.Fatal("corrupt certificate still verifies")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	result := peerIdentity{cert: cert, key: key, certPath: filepath.Join(dir, "cert.pem"), keyPath: filepath.Join(dir, "key.pem")}
	for path, block := range map[string]*pem.Block{result.certPath: {Type: "CERTIFICATE", Bytes: der}, result.keyPath: {Type: "PRIVATE KEY", Bytes: private}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".der", block.Bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	result.tls = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
	return result
}
func makePeerFixtures(t *testing.T) peerFixtures {
	t.Helper()
	ca := func(c *x509.Certificate) {
		c.IsCA = true
		c.MaxPathLen = 2
		c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		c.ExtKeyUsage = nil
	}
	root := peerCert(t, "mTLS root", peerKey(t, false), nil, ca, false)
	wrong := peerCert(t, "untrusted root", peerKey(t, false), nil, ca, false)
	intermediate := peerCert(t, "intermediate", peerKey(t, false), &root, ca, false)
	f := peerFixtures{root: root, intermediate: intermediate, identities: map[string]peerIdentity{}}
	for _, name := range []string{"server", "client", "wrongca", "eku", "expired", "chain", "badsig", "server-ip", "server-ip-dns", "server-chain"} {
		parent := &root
		if name == "wrongca" {
			parent = &wrong
		}
		if name == "chain" || name == "server-chain" {
			parent = &intermediate
		}
		id := peerCert(t, name, peerKey(t, false), parent, func(c *x509.Certificate) {
			if strings.HasPrefix(name, "server") || name == "eku" {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
			if name == "server" || name == "server-chain" {
				c.DNSNames = []string{"localhost"}
			}
			if name == "server-ip" {
				c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
			}
			if name == "server-ip-dns" {
				c.Subject.CommonName = "127.0.0.1"
				c.DNSNames = []string{"127.0.0.1"}
			}
			if name == "expired" {
				c.NotBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
				c.NotAfter = c.NotBefore.Add(24 * time.Hour)
			}
		}, name == "badsig")
		if name == "server-chain" {
			id.tls.Certificate = append(id.tls.Certificate, intermediate.cert.Raw)
		}
		f.identities[name] = id
	}
	return f
}
func peerRun(t *testing.T, binary string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	var out, diagnostic bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		t.Fatalf("native %v: %v\n%s", args[:1], err, safePeerDiagnostic(diagnostic.String()))
	}
	return out.String()
}
func safePeerDiagnostic(s string) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "CNET_") || strings.HasPrefix(line, "TLS_EOF_ORDER") || strings.HasPrefix(line, "CNet TLS case") || strings.Contains(line, "Assertion") || strings.Contains(line, "REQUIRE") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}
func TestRequiredMTLS(t *testing.T) {
	f := makePeerFixtures(t)
	for _, name := range []string{"client", "missing", "wrongca", "eku", "expired", "chain", "badsig"} {
		t.Run(name, func(t *testing.T) {
			cert, key, outcome := "-", "-", "reject"
			if name != "missing" {
				id := f.identities[name]
				cert, key = id.certPath, id.keyPath
			}
			if name == "client" {
				outcome = "accept"
			}
			peerRun(t, *native, "--required-mtls", f.root.certPath, f.identities["server"].certPath, f.identities["server"].keyPath, cert, key, outcome)
		})
	}
}
func TestPrivateRequiredMTLS(t *testing.T) {
	f := makePeerFixtures(t)
	for _, proto := range []string{"12", "13"} {
		for _, name := range []string{"client", "missing", "wrongca", "eku", "expired", "chain", "badsig"} {
			t.Run(proto+"/"+name, func(t *testing.T) {
				cert, key, outcome := "-", "-", "reject"
				if name != "missing" {
					id := f.identities[name]
					cert, key = id.certPath, id.keyPath
				}
				if name == "client" {
					outcome = "accept"
				}
				out := peerRun(t, *privateNative, "--mtls", proto, f.root.certPath, f.identities["server"].certPath, f.identities["server"].keyPath, cert, key, outcome)
				if !strings.Contains(out, "Original CNet Owner + sole static Crypto TLS") {
					t.Fatal("native assertions not reached")
				}
			})
		}
	}
}
func TestPluginMTLS(t *testing.T) {
	f := makePeerFixtures(t)
	for _, name := range []string{"client", "missing", "wrongca", "eku", "expired", "chain", "badsig"} {
		t.Run(name, func(t *testing.T) {
			cert, key, outcome := "-", "-", "reject"
			if name != "missing" {
				id := f.identities[name]
				cert, key = id.certPath, id.keyPath
			}
			if name == "client" {
				outcome = "accept"
			}
			out := peerRun(t, *pluginLoader, "--mtls", *pluginA, *pluginB, f.root.certPath, f.identities["server"].certPath, f.identities["server"].keyPath, cert, key, outcome)
			if !strings.Contains(out, "M6 original CNet TLS12/TLS13 concurrent mTLS") || !strings.Contains(out, "independent plugins PASS") {
				t.Fatal("native concurrent assertions not reached")
			}
		})
	}
}
func peerVersion(proto string) uint16 {
	switch proto {
	case "12", "tls12":
		return tls.VersionTLS12
	case "13", "tls13":
		return tls.VersionTLS13
	default:
		panic("unsupported TLS test protocol: " + proto)
	}
}
func peerConfig(version uint16) *tls.Config {
	return &tls.Config{MinVersion: version, MaxVersion: version, CurvePreferences: []tls.CurveID{tls.CurveP256}, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}
}
func sanSession(t *testing.T, binary, proto, hostname, ca string, certificate tls.Certificate, positive bool) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	results := make(chan error, 1)
	sni := make(chan string, 1)
	config := peerConfig(peerVersion(proto))
	config.Certificates = []tls.Certificate{certificate}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni <- hello.ServerName; return nil, nil }
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(12 * time.Second))
		peer := tls.Server(conn, config)
		if err = peer.Handshake(); err != nil {
			if positive {
				results <- err
			} else {
				results <- nil
			}
			return
		}
		if peer.ConnectionState().Version != peerVersion(proto) {
			results <- fmt.Errorf("wrong TLS version")
			return
		}
		if _, err = peer.Write([]byte("ok")); err != nil {
			if positive {
				results <- err
			} else {
				results <- nil
			}
			return
		}
		if positive {
			var b [1]byte
			if _, err = io.ReadFull(peer, b[:]); err != nil || b[0] != 'F' {
				results <- fmt.Errorf("request: %v", err)
				return
			}
			if _, err = peer.Read(b[:]); err != io.EOF {
				results <- fmt.Errorf("unauthenticated close: %v", err)
				return
			}
			err = peer.CloseWrite()
		} else {
			var b [1]byte
			peer.Read(b[:])
		}
		results <- err
	}()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	args := []string{"--external-san", port, proto, hostname}
	if ca != "" {
		outcome := "reject"
		if positive {
			outcome = "accept"
		}
		args = []string{"--external-ip-san", port, proto, hostname, ca, outcome}
	}
	peerRun(t, binary, args...)
	if err := <-results; err != nil {
		t.Fatal(err)
	}
	expected := hostname
	if net.ParseIP(hostname) != nil {
		expected = ""
	}
	if actual := <-sni; actual != expected {
		t.Fatalf("SNI=%q expected=%q", actual, expected)
	}
}
func TestExternalSAN(t *testing.T) {
	binary := *native
	if *privateNative != "" {
		binary = *privateNative
	}
	certificate, err := tls.LoadX509KeyPair(filepath.Join(*pinnedFixtures, "external-io-server-cert.pem"), filepath.Join(*pinnedFixtures, "external-io-server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"localhost", "wrong.example"} {
		t.Run(name, func(t *testing.T) { sanSession(t, binary, *peerProtocol, name, "", certificate, name == "localhost") })
	}
	if *privateNative != "" {
		return
	}
	f := makePeerFixtures(t)
	for _, name := range []string{"127.0.0.1", "::1", "127.0.0.2", "::2"} {
		t.Run(name, func(t *testing.T) {
			sanSession(t, binary, *peerProtocol, name, f.root.certPath, f.identities["server-ip"].tls, name == "127.0.0.1" || name == "::1")
		})
	}
	t.Run("dns_ip_spoof", func(t *testing.T) {
		sanSession(t, binary, *peerProtocol, "127.0.0.1", f.root.certPath, f.identities["server-ip-dns"].tls, false)
	})
	t.Run("intermediate_system_store", func(t *testing.T) {
		sanSession(t, binary, *peerProtocol, "localhost", f.root.certPath, f.identities["server-chain"].tls, true)
	})
}

type nativePeer struct {
	cmd             *exec.Cmd
	done            chan error
	out, diagnostic bytes.Buffer
	port            string
	waited          bool
}

func startNativePeer(t *testing.T, binary string, args []string, env []string) *nativePeer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	p := &nativePeer{cmd: exec.CommandContext(ctx, binary, args...), done: make(chan error, 1), port: args[1]}
	p.cmd.Stdout = &p.out
	p.cmd.Stderr = &p.diagnostic
	if env != nil {
		p.cmd.Env = env
	}
	if err := p.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	t.Cleanup(func() {
		cancel()
		if !p.waited {
			p.cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}
func (p *nativePeer) marker(t *testing.T, suffix string) string {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(p.port + suffix)
		if err == nil && (suffix != "" || bytes.HasSuffix(data, []byte{'\n'})) {
			return strings.TrimSpace(string(data))
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case err := <-p.done:
			p.waited = true
			t.Fatalf("native exited before marker %s: %v\n%s", suffix, err, safePeerDiagnostic(p.diagnostic.String()))
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("native marker %s timed out", suffix)
	return ""
}
func (p *nativePeer) wait(t *testing.T, proto, outcome string) {
	t.Helper()
	err := <-p.done
	p.waited = true
	if err != nil {
		t.Fatalf("native TLS%s/%s: %v\n%s", proto, outcome, err, safePeerDiagnostic(p.diagnostic.String()))
	}
	if !strings.Contains(p.out.String(), fmt.Sprintf("PASS production NativeIO CNet server / TLS%s / %s", proto, outcome)) {
		t.Fatal("native assertions not reached")
	}
}

// Intercept only the test peer's wire. TLS keys and record protection remain
// entirely inside Go's TLS implementation.
type peerWire struct {
	net.Conn
	hold            bool
	pending, inject []byte
	mutation        string
	mutations       int
}

func (w *peerWire) Read(b []byte) (int, error) {
	if len(w.inject) != 0 {
		n := copy(b, w.inject)
		w.inject = w.inject[n:]
		return n, nil
	}
	return w.Conn.Read(b)
}
func (w *peerWire) Write(b []byte) (int, error) {
	if w.hold {
		for at := 0; at+5 <= len(b); {
			if b[at] == 23 {
				w.pending = append(w.pending, b...)
				return len(b), nil
			}
			at += 5 + (int(b[at+3]) << 8) + int(b[at+4])
		}
		if len(w.pending) != 0 {
			w.pending = append(w.pending, b...)
			return len(b), nil
		}
	}
	if w.mutation != "" {
		copy := bytes.Clone(b)
		if len(copy) > 5 {
			w.mutations++
			if w.mutation == "truncated" {
				copy = copy[:len(copy)-1]
			} else {
				copy[len(copy)-1] ^= 1
			}
			if err := writePeerBytes(w.Conn, copy); err != nil {
				return 0, err
			}
			return len(b), nil
		}
	}
	return w.Conn.Write(b)
}
func writePeerBytes(w io.Writer, b []byte) error {
	for len(b) != 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (w *peerWire) flush(fragmented bool) error {
	w.hold = false
	data := w.pending
	w.pending = nil
	if !fragmented {
		return writePeerBytes(w.Conn, data)
	}
	for _, size := range []int{1, 2, 7, 31, 127} {
		if len(data) == 0 {
			break
		}
		if size > len(data) {
			size = len(data)
		}
		if err := writePeerBytes(w.Conn, data[:size]); err != nil {
			return err
		}
		data = data[size:]
		time.Sleep(time.Millisecond)
	}
	return writePeerBytes(w.Conn, data)
}
func clientScenario(t *testing.T, f peerFixtures, proto, name, mode string) {
	t.Helper()
	outcome := "accept"
	if name != "client" {
		outcome = "reject"
	}
	switch mode {
	case "idle", "gated", "close", "localclose", "sendclose", "race-eof", "race-eof-pending", "eof", "truncated", "badalert", "fatal":
		outcome = mode
	}
	server := f.identities["server"]
	digest := "-"
	if name == "client" {
		digest = fmt.Sprintf("%x", sha256.Sum256(f.identities["client"].cert.Raw))
	}
	portFile := filepath.Join(t.TempDir(), "native.port")
	p := startNativePeer(t, *native, []string{"--go-tls-client", portFile, f.root.certPath, server.certPath, server.keyPath, proto, outcome, digest}, nil)
	port := p.marker(t, "")
	raw, err := net.DialTimeout("tcp4", "127.0.0.1:"+port, 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(9 * time.Second))
	wire := &peerWire{Conn: raw, hold: mode == "fragmented" || mode == "coalesced"}
	config := peerConfig(peerVersion(proto))
	config.ServerName = "localhost"
	config.RootCAs = x509.NewCertPool()
	config.RootCAs.AddCert(f.root.cert)
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if name == "missing" {
			return &tls.Certificate{}, nil
		}
		id := f.identities[name]
		return &id.tls, nil
	}
	peer := tls.Client(wire, config)
	err = peer.Handshake()
	if outcome == "reject" {
		if err == nil {
			_, err = peer.Write([]byte{'F'})
			if err == nil {
				var b [1]byte
				_, err = peer.Read(b[:])
				if err == nil && b[0] == 'G' {
					t.Fatal("invalid identity admitted")
				}
			}
		}
		raw.Close()
		p.wait(t, proto, outcome)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if peer.ConnectionState().Version != peerVersion(proto) || len(peer.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("unverified/version mismatch")
	}
	if mode == "idle" {
		var b [1]byte
		if n, _ := peer.Read(b[:]); n != 0 {
			t.Fatal("idle application data")
		}
		raw.Close()
		p.wait(t, proto, outcome)
		return
	}
	if mode == "gated" {
		p.marker(t, ".ready")
	}
	if _, err = peer.Write([]byte{'F'}); err != nil {
		t.Fatal(err)
	}
	if wire.hold {
		if len(wire.pending) == 0 {
			t.Fatal("Finished and application were not coalesced")
		}
		if err = wire.flush(mode == "fragmented"); err != nil {
			t.Fatal(err)
		}
	}
	var b [1]byte
	if _, err = io.ReadFull(peer, b[:]); err != nil || b[0] != 'G' {
		t.Fatalf("authenticated response: %v", err)
	}
	switch mode {
	case "close", "localclose", "sendclose":
		if mode == "localclose" {
			p.marker(t, ".localclose")
		}
		if err = peer.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err = peer.Read(b[:]); err != io.EOF {
			t.Fatalf("reciprocal close_notify: %v", err)
		}
	case "race-eof", "race-eof-pending", "eof", "truncated", "badalert", "fatal":
		if mode != "race-eof" && mode != "race-eof-pending" {
			p.marker(t, ".sent")
		}
		if mode == "truncated" || mode == "badalert" {
			wire.mutation = mode
			if err = peer.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if wire.mutations != 1 {
				t.Fatal("close_notify mutation not executed")
			}
		}
		if mode == "fatal" {
			wire.inject = append([]byte{23, 3, 3, 0, 32}, make([]byte, 32)...)
			if _, err = peer.Read(b[:]); err == nil {
				t.Fatal("forged record accepted")
			}
		}
		if err = raw.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, raw)
	default:
		if mode != "gated" {
			p.marker(t, ".sent")
		}
	}
	raw.Close()
	p.wait(t, proto, outcome)
}
func TestGoClientRequiredMTLS(t *testing.T) {
	f := makePeerFixtures(t)
	for _, proto := range []string{"12", "13"} {
		for _, mode := range []string{"race-eof", "race-eof-pending", "eof", "truncated", "badalert", "fatal", "close", "localclose", "sendclose"} {
			t.Run(proto+"/"+mode, func(t *testing.T) { clientScenario(t, f, proto, "client", mode) })
		}
		for _, name := range []string{"client", "missing", "wrongca", "eku", "expired", "chain", "badsig"} {
			t.Run(proto+"/"+name, func(t *testing.T) { clientScenario(t, f, proto, name, "") })
		}
	}
	for _, mode := range []string{"gated", "coalesced", "fragmented", "idle"} {
		t.Run("13/"+mode, func(t *testing.T) { clientScenario(t, f, "13", "client", mode) })
	}
}
