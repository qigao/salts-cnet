package tlcpinterop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/pkcs8"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var native = flag.String("native", "", "production CNet formal peer")

// Inspect the actual ClientHello without replacing either protocol engine.
// The signature extension is TLCP's hash/signature pair, not RFC 8998's ID.
func signatureExtension(record []byte) ([]byte, error) {
	if len(record) < 43 || record[0] != 22 || binary.BigEndian.Uint16(record[1:3]) != tlcp.VersionTLCP ||
		int(binary.BigEndian.Uint16(record[3:5])) != len(record)-5 || record[5] != 1 ||
		(int(record[6])<<16|int(record[7])<<8|int(record[8])) != len(record)-9 {
		return nil, errors.New("expected a complete TLCP ClientHello record")
	}
	data := record[43:]
	vector := func(width int) ([]byte, error) {
		if len(data) < width {
			return nil, io.ErrUnexpectedEOF
		}
		n := int(data[0])
		if width == 2 {
			n = int(binary.BigEndian.Uint16(data))
		}
		data = data[width:]
		if n > len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		value := data[:n]
		data = data[n:]
		return value, nil
	}
	for _, width := range []int{1, 2, 1} {
		if _, err := vector(width); err != nil {
			return nil, err
		}
	}
	extensions, err := vector(2)
	if err != nil || len(data) != 0 {
		return nil, errors.New("invalid ClientHello extensions")
	}
	data = extensions
	var signature []byte
	for len(data) != 0 {
		if len(data) < 2 {
			return nil, io.ErrUnexpectedEOF
		}
		kind := binary.BigEndian.Uint16(data)
		data = data[2:]
		value, err := vector(2)
		if err != nil {
			return nil, err
		}
		if kind == 13 {
			if signature != nil {
				return nil, errors.New("duplicate signature extension")
			}
			signature = value
		}
	}
	if !bytes.Equal(signature, []byte{0, 2, 7, 4}) {
		return nil, fmt.Errorf("unexpected TLCP signature extension: %x", signature)
	}
	return signature, nil
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type alteredHelloConn struct {
	net.Conn
	value   []byte
	changed bool
}

func (c *alteredHelloConn) Write(p []byte) (int, error) {
	if !c.changed {
		p = bytes.Clone(p)
		ext, err := signatureExtension(p)
		if err != nil {
			return 0, err
		}
		if len(c.value) != len(ext) {
			return 0, errors.New("invalid test signature extension size")
		}
		copy(ext, c.value)
		c.changed = true
	}
	return c.Conn.Write(p)
}

type fixture struct {
	root                      *smx509.Certificate
	rootKey                   *sm2.PrivateKey
	certificates              []tlcp.Certificate
	caPath, certPath, keyPath string
}

func credentials(t *testing.T, change func(int, *x509.Certificate)) fixture {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()
	keys := make([]*sm2.PrivateKey, 3)
	certs := make([][]byte, 3)
	for i := range keys {
		var err error
		keys[i], err = sm2.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TLCP test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	var err error
	certs[0], err = smx509.CreateCertificate(rand.Reader, root, root, &keys[0].PublicKey, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if i == 2 {
			cert.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
		}
		if change != nil {
			change(i, cert)
		}
		certs[i], err = smx509.CreateCertificate(rand.Reader, cert, root, &keys[i].PublicKey, keys[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	f := fixture{rootKey: keys[0], caPath: filepath.Join(dir, "ca.pem"), certPath: filepath.Join(dir, "dual.pem"), keyPath: filepath.Join(dir, "keys.pem")}
	f.root, err = smx509.ParseCertificate(certs[0])
	if err != nil {
		t.Fatal(err)
	}
	var certPEM, keyPEM []byte
	for i := 1; i <= 2; i++ {
		f.certificates = append(f.certificates, tlcp.Certificate{Certificate: [][]byte{certs[i]}, PrivateKey: keys[i]})
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[i]})...)
		der, err := smx509.MarshalPKCS8PrivateKey(keys[i])
		if err != nil {
			t.Fatal(err)
		}
		keyPEM = append(keyPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
	}
	for path, data := range map[string][]byte{f.caPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0]}), f.certPath: certPEM, f.keyPath: keyPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}
func verifiedConfig(f fixture) *tlcp.Config {
	roots := smx509.NewCertPool()
	roots.AddCert(f.root)
	return &tlcp.Config{MinVersion: tlcp.VersionTLCP, MaxVersion: tlcp.VersionTLCP, RootCAs: roots, ServerName: "localhost", CipherSuites: []uint16{tlcp.ECC_SM4_GCM_SM3}}
}
func checkNegotiation(c *tlcp.Conn, client bool) error {
	state := c.ConnectionState()
	if !state.HandshakeComplete || state.Version != tlcp.VersionTLCP || state.CipherSuite != tlcp.ECC_SM4_GCM_SM3 || state.DidResume {
		return fmt.Errorf("unexpected TLCP state: complete=%v version=%x cipher=%x resume=%v", state.HandshakeComplete, state.Version, state.CipherSuite, state.DidResume)
	}
	if client && (len(state.PeerCertificates) != 2 || len(state.VerifiedChains) == 0) {
		return errors.New("missing verified dual certificate chain")
	}
	return nil
}
func runNativeClient(t *testing.T, f fixture, identity string, accept bool, suites []uint16, policy ...string) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(20 * time.Second))
	finished := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
		var header [5]byte
		if _, err = io.ReadFull(raw, header[:]); err != nil {
			finished <- err
			return
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if length > 16384 {
			finished <- errors.New("oversized ClientHello")
			return
		}
		record := make([]byte, 5+length)
		copy(record, header[:])
		if _, err = io.ReadFull(raw, record[5:]); err != nil {
			finished <- err
			return
		}
		if _, err = signatureExtension(record); err != nil {
			finished <- err
			return
		}
		transport := &replayConn{raw, io.MultiReader(bytes.NewReader(record), raw)}
		peer := tlcp.Server(transport, &tlcp.Config{MinVersion: tlcp.VersionTLCP, MaxVersion: tlcp.VersionTLCP, Certificates: f.certificates, CipherSuites: suites})
		err = peer.Handshake()
		if err == nil {
			err = checkNegotiation(peer, false)
		}
		var request [1]byte
		if err == nil {
			_, err = io.ReadFull(peer, request[:])
			if err == nil && request[0] != 'F' {
				err = errors.New("incorrect native request")
			}
		}
		if !accept {
			if err == nil {
				finished <- errors.New("rejected case released application data")
			} else {
				var timeout net.Error
				if len(policy) != 0 && errors.As(err, &timeout) && timeout.Timeout() {
					finished <- fmt.Errorf("policy rejection timed out: %w", err)
					return
				}
				finished <- nil
			}
			return
		}
		if err == nil {
			_, err = peer.Write([]byte("ok"))
		}
		if err == nil {
			n, e := peer.Read(request[:])
			if n != 0 || e != io.EOF {
				err = fmt.Errorf("native close_notify: n=%d err=%v", n, e)
			}
		}
		if err == nil {
			err = peer.CloseWrite()
		}
		finished <- err
	}()
	expectation := "reject"
	if accept {
		expectation = "accept"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
	args := []string{"--external-ip-san", port, "tlcp", identity, f.caPath, expectation}
	if len(policy) != 0 {
		if len(policy) != 3 {
			t.Fatal("expected issuer, CRL, policy mode")
		}
		args = []string{"--tlcp-crl-policy", port, identity, f.caPath, policy[0], policy[1], expectation, policy[2]}
	}
	command := exec.CommandContext(ctx, *native, args...)
	output, runErr := command.CombinedOutput()
	listener.Close()
	peerErr := <-finished
	if runErr != nil {
		t.Fatalf("native client: %v\n%s\npeer: %v", runErr, output, peerErr)
	}
	if peerErr != nil {
		t.Fatal(peerErr)
	}
}
func runNativeServer(t *testing.T, f fixture, clientConfig *tlcp.Config, outcome string, signature ...byte) {
	runNativeServerIdentities(t, f, nil, clientConfig, outcome, signature...)
}

func runNativeServerIdentities(t *testing.T, f fixture, primary *fixture, clientConfig *tlcp.Config, outcome string, signature ...byte) {
	t.Helper()
	portPath := filepath.Join(t.TempDir(), "port")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, *native, "--gotlcp-client", portPath, f.certPath, f.keyPath, outcome)
	if primary != nil {
		command.Args[3], command.Args[4] = primary.certPath, primary.keyPath
		command.Env = append(os.Environ(), "SALTS_TEST_TLS_ALT_CERT="+f.certPath, "SALTS_TEST_TLS_ALT_KEY="+f.keyPath)
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	waited := false
	defer func() {
		if !waited {
			cancel()
			<-done
		}
	}()
	var port []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		port, err = os.ReadFile(portPath)
		if err == nil && len(bytes.TrimSpace(port)) > 0 {
			break
		}
		select {
		case err := <-done:
			waited = true
			t.Fatalf("native server start: %v\n%s", err, output.String())
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(port) == 0 {
		t.Fatal("native listener did not become ready")
	}
	raw, err := net.DialTimeout("tcp4", "127.0.0.1:"+string(bytes.TrimSpace(port)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	transport := raw
	var altered *alteredHelloConn
	if signature != nil {
		altered = &alteredHelloConn{Conn: raw, value: signature}
		transport = altered
	}
	peer := tlcp.Client(transport, clientConfig)
	err = peer.Handshake()
	if altered != nil && !altered.changed {
		t.Fatalf("ClientHello was not altered: %v", err)
	}
	if outcome == "reject" {
		if err == nil {
			t.Fatal("negative peer unexpectedly completed handshake")
		}
		raw.Close()
	} else {
		if err == nil {
			err = checkNegotiation(peer, true)
		}
		if err == nil {
			_, err = peer.Write([]byte{'F'})
		}
		var reply [1]byte
		if err == nil {
			_, err = io.ReadFull(peer, reply[:])
			if err == nil && reply[0] != 'G' {
				err = errors.New("incorrect native response")
			}
		}
		if err == nil {
			err = peer.CloseWrite()
		}
		if err == nil {
			n, e := peer.Read(reply[:])
			if n != 0 || e != io.EOF {
				err = fmt.Errorf("server close_notify: n=%d err=%v", n, e)
			}
		}
		if err != nil {
			raw.Close()
			cancel()
			runErr := <-done
			waited = true
			t.Fatalf("GoTLCP client: %v; native: %v\n%s", err, runErr, output.String())
		}
	}
	runErr := <-done
	waited = true
	if runErr != nil {
		t.Fatalf("native server: %v\n%s", runErr, output.String())
	}
}
func TestTLCP(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	f := credentials(t, nil)
	t.Run("sni_identity_set", func(t *testing.T) {
		first := credentials(t, func(_ int, cert *x509.Certificate) { cert.DNSNames = []string{"first.test"} })
		for _, identity := range []fixture{first, f} {
			memoryFixtures(t, identity.certPath)
			bundle, err := os.ReadFile(identity.keyPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range []string{".sign", ".enc"} {
				block, rest := pem.Decode(bundle)
				if block == nil {
					t.Fatal("missing dual key")
				}
				if err := os.WriteFile(identity.keyPath+part, pem.EncodeToMemory(block), 0600); err != nil {
					t.Fatal(err)
				}
				memoryFixtures(t, identity.keyPath+part)
				bundle = rest
			}
		}
		for _, mode := range []string{"file", "pem", "der"} {
			t.Run(mode, func(t *testing.T) {
				if mode != "file" {
					t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
				}
				// Trust only the second identity's CA; both signing and encryption
				// keys must be selected together for authenticated application IO.
				runNativeServerIdentities(t, f, &first, verifiedConfig(f), "close")
			})
		}
	})
	memoryFixtures(t, f.caPath, f.certPath)
	bundle, err := os.ReadFile(f.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{".sign", ".enc"} {
		block, rest := pem.Decode(bundle)
		if block == nil {
			t.Fatal("missing dual key")
		}
		if err := os.WriteFile(f.keyPath+part, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
		memoryFixtures(t, f.keyPath+part)
		password := "memory\x00sign"
		if part == ".enc" {
			password = "memory\x00encryption"
		}
		key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		der, err := pkcs8.MarshalPrivateKey(key, []byte(password),
			pkcs.NewPBESEncrypter(pkcs.SM4CBC, pkcs.NewPBKDF2Opts(pkcs.SM3, 16, 10000)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.keyPath+part+".encrypted.der", der, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.keyPath+part+".encrypted", pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		for _, bits := range []int{128, 192, 256} {
			suffix := ".aes"
			algorithm := pkcs.AES256CBC
			if bits == 128 {
				suffix = ".aes128"
				algorithm = pkcs.AES128CBC
			}
			if bits == 192 {
				suffix = ".aes192"
				algorithm = pkcs.AES192CBC
			}
			aesDER, err := pkcs8.MarshalPrivateKey(key, []byte(password),
				pkcs.NewPBESEncrypter(algorithm, pkcs.NewPBKDF2Opts(pkcs.SHA256, 16, 10000)))
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.keyPath+part+suffix+".der", aesDER, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(f.keyPath+part+suffix, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: aesDER}), 0600); err != nil {
				t.Fatal(err)
			}
		}
		bundle = rest
	}
	for _, mode := range []string{"pem", "der"} {
		t.Run("memory_"+mode, func(t *testing.T) {
			t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
			runNativeClient(t, f, "localhost", true, []uint16{tlcp.ECC_SM4_GCM_SM3})
			runNativeServer(t, f, verifiedConfig(f), "close")
		})
		for _, encryption := range []string{"aes128", "aes192", "aes"} {
			t.Run(encryption+"_encrypted_memory_"+mode, func(t *testing.T) {
				t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
				t.Setenv("SALTS_TEST_TLS_ENCRYPTED", encryption)
				runNativeServer(t, f, verifiedConfig(f), "close")
			})
		}
		t.Run("encrypted_memory_"+mode, func(t *testing.T) {
			t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
			t.Setenv("SALTS_TEST_TLS_ENCRYPTED", "1")
			runNativeServer(t, f, verifiedConfig(f), "close")
		})
	}
	t.Run("native_client", func(t *testing.T) { runNativeClient(t, f, "localhost", true, []uint16{tlcp.ECC_SM4_GCM_SM3}) })
	t.Run("native_client_ip", func(t *testing.T) { runNativeClient(t, f, "127.0.0.1", true, []uint16{tlcp.ECC_SM4_GCM_SM3}) })
	t.Run("native_server", func(t *testing.T) { runNativeServer(t, f, verifiedConfig(f), "close") })
	for _, identity := range []string{"wrong.example", "127.0.0.2"} {
		t.Run("reject_identity_"+identity, func(t *testing.T) {
			runNativeClient(t, f, identity, false, []uint16{tlcp.ECC_SM4_GCM_SM3})
		})
	}
	t.Run("reject_unknown_ca", func(t *testing.T) {
		untrusted := f
		untrusted.caPath = credentials(t, nil).caPath
		runNativeClient(t, untrusted, "localhost", false, []uint16{tlcp.ECC_SM4_GCM_SM3})
	})
	for _, role := range []int{1, 2} {
		t.Run(fmt.Sprintf("reject_future_role_%d", role), func(t *testing.T) {
			t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "future")
			bad := credentials(t, func(i int, cert *x509.Certificate) {
				if i == role {
					cert.NotBefore = time.Now().Add(time.Hour)
				}
			})
			runNativeClient(t, bad, "localhost", false, []uint16{tlcp.ECC_SM4_GCM_SM3})
		})
		t.Run(fmt.Sprintf("reject_signature_role_%d", role), func(t *testing.T) {
			bad := credentials(t, nil)
			der := bad.certificates[role-1].Certificate[0]
			der[len(der)-1] ^= 1
			runNativeClient(t, bad, "localhost", false, []uint16{tlcp.ECC_SM4_GCM_SM3})
		})
		t.Run(fmt.Sprintf("reject_expired_role_%d", role), func(t *testing.T) {
			t.Setenv("SALTS_TEST_TLS_VALIDITY_DIAGNOSTIC", "expired")
			bad := credentials(t, func(i int, cert *x509.Certificate) {
				if i == role {
					cert.NotBefore = time.Now().Add(-48 * time.Hour)
					cert.NotAfter = time.Now().Add(-24 * time.Hour)
				}
			})
			runNativeClient(t, bad, "localhost", false, []uint16{tlcp.ECC_SM4_GCM_SM3})
		})
		t.Run(fmt.Sprintf("reject_key_usage_role_%d", role), func(t *testing.T) {
			bad := credentials(t, func(i int, cert *x509.Certificate) {
				if i == role {
					cert.KeyUsage = x509.KeyUsageCertSign
				}
			})
			runNativeClient(t, bad, "localhost", false, []uint16{tlcp.ECC_SM4_GCM_SM3})
		})
	}
	t.Run("client_reject_cbc_only", func(t *testing.T) {
		runNativeClient(t, f, "localhost", false, []uint16{tlcp.ECC_SM4_CBC_SM3})
	})
	t.Run("server_reject_cbc_only", func(t *testing.T) {
		cfg := verifiedConfig(f)
		cfg.CipherSuites = []uint16{tlcp.ECC_SM4_CBC_SM3}
		runNativeServer(t, f, cfg, "reject")
	})
	for name, ext := range map[string][]byte{
		"tls13_sm2_scheme":           {0, 2, 7, 8},
		"unknown_scheme":             {0, 2, 0, 0},
		"odd_signature_vector":       {0, 1, 7, 4},
		"empty_signature_vector":     {0, 0, 7, 4},
		"truncated_signature_vector": {0, 4, 7, 4},
	} {
		t.Run("server_reject_"+name, func(t *testing.T) { runNativeServer(t, f, verifiedConfig(f), "reject", ext...) })
	}
}

func TestLocalDualIdentity(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	f := credentials(t, nil)
	readPair := func(path string) [2][]byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		first, rest := pem.Decode(data)
		second, rest := pem.Decode(rest)
		if first == nil || second == nil || len(rest) != 0 {
			t.Fatal("invalid dual fixture")
		}
		return [2][]byte{pem.EncodeToMemory(first), pem.EncodeToMemory(second)}
	}
	certs, keys := readPair(f.certPath), readPair(f.keyPath)
	otherKeys := readPair(credentials(t, nil).keyPath)
	for _, test := range []struct {
		name      string
		cert, key []byte
	}{
		{"missing_encryption_certificate", certs[0], bytes.Join(keys[:], nil)},
		{"reversed_certificates", bytes.Join([][]byte{certs[1], certs[0]}, nil), bytes.Join(keys[:], nil)},
		{"missing_encryption_key", bytes.Join(certs[:], nil), keys[0]},
		{"reversed_keys", bytes.Join(certs[:], nil), bytes.Join([][]byte{keys[1], keys[0]}, nil)},
		{"wrong_signing_key", bytes.Join(certs[:], nil), bytes.Join([][]byte{otherKeys[0], keys[1]}, nil)},
		{"wrong_encryption_key", bytes.Join(certs[:], nil), bytes.Join([][]byte{keys[0], otherKeys[1]}, nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			if err := os.WriteFile(certPath, test.cert, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, test.key, 0600); err != nil {
				t.Fatal(err)
			}
			// These cases reach the production memory importer with
			// complete, independently encoded inputs and must still reject.
			if test.name != "missing_encryption_key" {
				bundle := test.key
				for _, part := range []string{".sign", ".enc"} {
					block, rest := pem.Decode(bundle)
					if block == nil {
						t.Fatal("missing test key")
					}
					if err := os.WriteFile(keyPath+part, pem.EncodeToMemory(block), 0600); err != nil {
						t.Fatal(err)
					}
					memoryFixtures(t, keyPath+part)
					bundle = rest
				}
				memoryFixtures(t, certPath)
				for _, mode := range []string{"pem", "der"} {
					t.Run("memory_"+mode, func(t *testing.T) {
						t.Setenv("SALTS_TEST_TLS_MEMORY", mode)
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						if out, err := exec.CommandContext(ctx, *native, "--reject-tlcp-identity", certPath, keyPath).CombinedOutput(); err != nil {
							t.Fatalf("memory identity rejection: %v\n%s", err, out)
						}
					})
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, *native, "--reject-tlcp-identity", certPath, keyPath).CombinedOutput(); err != nil {
				t.Fatalf("local identity rejection: %v\n%s", err, out)
			}
		})
	}
}

// Write independent DER fixtures; the native adapter consumes and then erases
// memory inputs before handshake progress.
func memoryFixtures(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var der []byte
		for len(data) != 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				t.Fatal("invalid fixture PEM")
			}
			der = append(der, block.Bytes...)
			data = rest
		}
		if err := os.WriteFile(path+".der", der, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
