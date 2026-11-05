package shangmiinterop

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	peerx509 "github.com/iuboy/pollux-go/smx509"
	"github.com/iuboy/pollux-go/tls13gm"
)

var native = flag.String("native", "", "production CNet formal peer")

type fixture struct {
	root, leaf                *x509.Certificate
	key                       *sm2.PrivateKey
	rootKey                   *sm2.PrivateKey
	caPath, certPath, keyPath string
}

func credentials(t *testing.T, change func(*x509.Certificate)) fixture {
	t.Helper()
	dir := t.TempDir()
	rootKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: fmt.Sprintf("ShangMi test CA %x", rootKey.PublicKey.X.Bytes()[:8])}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := peerx509.CreateCertificate(root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if change != nil {
		change(leaf)
	}
	leafDER, err := peerx509.CreateCertificate(leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedRoot, err := peerx509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	parsedLeaf, err := peerx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{root: parsedRoot, leaf: parsedLeaf, key: key, rootKey: rootKey,
		caPath: filepath.Join(dir, "ca.pem"), certPath: filepath.Join(dir, "leaf.pem"), keyPath: filepath.Join(dir, "key.pem")}
	keyDER, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for path, block := range map[string]*pem.Block{f.caPath: {Type: "CERTIFICATE", Bytes: rootDER}, f.certPath: {Type: "CERTIFICATE", Bytes: leafDER}, f.keyPath: {Type: "PRIVATE KEY", Bytes: keyDER}} {
		if err = os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func runNativeClient(t *testing.T, f fixture, identity string, accept bool, corrupt string) {
	runNativeClientWithIdentity(t, f, nil, identity, accept, corrupt)
}

func runNativeClientWithIdentity(t *testing.T, f fixture, client *fixture, identity string, accept bool, corrupt string) {
	runNativeClientIdentities(t, f, client, client, identity, accept, corrupt)
}

func runNativeClientIdentities(t *testing.T, f fixture, offered, expected *fixture, identity string, accept bool, corrupt string) {
	t.Helper()
	client := expected
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(20 * time.Second))
	finished := make(chan error, 1)
	go func() {
		var result error
		defer func() { finished <- result }()
		raw, err := listener.Accept()
		if err != nil {
			result = err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
		p := &recordPeer{Conn: raw}
		defer p.clearSecrets()
		handshakeScenario := corrupt
		keyUpdate := strings.HasPrefix(corrupt, "key_update")
		if keyUpdate || strings.HasPrefix(corrupt, "rotate") || strings.HasPrefix(corrupt, "limit") {
			handshakeScenario = ""
		}
		if client == nil {
			result = p.server(tls13gm.ServerConfig{DCID: []byte("formal TCP peer"), Certificate: f.leaf, PrivateKey: f.key}, handshakeScenario)
		} else {
			result = p.mutualServer(f, *client, handshakeScenario)
			if !accept && !p.authFlightSent {
				result = fmt.Errorf("server authentication flight did not execute: %w", result)
				return
			}
		}
		if !accept {
			// CNet's IP-SAN check can reject after provider Finished, before
			// publishing CONNECTED. No application bytes may escape that gate.
			if result == nil {
				kind, data, readErr := p.record()
				if readErr == nil && kind == 23 && len(data) != 0 {
					result = errors.New("rejected peer received application data")
					return
				}
				result = readErr
			}
			var timeout net.Error
			if errors.As(result, &timeout) && timeout.Timeout() {
				return
			}
			result = nil
			return
		}
		if strings.HasPrefix(corrupt, "limit") {
			if result == nil {
				result = p.peerUpdateLimit(false, corrupt, nil)
			}
			return
		}
		if strings.HasPrefix(corrupt, "rotate") {
			if result == nil {
				result = p.localRotation(false, localRotationLimit(corrupt))
			}
			return
		}
		if result == nil {
			result = p.expect(23, []byte{'F'})
		}
		if result == nil && keyUpdate {
			request := byte(1)
			if corrupt == "key_update_one_way" {
				request = 0
			}
			result = p.sendKeyUpdate(request)
			if result == nil && corrupt == "key_update_coalesced" {
				result = p.sendKeyUpdate(request)
			}
		}
		if result == nil {
			result = p.send(23, []byte("ok"))
		}
		if result == nil && keyUpdate {
			if corrupt != "key_update_one_way" {
				result = p.receiveKeyUpdate()
			}
			if result == nil {
				result = p.expect(23, []byte{'F'})
			}
			if result == nil {
				result = p.send(23, []byte("ok"))
			}
		}
		if result == nil {
			result = p.expect(21, []byte{1, 0})
		}
		if result == nil {
			result = p.send(21, []byte{1, 0})
		}
	}()
	expect := "reject"
	if accept {
		expect = "accept"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
	protocol := "shangmi13"
	if strings.HasPrefix(corrupt, "key_update") {
		protocol = "shangmi13-update"
	}
	if strings.HasPrefix(corrupt, "rotate") {
		protocol = "shangmi13-" + corrupt
	}
	if strings.HasPrefix(corrupt, "limit") {
		protocol = "shangmi13-" + corrupt
	}
	args := []string{"--external-ip-san", port, protocol, identity, f.caPath, expect}
	if client != nil {
		args = []string{"--shangmi-required-server", port, identity, f.caPath, offered.certPath, offered.keyPath, expect,
			fmt.Sprintf("%x", sha256.Sum256(f.leaf.Raw))}
	}
	out, runErr := exec.CommandContext(ctx, *native, args...).CombinedOutput()
	listener.Close()
	peerErr := <-finished
	if runErr != nil || peerErr != nil {
		t.Fatalf("native client: %v; independent peer: %v\n%s", runErr, peerErr, out)
	}
}

func runNativeServer(t *testing.T, f fixture, outcome string, corrupt ...string) {
	runNativeServerWithClient(t, f, nil, outcome, corrupt...)
}

func runNativeServerWithClient(t *testing.T, f fixture, client *fixture, outcome string, corrupt ...string) {
	runNativeServerIdentities(t, f, client, nil, outcome, corrupt...)
}

// f is the independently trusted identity; primary, when set, precedes it.
func runNativeServerIdentities(t *testing.T, f fixture, client, primary *fixture, outcome string, corrupt ...string) {
	t.Helper()
	portPath := filepath.Join(t.TempDir(), "port")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	args := []string{"--shangmi-client", portPath, f.certPath, f.keyPath, outcome}
	if client != nil {
		args = []string{"--shangmi-required-client", portPath, client.caPath, f.certPath, f.keyPath, outcome,
			fmt.Sprintf("%x", sha256.Sum256(client.leaf.Raw))}
	}
	command := exec.CommandContext(ctx, *native, args...)
	if primary != nil {
		certIndex := 3
		if client != nil {
			certIndex = 4
		}
		command.Args[certIndex], command.Args[certIndex+1] = primary.certPath, primary.keyPath
		command.Env = append(os.Environ(), "SALTS_TEST_TLS_ALT_CERT="+f.certPath, "SALTS_TEST_TLS_ALT_KEY="+f.keyPath)
	}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
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
		port, _ = os.ReadFile(portPath)
		if len(bytes.TrimSpace(port)) != 0 {
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
	roots := peerx509.NewCertPool()
	roots.AddCert(f.root)
	p := &recordPeer{Conn: raw}
	defer p.clearSecrets()
	scenario := ""
	if len(corrupt) != 0 {
		scenario = corrupt[0]
	}
	handshakeScenario := scenario
	keyUpdateFailure := strings.HasPrefix(scenario, "key_update_bad")
	if strings.HasPrefix(scenario, "key_update") || strings.HasPrefix(scenario, "rotate") || strings.HasPrefix(scenario, "limit") {
		handshakeScenario = ""
	}
	if client == nil {
		err = p.client(tls13gm.ClientConfig{DCID: []byte("formal TCP peer"), Roots: roots, ServerName: "localhost"}, handshakeScenario)
	} else {
		err = p.mutualClient(f, *client, handshakeScenario)
	}
	if strings.HasPrefix(scenario, "limit") {
		if err == nil {
			err = p.peerUpdateLimit(true, scenario, func() error {
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					if _, ready := os.Stat(portPath + ".sent"); ready == nil {
						return nil
					}
					time.Sleep(5 * time.Millisecond)
				}
				return errors.New("native SEND marker timed out")
			})
		}
		if err != nil {
			raw.Close()
			cancel()
		}
		runErr := <-done
		waited = true
		if runErr != nil || err != nil {
			t.Fatalf("native peer update limit: %v; peer: %v\n%s", runErr, err, output.String())
		}
		return
	}
	if strings.HasPrefix(scenario, "rotate") {
		if err == nil {
			err = p.localRotation(true, localRotationLimit(scenario))
		}
		if err != nil {
			raw.Close()
			cancel()
		}
		runErr := <-done
		waited = true
		if runErr != nil || err != nil {
			t.Fatalf("native local rotation: %v; peer: %v\n%s", runErr, err, output.String())
		}
		return
	}
	if outcome == "reject" {
		if (client == nil && !p.altered) || (client != nil && !p.authFlightSent) {
			t.Fatalf("negative client flight did not execute: %v", err)
		}
		if err == nil {
			kind, data, readErr := p.record()
			if readErr == nil && kind != 21 {
				t.Fatalf("rejected client received type=%d data=%x", kind, data)
			}
			err = readErr
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("rejection timed out: %v", err)
		}
		raw.Close()
		runErr := <-done
		waited = true
		if runErr != nil {
			t.Fatalf("native rejection: %v\n%s", runErr, output.String())
		}
		return
	}
	if err == nil && strings.HasPrefix(scenario, "key_update") && !keyUpdateFailure {
		request := byte(1)
		if scenario == "key_update_one_way" {
			request = 0
		}
		err = p.sendKeyUpdate(request)
		if err == nil && scenario == "key_update_coalesced" {
			err = p.sendKeyUpdate(request)
		}
	}
	if err == nil {
		err = p.send(23, []byte{'F'})
	}
	if err == nil && strings.HasPrefix(scenario, "key_update") && scenario != "key_update_one_way" && !keyUpdateFailure {
		err = p.receiveKeyUpdate()
	}
	if err == nil {
		err = p.expect(23, []byte{'G'})
	}
	if err == nil && outcome == "close" {
		err = p.send(21, []byte{1, 0})
	}
	if err == nil && outcome == "close" {
		err = p.expect(21, []byte{1, 0})
	}
	if outcome == "eof" || keyUpdateFailure {
		// Ciphertext receipt does not prove the native SEND callback ran.
		// Let the formal native peer publish completion before injecting EOF.
		deadline := time.Now().Add(5 * time.Second)
		for err == nil {
			if _, readyErr := os.Stat(portPath + ".sent"); readyErr == nil {
				break
			}
			if time.Now().After(deadline) {
				err = errors.New("native SEND marker timed out")
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if outcome == "eof" {
			raw.Close()
		}
	}
	if err == nil && keyUpdateFailure {
		switch scenario {
		case "key_update_bad_value":
			err = p.send(22, []byte{24, 0, 0, 1, 2})
		case "key_update_bad_length":
			err = p.send(22, []byte{24, 0, 0, 0})
		case "key_update_bad_stale_key":
			oldCipher, oldSeq := p.writeCipher, p.writeSeq
			err = p.sendKeyUpdate(0)
			p.writeCipher, p.writeSeq = oldCipher, oldSeq+1
			if err == nil {
				err = p.send(23, []byte{'X'})
			}
		}
		if err == nil {
			kind, _, readErr := p.record()
			var timeout net.Error
			if errors.As(readErr, &timeout) && timeout.Timeout() {
				err = readErr
			} else if readErr == nil && kind != 21 {
				err = errors.New("invalid KeyUpdate did not terminate the stream")
			}
		}
	}
	if err != nil {
		raw.Close()
		cancel()
	}
	runErr := <-done
	waited = true
	if runErr != nil || err != nil {
		t.Fatalf("native server: %v; independent peer: %v\n%s", runErr, err, output.String())
	}
}

func TestShangMi(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	f := credentials(t, nil)
	t.Run("sni_identity_set", func(t *testing.T) {
		first := credentials(t, func(cert *x509.Certificate) { cert.DNSNames = []string{"first.test"} })
		client := clientCredentials(t, nil)
		memoryFixtures(t, client.caPath)
		for _, identity := range []fixture{first, f} {
			memoryFixtures(t, identity.certPath, identity.keyPath)
			encryptedMemoryFixture(t, identity.keyPath)
		}
		for _, mode := range []string{"file", "pem", "der", "encrypted_pem", "encrypted_der"} {
			t.Run(mode, func(t *testing.T) {
				if mode != "file" {
					t.Setenv("SALTS_TEST_TLS_MEMORY", strings.TrimPrefix(mode, "encrypted_"))
				}
				if strings.HasPrefix(mode, "encrypted_") {
					t.Setenv("SALTS_TEST_TLS_ENCRYPTED", "1")
				}
				runNativeServerIdentities(t, f, &client, &first, "close", "sni")
			})
		}
	})
	t.Run("native_client", func(t *testing.T) { runNativeClient(t, f, "localhost", true, "") })
	t.Run("native_client_ip", func(t *testing.T) { runNativeClient(t, f, "127.0.0.1", true, "") })
	t.Run("native_server", func(t *testing.T) { runNativeServer(t, f, "close") })
	t.Run("native_server_reject_raw_eof", func(t *testing.T) { runNativeServer(t, f, "eof") })
	t.Run("fragmented_server_handshake", func(t *testing.T) { runNativeClient(t, f, "localhost", true, "fragmented") })
	for _, identity := range []string{"wrong.example", "127.0.0.2"} {
		t.Run("reject_identity_"+identity, func(t *testing.T) { runNativeClient(t, f, identity, false, "") })
	}
	t.Run("reject_unknown_ca", func(t *testing.T) {
		bad := f
		bad.caPath = credentials(t, nil).caPath
		runNativeClient(t, bad, "localhost", false, "")
	})
	for name, change := range map[string]func(*x509.Certificate){
		"expired": func(cert *x509.Certificate) {
			cert.NotBefore = time.Now().Add(-48 * time.Hour)
			cert.NotAfter = time.Now().Add(-24 * time.Hour)
		},
		"future":             func(cert *x509.Certificate) { cert.NotBefore = time.Now().Add(time.Hour) },
		"key_usage":          func(cert *x509.Certificate) { cert.KeyUsage = x509.KeyUsageKeyEncipherment },
		"extended_key_usage": func(cert *x509.Certificate) { cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
	} {
		t.Run("reject_"+name, func(t *testing.T) { runNativeClient(t, credentials(t, change), "localhost", false, "") })
	}
	t.Run("reject_certificate_signature", func(t *testing.T) {
		bad := credentials(t, nil)
		bad.leaf.Raw[len(bad.leaf.Raw)-1] ^= 1
		runNativeClient(t, bad, "localhost", false, "")
	})
	for _, corrupt := range []string{"certificate_verify", "finished"} {
		t.Run("reject_"+corrupt, func(t *testing.T) { runNativeClient(t, f, "localhost", false, corrupt) })
	}
	for _, corrupt := range []string{"standard_cipher", "tls12_version", "tlcp_signature", "p256_group", "invalid_point", "finished"} {
		t.Run("server_reject_"+corrupt, func(t *testing.T) { runNativeServer(t, f, "reject", corrupt) })
	}
}
