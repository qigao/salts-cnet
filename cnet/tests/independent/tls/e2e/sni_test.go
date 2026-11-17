package tls_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var retryRandom = []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}

type helloObserver struct {
	records, messages []byte
	hellos, retries   int
}

func (o *helloObserver) feed(b []byte) {
	o.records = append(o.records, b...)
	for len(o.records) >= 5 {
		size := int(binary.BigEndian.Uint16(o.records[3:5]))
		if len(o.records) < size+5 {
			return
		}
		if o.records[0] == 22 {
			o.messages = append(o.messages, o.records[5:5+size]...)
		}
		o.records = o.records[5+size:]
		for len(o.messages) >= 4 {
			size = int(o.messages[1])<<16 | int(o.messages[2])<<8 | int(o.messages[3])
			if len(o.messages) < size+4 {
				break
			}
			if o.messages[0] == 1 {
				o.hellos++
			}
			if o.messages[0] == 2 && size >= 34 && bytes.Equal(o.messages[6:38], retryRandom) {
				o.retries++
			}
			o.messages = o.messages[4+size:]
		}
	}
}

type sniWire struct {
	net.Conn
	first          bool
	sent, received helloObserver
}

func (w *sniWire) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	w.received.feed(b[:n])
	return n, err
}
func (w *sniWire) Write(b []byte) (int, error) {
	w.sent.feed(b)
	if !w.first {
		return w.Conn.Write(b)
	}
	w.first = false
	data := b
	for _, size := range []int{1, 2, 3, 5, 8, 13} {
		if size > len(data) {
			size = len(data)
		}
		if err := writePeerBytes(w.Conn, data[:size]); err != nil {
			return 0, err
		}
		data = data[size:]
		if len(data) == 0 {
			break
		}
	}
	if err := writePeerBytes(w.Conn, data); err != nil {
		return 0, err
	}
	return len(b), nil
}
func sniScenario(t *testing.T, f peerFixtures, identities map[string]peerIdentity, proto, mode, hostname, selected, primary string, defaultGroups bool) {
	t.Helper()
	root := f.root
	client := f.identities["client"]
	outcome := "accept"
	if selected == "" {
		outcome = "reject"
	}
	portFile := filepath.Join(t.TempDir(), "sni.port")
	var env []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "SALTS_TEST_TLS_MEMORY=") && !strings.HasPrefix(value, "SALTS_TEST_TLS_ENCRYPTED=") && !strings.HasPrefix(value, "SALTS_TEST_TLS_ALT_CERT=") && !strings.HasPrefix(value, "SALTS_TEST_TLS_ALT_KEY=") {
			env = append(env, value)
		}
	}
	env = append(env, "SALTS_TEST_TLS_ALT_CERT="+identities["second"].certPath, "SALTS_TEST_TLS_ALT_KEY="+identities["second"].keyPath)
	if mode != "file" {
		env = append(env, "SALTS_TEST_TLS_MEMORY="+mode)
	}
	id := identities[primary]
	p := startNativePeer(t, *native, []string{"--go-tls-client", portFile, root.certPath, id.certPath, id.keyPath, proto, outcome, fmt.Sprintf("%x", sha256.Sum256(client.cert.Raw))}, env)
	port := p.marker(t, "")
	raw, err := net.DialTimeout("tcp4", "127.0.0.1:"+port, 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(8 * time.Second))
	wire := &sniWire{Conn: raw, first: true}
	config := peerConfig(peerVersion(proto))
	if defaultGroups {
		config.CurvePreferences = nil
	}
	config.ServerName = hostname
	config.RootCAs = x509.NewCertPool()
	config.RootCAs.AddCert(root.cert)
	config.Certificates = []tls.Certificate{client.tls}
	if hostname == "" {
		config.InsecureSkipVerify = true
		config.VerifyConnection = func(state tls.ConnectionState) error {
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: config.RootCAs, Intermediates: intermediates})
			return err
		}
	}
	peer := tls.Client(wire, config)
	err = peer.Handshake()
	if selected == "" {
		if err == nil {
			t.Fatal("unmatched SNI authenticated")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(peer.ConnectionState().PeerCertificates[0].Raw, identities[selected].cert.Raw) {
			t.Fatal("wrong SNI identity")
		}
		if _, err = peer.Write([]byte{'F'}); err != nil {
			t.Fatal(err)
		}
		var b [1]byte
		if _, err = io.ReadFull(peer, b[:]); err != nil || b[0] != 'G' {
			t.Fatalf("application response: %v", err)
		}
		p.marker(t, ".sent")
		if wire.received.retries != 0 && (wire.received.retries != 1 || wire.sent.hellos != 2 || peer.ConnectionState().Version != tls.VersionTLS13) {
			t.Fatal("invalid HelloRetryRequest transcript")
		}
	}
	raw.Close()
	p.wait(t, proto, outcome)
}
func TestServerSNI(t *testing.T) {
	f := makePeerFixtures(t)
	identities := map[string]peerIdentity{}
	for _, name := range []string{"first", "second", "ecdsa"} {
		identities[name] = peerCert(t, "cn-only.test", peerKey(t, name == "ecdsa"), &f.root, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			if name == "first" {
				c.DNSNames = []string{"alpha.test"}
			} else if name == "second" {
				c.DNSNames = []string{"beta.test", "alias.test", "*.wild.test"}
			} else {
				c.DNSNames = []string{"beta.test"}
			}
		}, false)
	}
	for _, proto := range []string{"12", "13"} {
		for _, mode := range []string{"file", "pem", "der"} {
			for _, choice := range [][2]string{{"alpha.test", "first"}, {"beta.test", "second"}, {"ALIAS.TEST", "second"}, {"one.wild.test", "second"}, {"", "first"}, {"unknown.test", ""}, {"cn-only.test", ""}, {"wild.test", ""}, {"two.one.wild.test", ""}} {
				t.Run(proto+"/"+mode+"/"+choice[0], func(t *testing.T) { sniScenario(t, f, identities, proto, mode, choice[0], choice[1], "first", false) })
			}
			for _, name := range []string{"beta.test", ""} {
				t.Run(proto+"/"+mode+"/rsa_policy/"+name, func(t *testing.T) { sniScenario(t, f, identities, proto, mode, name, "second", "ecdsa", false) })
			}
		}
	}
	for _, mode := range []string{"file", "pem", "der"} {
		t.Run("13/default_groups/"+mode, func(t *testing.T) { sniScenario(t, f, identities, "13", mode, "beta.test", "second", "first", true) })
	}
}
