package independent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	pioncurve "github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

var serverEndpoint = flag.String("dtls-server", "", "native private DTLS server endpoint")

func serverInput(t *testing.T, cert tls.Certificate, roots []byte, mtls, object bool) []byte {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := bytes.Join(cert.Certificate, nil)
	out := make([]byte, 14)
	if mtls {
		out[0] = 1
	}
	if object {
		out[1] = 1
	}
	binary.BigEndian.PutUint32(out[2:6], uint32(len(chain)))
	binary.BigEndian.PutUint32(out[6:10], uint32(len(key)))
	binary.BigEndian.PutUint32(out[10:14], uint32(len(roots)))
	return append(append(append(out, chain...), key...), roots...)
}
func addressPacket(addr *net.UDPAddr, packet []byte) []byte {
	address := append([]byte{4}, addr.IP.To4()...)
	address = append(address, byte(addr.Port>>8), byte(addr.Port))
	return append(append([]byte{byte(len(address))}, address...), packet...)
}
func mutateCertificateVerify(packet []byte, scheme bool) bool {
	for at := 0; at+13 <= len(packet); {
		size := int(binary.BigEndian.Uint16(packet[at+11 : at+13]))
		end := at + 13 + size
		if end > len(packet) {
			return false
		}
		if packet[at] == 22 && binary.BigEndian.Uint16(packet[at+3:at+5]) == 0 {
			for hs := at + 13; hs+12 <= end; {
				n := int(packet[hs+9])<<16 | int(packet[hs+10])<<8 | int(packet[hs+11])
				if hs+12+n > end {
					return false
				}
				if packet[hs] == 15 && n > 4 {
					if scheme {
						packet[hs+13] ^= 2
					} else {
						packet[hs+12+n-1] ^= 1
					}
					return true
				}
				hs += 12 + n
			}
		}
		at = end
	}
	return false
}
func runServer(t *testing.T, rsaServer bool, clientKind string, loss bool, failure string) {
	t.Helper()
	root, cert := roleIdentity(t, rsaServer, false, true)
	var clientRoots []byte
	var clientCert tls.Certificate
	mtls := clientKind != "none"
	if mtls {
		clientRoots, clientCert = roleIdentity(t, clientKind == "rsa", true, false)
	}
	if failure == "untrusted" {
		clientRoots, _ = roleIdentity(t, false, true, false)
	}
	if failure == "purpose" {
		clientRoots, clientCert = roleIdentity(t, false, false, false)
	}
	mode := "accept"
	if failure == "policy" {
		mode = "reject"
	}
	exporter := loss && failure == ""
	args := []string{mode, "static"}
	if exporter {
		args = append(args, "exporter")
	}
	n := startEndpoint(t, *serverEndpoint, args...)
	status, _ := n.rpc('I', serverInput(t, cert, clientRoots, mtls, clientKind == "rsa"))
	if status != 0 || n.refs != 0 {
		t.Fatalf("context init status=%d leases=%d\n%s", status, n.refs, n.diagnostics())
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()
	pool := x509.NewCertPool()
	serverCA, err := x509.ParseCertificate(root)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(serverCA)
	suite := dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	if rsaServer {
		suite = dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	}
	config := &dtls.Config{RootCAs: pool, ServerName: "localhost", CipherSuites: []dtls.CipherSuiteID{suite},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PKCS1WithSHA256},
		EllipticCurves:   []pioncurve.Curve{pioncurve.P256}, ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		SupportedProtocols: []string{"test"}, FlightInterval: 150 * time.Millisecond, MTU: 512}
	if mtls && failure != "missing" {
		config.Certificates = []tls.Certificate{clientCert}
	}
	if failure == "ems" {
		config.ExtendedMasterSecret = dtls.DisableExtendedMasterSecret
	}
	if failure == "alpn" {
		config.SupportedProtocols = []string{"other"}
	}
	if failure == "curve" {
		config.EllipticCurves = []pioncurve.Curve{pioncurve.P384}
	}
	connection, err := dtls.Client(clientUDP, server.LocalAddr(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	exported := make(chan []byte, 1)
	go func() {
		if e := connection.HandshakeContext(ctx); e != nil {
			finished <- e
			return
		}
		material, e := exportedMaterial(connection)
		if e != nil {
			finished <- e
			return
		}
		exported <- material
		if e := connection.SetDeadline(time.Now().Add(7 * time.Second)); e != nil {
			finished <- e
			return
		}
		if _, e := connection.Write([]byte("pion-to-native")); e != nil {
			finished <- e
			return
		}
		buffer := make([]byte, 1500)
		size, e := connection.Read(buffer)
		if e != nil || !bytes.Equal(buffer[:size], []byte("native-to-pion")) {
			finished <- fmt.Errorf("native data: size=%d err=%v", size, e)
			return
		}
		if _, e = connection.Write([]byte("ack")); e != nil {
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
	var remote *net.UDPAddr
	dropped, application, ack, mutated, fragmented, leaseChecked := false, false, false, false, false, false
	var heldVerify []byte
	proofReordered := false
	deadline := time.Now().Add(9 * time.Second)
	for time.Now().Before(deadline) && n.phase != 8 {
		select {
		case peerErr := <-finished:
			t.Fatalf("Pion terminated before native close/rejection: %v (native phase=%d)\n%s", peerErr, n.phase, n.diagnostics())
		default:
		}
		if n.phase != 0 {
			for {
				status, wire := n.rpc('N', nil)
				if status == 1 {
					break
				}
				if status != 0 {
					t.Fatalf("next %d phase=%d\n%s", status, n.phase, n.diagnostics())
				}
				if len(wire) >= 25 && wire[0] == 22 && wire[3] == 0 && wire[4] == 0 {
					t.Logf("native flight: epoch=%d record=%d hs=%d seq=%d total=%d offset=%d fragment=%d", binary.BigEndian.Uint16(wire[3:5]), uint64(wire[5])<<40|uint64(wire[6])<<32|uint64(wire[7])<<24|uint64(wire[8])<<16|uint64(wire[9])<<8|uint64(wire[10]), wire[13], binary.BigEndian.Uint16(wire[17:19]), int(wire[14])<<16|int(wire[15])<<8|int(wire[16]), int(wire[19])<<16|int(wire[20])<<8|int(wire[21]), int(wire[22])<<16|int(wire[23])<<8|int(wire[24]))
				}
				if len(wire) > 25 && wire[0] == 22 && wire[3] == 0 && wire[4] == 0 && wire[13] == 11 &&
					(int(wire[14])<<16|int(wire[15])<<8|int(wire[16])) > (int(wire[22])<<16|int(wire[23])<<8|int(wire[24])) {
					fragmented = true
				}
				if loss && !dropped && len(wire) >= 13 && wire[0] == 22 && binary.BigEndian.Uint16(wire[3:5]) == 1 {
					dropped = true
				} else {
					if remote == nil {
						t.Fatal("native output before peer address")
					}
					if _, err = server.WriteToUDP(wire, remote); err != nil {
						t.Fatal(err)
					}
				}
				if status, _ = n.rpc('S', []byte{1}); status != 0 {
					t.Fatalf("sent %d", status)
				}
			}
		}
		if n.phase == 8 {
			break
		}
		if n.phase == 6 && !leaseChecked {
			if n.refs != 1 || (n.flags&32 != 0) == exporter || n.flags&16 == 0 {
				t.Fatalf("admission/erasure flags=%x leases=%d", n.flags, n.refs)
			}
			if status, _ := n.rpc('X', nil); status != 2 {
				t.Fatalf("context cleared a live lease: %d", status)
			}
			leaseChecked = true
		}
		if err = server.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, 16421)
		size, addr, e := server.ReadFromUDP(packet)
		if e != nil {
			if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
				continue
			}
			t.Fatal(e)
		}
		remote = addr
		packet = packet[:size]
		if len(packet) >= 25 && packet[3] == 0 && packet[4] == 0 {
			t.Logf("peer packet: type=%d epoch=%d handshake=%d msg=%d bytes=%d", packet[0], binary.BigEndian.Uint16(packet[3:5]), packet[13], binary.BigEndian.Uint16(packet[17:19]), len(packet))
		}
		if (failure == "signature" || failure == "scheme") && !mutated {
			mutated = mutateCertificateVerify(packet, failure == "scheme")
		}
		var status int32
		var payload []byte
		if clientKind == "reordered" && !proofReordered && n.phase != 0 {
			// Repack original records into datagrams and deliver authenticated
			// Finished before the plaintext CertificateVerify record. Keys are
			// already derived, but no client proof/policy/READY may commit early.
			for len(packet) > 0 {
				if len(packet) < 13 {
					t.Fatal("short Pion record")
				}
				size := 13 + int(binary.BigEndian.Uint16(packet[11:13]))
				if size > len(packet) {
					t.Fatal("truncated Pion record")
				}
				rec := packet[:size]
				packet = packet[size:]
				if len(rec) > 25 && rec[0] == 22 && rec[3] == 0 && rec[4] == 0 && rec[13] == 15 {
					heldVerify = append([]byte(nil), rec...)
					continue
				}
				status, payload = n.rpc('G', addressPacket(addr, rec))
				if status < 0 {
					break
				}
				if heldVerify != nil && rec[0] == 22 && binary.BigEndian.Uint16(rec[3:5]) == 1 {
					if n.phase != 3 || n.checks != 0 {
						t.Fatalf("Finished bypassed CertificateVerify: phase=%d checks=%d", n.phase, n.checks)
					}
					status, payload = n.rpc('G', addressPacket(addr, heldVerify))
					heldVerify = nil
					proofReordered = true
					if status == 0 && n.phase != 5 {
						t.Fatalf("valid reordered proofs did not queue final flight: %d", n.phase)
					}
					if status < 0 {
						break
					}
				}
			}
		} else {
			status, payload = n.rpc('G', addressPacket(addr, packet))
		}
		if status < 0 {
			if failure == "" {
				t.Fatalf("receive %d phase=%d\n%s", status, n.phase, n.diagnostics())
			}
			if n.phase != 9 || n.flags&8 == 0 || application {
				t.Fatalf("failed stream published data/keys phase=%d flags=%x", n.phase, n.flags)
			}
			wantChecks := uint16(0)
			if failure == "policy" {
				wantChecks = 1
			}
			if n.checks != wantChecks {
				t.Fatalf("policy calls=%d want=%d", n.checks, wantChecks)
			}
			if (failure == "signature" || failure == "scheme") && !mutated {
				t.Fatal("test did not mutate CertificateVerify")
			}
			sendNativeFatal(t, n, status, 0, func(wire []byte) (int, error) { return server.WriteToUDP(wire, remote) })
			awaitPeerFatal(t, finished)
			if st, _ := n.rpc('C', nil); st != 0 || n.refs != 0 {
				t.Fatalf("failed stream clear %d leases=%d", st, n.refs)
			}
			if st, _ := n.rpc('X', nil); st != 0 {
				t.Fatalf("context clear %d", st)
			}
			return
		}
		if status != 0 && status != 3 {
			t.Fatalf("receive busy without pending sends: %d", status)
		}
		if n.phase == 0 {
			if n.refs != 0 || len(payload) > len(packet) {
				t.Fatal("cookie gate allocated a lease or amplified")
			}
			if len(payload) > 0 {
				if _, err = server.WriteToUDP(payload, addr); err != nil {
					t.Fatal(err)
				}
			}
			continue
		}
		for len(payload) > 0 {
			if len(payload) < 2 {
				t.Fatal("invalid callback framing")
			}
			size := int(binary.BigEndian.Uint16(payload[:2]))
			if size > len(payload)-2 {
				t.Fatal("invalid callback size")
			}
			text := string(payload[2 : 2+size])
			payload = payload[2+size:]
			switch text {
			case "pion-to-native":
				select {
				case material := <-exported:
					nativeExport(t, n, exporter, material)
				case <-time.After(time.Second):
					t.Fatal("missing peer exporter")
				}
				application = true
				if st, _ := n.rpc('W', []byte("native-to-pion")); st != 0 {
					t.Fatalf("write %d", st)
				}
			case "ack":
				ack = true
				if st, _ := n.rpc('O', nil); st != 0 {
					t.Fatalf("close %d", st)
				}
				nativeExport(t, n, false, nil)
				if n.flags&32 == 0 {
					t.Fatal("master survived close admission")
				}
			default:
				t.Fatalf("unexpected application datagram of %d bytes", len(text))
			}
		}
	}
	if failure != "" {
		t.Fatalf("negative case was not rejected: %s", failure)
	}
	if n.phase != 8 || !application || !ack || !fragmented || (loss && !dropped) {
		t.Fatalf("incomplete exchange phase=%d app=%t ack=%t fragmented=%t loss=%t\n%s", n.phase, application, ack, fragmented, dropped, n.diagnostics())
	}
	if clientKind == "reordered" && !proofReordered {
		t.Fatal("CertificateVerify reorder was not exercised")
	}
	want := uint16(0)
	if mtls {
		want = 1
	}
	if n.checks != want {
		t.Fatalf("policy reran on retransmission: %d", n.checks)
	}
	select {
	case e := <-finished:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Pion did not close")
	}
	if status, _ := n.rpc('C', nil); status != 0 || n.refs != 0 {
		t.Fatalf("stream clear %d leases=%d", status, n.refs)
	}
	if status, _ := n.rpc('X', nil); status != 0 {
		t.Fatalf("context clear %d", status)
	}
}
func TestDTLSServerAgainstPion(t *testing.T) {
	if *serverEndpoint == "" {
		t.Fatal("missing native DTLS server endpoint")
	}
	for _, rsaServer := range []bool{false, true} {
		for _, kind := range []string{"none", "ec", "rsa", "reordered"} {
			for _, loss := range []bool{false, true} {
				t.Run(fmt.Sprintf("rsa_%t/client_%s/drop_final_%t", rsaServer, kind, loss), func(t *testing.T) { runServer(t, rsaServer, kind, loss, "") })
			}
		}
	}
	for _, failure := range []string{"missing", "untrusted", "purpose", "signature", "scheme", "policy", "ems", "alpn", "curve"} {
		t.Run("reject_"+failure, func(t *testing.T) { runServer(t, false, "ec", false, failure) })
	}
}
