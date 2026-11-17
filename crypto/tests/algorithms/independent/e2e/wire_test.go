package independent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var recordSuite = flag.String("record-suite", "", "native DTLS record suite")
var wireSuites = []*string{
	flag.String("handshake-suite", "", "native handshake suite"),
	flag.String("secrets-suite", "", "native secrets suite"),
	flag.String("exchange-suite", "", "native exchange suite"),
	flag.String("client-suite", "", "native client cases"),
	flag.String("server-suite", "", "native server cases"),
}

func wireRange(start, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(start + i)
	}
	return b
}
func put24(b []byte, value int) { b[0], b[1], b[2] = byte(value>>16), byte(value>>8), byte(value) }
func wireHeader(kind byte, seq uint16, total, offset, fragment int) []byte {
	b := make([]byte, 12)
	b[0] = kind
	put24(b[1:4], total)
	binary.BigEndian.PutUint16(b[4:6], seq)
	put24(b[6:9], offset)
	put24(b[9:12], fragment)
	return b
}
func wireMAC(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
func wirePRF(secret []byte, label string, seed []byte, size int) []byte {
	combined := append([]byte(label), seed...)
	a := wireMAC(secret, combined)
	var output []byte
	for len(output) < size {
		output = append(output, wireMAC(secret, a, combined)...)
		a = wireMAC(secret, a)
	}
	return output[:size]
}
func wireRun(t *testing.T, program string, env []string) {
	t.Helper()
	if program == "" {
		t.Fatal("native suite path is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program)
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native suite: %v\n%s", err, out)
	}
}
func wireWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func wireRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func wireGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func wireOpen(t *testing.T, key, salt, record []byte, expected []byte) {
	t.Helper()
	aad := append(bytes.Clone(record[3:11]), record[:3]...)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(expected)))
	plain, err := wireGCM(t, key).Open(nil, append(bytes.Clone(salt), record[13:21]...), record[21:], aad)
	if err != nil || !bytes.Equal(plain, expected) {
		t.Fatalf("directional record: %v", err)
	}
}

func TestDTLSRecordOracle(t *testing.T) {
	key, salt, plain := wireRange(0, 16), []byte{0xa0, 0xa1, 0xa2, 0xa3}, []byte("independent DTLS record")
	sequence := []byte{0, 1, 0, 0, 0, 0, 0, 17}
	nonce := wireRange(0x90, 8)
	aad := append(bytes.Clone(sequence), 23, 0xfe, 0xfd)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(plain)))
	sealed := wireGCM(t, key).Seal(nil, append(bytes.Clone(salt), nonce...), plain, aad)
	wire := append([]byte{23, 0xfe, 0xfd}, sequence...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(8+len(sealed)))
	wire = append(append(wire, nonce...), sealed...)
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	wireWrite(t, input, wire)
	wireRun(t, *recordSuite, []string{"SALTS_DTLS_RECORD_INPUT=" + input, "SALTS_DTLS_RECORD_OUTPUT=" + output})
	record := wireRead(t, output)
	if len(record) < 37 || !bytes.Equal(record[:5], []byte{23, 0xfe, 0xfd, 0, 1}) || !bytes.Equal(record[5:11], make([]byte, 6)) || int(binary.BigEndian.Uint16(record[11:13])) != len(record)-13 || !bytes.Equal(record[13:21], record[3:11]) {
		t.Fatal("invalid native record metadata")
	}
	wireOpen(t, key, salt, record, []byte("native DTLS record"))
}

func cookieMAC(issued, hello []byte) []byte {
	address := []byte{4, 127, 0, 0, 1, 1, 0xbb}
	framed := []byte{byte(len(address)), 0, 0, 0}
	put24(framed[1:], len(hello))
	return wireMAC(wireRange(0, 32), []byte("Salts DTLS1.2 cookie"), issued, framed, address, hello)[:24]
}
func wireHello(cookie []byte) []byte {
	body := append([]byte{0xfe, 0xfd}, wireRange(0, 32)...)
	body = append(body, 0, byte(len(cookie)))
	body = append(body, cookie...)
	return append(body, 0, 2, 0xc0, 0x2b, 1, 0)
}
func helloPacket(body []byte, seq uint16) []byte {
	h := append(wireHeader(1, seq, len(body), 0, len(body)), body...)
	record := []byte{22, 0xfe, 0xff, 0, 0, 1, 2, 3, 4, 5, 6}
	record = binary.BigEndian.AppendUint16(record, uint16(len(h)))
	return append(record, h...)
}
func TestDTLSHandshakeOracle(t *testing.T) {
	dir := t.TempDir()
	env := []string{}
	paths := map[string]string{}
	for _, name := range []string{"first", "second", "reply", "fragments", "canonical", "proofs", "secrets", "ec-cert", "ec-key", "rsa-key", "rsa-cert", "ec-exchange", "rsa-exchange", "exchange-output"} {
		paths[name] = filepath.Join(dir, name)
	}
	keys := map[string]string{"first": "FIRST", "second": "SECOND", "reply": "REPLY", "fragments": "FRAGMENTS", "canonical": "CANONICAL", "proofs": "PROOFS", "secrets": "SECRETS", "ec-cert": "EC_CERT", "ec-key": "EC_KEY", "rsa-key": "RSA_KEY", "rsa-cert": "RSA_CERT", "ec-exchange": "EC_EXCHANGE", "rsa-exchange": "RSA_EXCHANGE", "exchange-output": "EXCHANGE_OUTPUT"}
	for name, path := range paths {
		env = append(env, "SALTS_DTLS_"+keys[name]+"="+path)
	}
	first := helloPacket(wireHello(nil), 0)
	issued := binary.BigEndian.AppendUint64(nil, 100)
	cookie := append(bytes.Clone(issued), cookieMAC(issued, wireHello(nil))...)
	wireWrite(t, paths["first"], first)
	wireWrite(t, paths["second"], helloPacket(wireHello(cookie), 1))
	body := make([]byte, 4096)
	for i := range body {
		body[i] = byte(i % 251)
	}
	var fragments []byte
	for _, part := range [][2]int{{2048, 2048}, {0, 1024}, {512, 2048}} {
		fragments = append(fragments, wireHeader(11, 7, len(body), part[0], part[1])...)
		fragments = append(fragments, body[part[0]:part[0]+part[1]]...)
	}
	wireWrite(t, paths["fragments"], fragments)
	var canonical []byte
	for _, m := range []struct {
		kind byte
		seq  uint16
		body string
	}{{1, 1, "client hello"}, {2, 1, "server hello"}, {11, 2, "certificate"}, {12, 3, "key exchange"}, {14, 4, ""}, {16, 2, "key"}} {
		canonical = append(canonical, wireHeader(m.kind, m.seq, len(m.body), 0, len(m.body))...)
		canonical = append(canonical, m.body...)
	}
	hash := sha256.Sum256(canonical)
	shared, client, server := wireRange(0, 32), wireRange(32, 32), wireRange(64, 32)
	master := wirePRF(shared, "extended master secret", hash[:], 48)
	traffic := wirePRF(master, "key expansion", append(bytes.Clone(server), client...), 40)
	finished := sha256.Sum256(append(append(bytes.Clone(canonical), wireHeader(15, 3, 5, 0, 5)...), []byte("proof")...))
	proofs := append(wirePRF(master, "client finished", finished[:], 12), wirePRF(master, "server finished", finished[:], 12)...)
	wireWrite(t, paths["proofs"], proofs)
	ephScalar := make([]byte, 32)
	ephScalar[31] = 7
	ephemeral, err := ecdh.P256().NewPrivateKey(ephScalar)
	if err != nil {
		t.Fatal(err)
	}
	params := append([]byte{3, 0, 23, 65}, ephemeral.PublicKey().Bytes()...)
	signed := append(append(bytes.Clone(client), server...), params...)
	signedHash := sha256.Sum256(signed)
	x, y := elliptic.P256().ScalarBaseMult([]byte{11})
	ecKey := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: big.NewInt(11)}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for i, key := range []crypto.Signer{ecKey, rsaKey} {
		name, scheme := "ec", uint16(0x0403)
		if i == 1 {
			name, scheme = "rsa", 0x0401
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "DTLS proof fixture " + name}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		wireWrite(t, paths[name+"-cert"], der)
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		wireWrite(t, paths[name+"-key"], private)
		var signature []byte
		if i == 0 {
			signature, err = ecdsa.SignASN1(rand.Reader, ecKey, signedHash[:])
		} else {
			signature, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, signedHash[:])
		}
		if err != nil {
			t.Fatal(err)
		}
		exchange := binary.BigEndian.AppendUint16(bytes.Clone(params), scheme)
		exchange = binary.BigEndian.AppendUint16(exchange, uint16(len(signature)))
		wireWrite(t, paths[name+"-exchange"], append(exchange, signature...))
	}
	for _, program := range wireSuites {
		wireRun(t, *program, env)
	}
	reply := wireRead(t, paths["reply"])
	if len(reply) != 60 || len(reply) > len(first) || !bytes.Equal(reply[5:11], first[5:11]) || !bytes.Equal(reply[13:25], wireHeader(3, 0, 35, 0, 35)) || !bytes.Equal(reply[25:28], []byte{0xfe, 0xfd, 32}) {
		t.Fatal("native HelloVerifyRequest metadata")
	}
	if binary.BigEndian.Uint64(reply[28:36]) != 200 || !hmac.Equal(reply[36:], cookieMAC(reply[28:36], wireHello(nil))) {
		t.Fatal("native cookie MAC")
	}
	if !bytes.Equal(wireRead(t, paths["canonical"]), append(wireHeader(11, 7, len(body), 0, len(body)), body...)) {
		t.Fatal("fragment transcript normalization")
	}
	native := wireRead(t, paths["secrets"])
	expected := append(append(append(bytes.Clone(master), finished[:]...), proofs...), wirePRF(shared, "oracle", append(bytes.Clone(client), server...), 65)...)
	if len(native) != 257 || !hmac.Equal(native[:169], expected) {
		t.Fatal("EMS/Finished/multiblock PRF differs")
	}
	for i, plain := range []string{"client!", "server!"} {
		wireOpen(t, traffic[i*16:(i+1)*16], traffic[32+i*4:36+i*4], native[169+i*44:169+(i+1)*44], []byte(plain))
	}
	exchange := wireRead(t, paths["exchange-output"])
	if len(exchange) != 378 || bytes.Equal(exchange[:65], exchange[189:254]) {
		t.Fatal("ephemeral keys missing or reused")
	}
	for i := 0; i < 2; i++ {
		result := exchange[i*189 : (i+1)*189]
		point, err := ecdh.P256().NewPublicKey(result[:65])
		if err != nil {
			t.Fatal(err)
		}
		shared, err := ephemeral.ECDH(point)
		if err != nil {
			t.Fatal(err)
		}
		master := wirePRF(shared, "extended master secret", bytes.Repeat([]byte{17}, 32), 48)
		traffic := wirePRF(master, "key expansion", append(bytes.Clone(server), client...), 40)
		if !hmac.Equal(result[65:145], append(bytes.Clone(shared), master...)) {
			t.Fatal("independent ECDH/EMS differs")
		}
		wireOpen(t, traffic[:16], traffic[32:36], result[145:], []byte("client!"))
	}
}
