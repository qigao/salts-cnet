package independent

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"testing"
	"time"
)

const (
	wireZero byte = iota
	wireCookie
	wireHelloPhase
	wireCertificate
	wireKey
	wireDone
	wireFinished
	wireReady
	wireClosing
	wireClosed
	wireFailed
)

func vec24(data []byte) []byte { b := make([]byte, 3); put24(b, len(data)); return append(b, data...) }
func wireMessage(kind byte, seq uint16, body []byte) []byte {
	return append(wireHeader(kind, seq, len(body), 0, len(body)), body...)
}
func wireRecord(kind byte, seq uint64, body []byte, epoch uint16) []byte {
	b := make([]byte, 13)
	b[0] = kind
	b[1], b[2] = 0xfe, 0xfd
	binary.BigEndian.PutUint16(b[3:5], epoch)
	for i := 0; i < 6; i++ {
		b[10-i] = byte(seq >> (8 * i))
	}
	binary.BigEndian.PutUint16(b[11:13], uint16(len(body)))
	return append(b, body...)
}
func wireUnpack(t *testing.T, wire []byte) (byte, uint16, uint64, []byte) {
	t.Helper()
	if len(wire) < 13 || int(binary.BigEndian.Uint16(wire[11:13])) != len(wire)-13 {
		t.Fatal("native record framing")
	}
	var seq uint64
	for _, b := range wire[5:11] {
		seq = seq<<8 | uint64(b)
	}
	return wire[0], binary.BigEndian.Uint16(wire[3:5]), seq, wire[13:]
}
func wireExtension(kind uint16, body []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, kind)
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...)
}
func uint24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

type wireIdentity struct {
	key   crypto.Signer
	certs []*x509.Certificate
}
type wireCredentials struct {
	root        *x509.Certificate
	rootKey, ec *ecdsa.PrivateKey
	rsa         *rsa.PrivateKey
	ephemeral   *ecdh.PrivateKey
	now         time.Time
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
func signCertificate(t *testing.T, template, parent *x509.Certificate, key crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func newWireCredentials(t *testing.T) *wireCredentials {
	t.Helper()
	c := &wireCredentials{rootKey: ecKey(t), ec: ecKey(t), now: time.Now()}
	var err error
	c.rsa, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	scalar := make([]byte, 32)
	scalar[31] = 7
	c.ephemeral, err = ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DTLS root"}, NotBefore: c.now.Add(-24 * time.Hour), NotAfter: c.now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 2, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	c.root = signCertificate(t, root, root, c.rootKey.Public(), c.rootKey)
	return c
}
func (c *wireCredentials) leaf(t *testing.T, rsaLeaf bool, failure string, client bool) wireIdentity {
	t.Helper()
	var key crypto.Signer = c.ec
	if rsaLeaf {
		key = c.rsa
	}
	parent := c.root
	var signer crypto.Signer = c.rootKey
	var extra []*x509.Certificate
	if failure == "constraints" || failure == "intermediate" {
		k := ecKey(t)
		ca := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "constrained CA"}, NotBefore: c.root.NotBefore, NotAfter: c.root.NotAfter, IsCA: true, BasicConstraintsValid: true, MaxPathLen: 2, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		if failure == "constraints" {
			ca.PermittedDNSDomainsCritical = true
			ca.PermittedDNSDomains = []string{".allowed.test"}
		}
		parent = signCertificate(t, ca, c.root, k.Public(), c.rootKey)
		signer = k
		extra = []*x509.Certificate{parent}
	}
	if failure == "wrong_root" {
		signer = ecKey(t)
		copy := *parent
		copy.PublicKey = signer.Public()
		parent = &copy
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: c.now.Add(-24 * time.Hour), NotAfter: c.now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if client || failure == "purpose" {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if failure == "key_usage" {
		leaf.KeyUsage = x509.KeyUsageKeyEncipherment
	}
	if failure == "expired" {
		leaf.NotBefore = c.now.Add(-72 * time.Hour)
		leaf.NotAfter = c.now.Add(-48 * time.Hour)
	}
	if failure == "future" {
		leaf.NotBefore = c.now.Add(24 * time.Hour)
		leaf.NotAfter = c.now.Add(48 * time.Hour)
	}
	if failure == "critical" {
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}}
	}
	cert := signCertificate(t, leaf, parent, key.Public(), signer)
	return wireIdentity{key, append([]*x509.Certificate{cert}, extra...)}
}

type wirePeer struct {
	*nativeClient
	isServer                                                                           bool
	credentials                                                                        *wireCredentials
	now, sequence, sendSequence                                                        uint64
	alpn                                                                               string
	clientSequence, serverFinishedSequence                                             uint16
	hello, clientRandom, serverRandom, transcript, master, keys, proof, nativeFinished []byte
	serverMessages                                                                     [][]byte
}

func newWirePeer(t *testing.T, c *wireCredentials, hostname, policy, alpn string, identity *wireIdentity, object, exporter bool) *wirePeer {
	t.Helper()
	args := []string{hostname, policy, alpn}
	if exporter {
		args = append(args, "exporter")
	}
	p := &wirePeer{nativeClient: startEndpoint(t, *endpoint, args...), credentials: c, alpn: alpn}
	if identity == nil {
		p.want('I', c.root.Raw, 0, nil)
	} else {
		var chain []byte
		for _, cert := range identity.certs {
			chain = append(chain, cert.Raw...)
		}
		key, err := x509.MarshalPKCS8PrivateKey(identity.key)
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, 13)
		if object {
			body[0] = 1
		}
		binary.BigEndian.PutUint32(body[1:5], uint32(len(c.root.Raw)))
		binary.BigEndian.PutUint32(body[5:9], uint32(len(chain)))
		binary.BigEndian.PutUint32(body[9:13], uint32(len(key)))
		body = append(append(append(body, c.root.Raw...), chain...), key...)
		p.want('J', body, 0, nil)
		if p.flags&64 != 0 {
			t.Fatal("identity erased before use")
		}
	}
	want := int32(1)
	if policy == "none" {
		want = 0
	}
	if p.refs != want {
		t.Fatalf("retained policy refs=%d", p.refs)
	}
	return p
}
func (p *wirePeer) rpc(op byte, body []byte) (int32, []byte) {
	return p.nativeClient.rpcAt(op, body, p.now)
}
func (p *wirePeer) want(op byte, body []byte, status int32, result []byte) []byte {
	p.t.Helper()
	actual, out := p.rpc(op, body)
	if actual != status || !bytes.Equal(out, result) {
		p.t.Fatalf("op=%c status=%d wanted=%d body=%x wanted=%x", op, actual, status, out, result)
	}
	return out
}
func (p *wirePeer) outgoing() []byte {
	p.t.Helper()
	status, wire := p.rpc('N', nil)
	if status != 0 || p.flags&1 == 0 {
		p.t.Fatalf("outgoing status=%d flags=%x", status, p.flags)
	}
	p.want('S', []byte{1}, 0, nil)
	return wire
}
func (p *wirePeer) receive(body []byte, kind byte) (int32, []byte) {
	wire := wireRecord(kind, p.sequence, body, 0)
	p.sequence++
	return p.rpc('R', wire)
}
func (p *wirePeer) start(renew bool) []byte {
	p.t.Helper()
	kind, epoch, _, first := wireUnpack(p.t, p.outgoing())
	if kind != 22 || epoch != 0 || first[0] != 1 || binary.BigEndian.Uint16(first[4:6]) != 0 {
		p.t.Fatal("initial ClientHello")
	}
	original := first[12:]
	p.clientRandom = bytes.Clone(original[2:34])
	count := 1
	if renew {
		count = 2
	}
	for i := 0; i < count; i++ {
		cookie := sha256.Sum256(append(append([]byte("independent cookie"), byte(i)), original...))
		status, _ := p.receive(wireMessage(3, 0, append([]byte{0xfe, 0xfd, 32}, cookie[:]...)), 22)
		if status != 0 {
			p.t.Fatal("cookie challenge")
		}
		_, _, _, canonical := wireUnpack(p.t, p.outgoing())
		body := canonical[12:]
		if !bytes.Equal(body[:35], original[:35]) || body[35] != 32 || !bytes.Equal(body[36:68], cookie[:]) || !bytes.Equal(body[68:], original[36:]) {
			p.t.Fatal("cookie renewal changed ClientHello")
		}
		p.clientSequence = binary.BigEndian.Uint16(canonical[4:6])
		p.hello = canonical
	}
	if p.phase != wireHelloPhase {
		p.t.Fatalf("hello phase=%d", p.phase)
	}
	return p.hello
}
func (p *wirePeer) flight(rsaLeaf bool, failure string, reorder bool, request []byte) int32 {
	p.t.Helper()
	identity := p.credentials.leaf(p.t, rsaLeaf, failure, false)
	key := identity.key
	p.serverRandom = wireRange(64, 32)
	suite := uint16(0xc02b)
	if rsaLeaf {
		suite = 0xc02f
	}
	type ext struct {
		kind uint16
		data []byte
	}
	extensions := []ext{{0, nil}, {11, []byte{3, 0, 1, 2}}, {23, nil}, {0xff01, []byte{0}}, {16, []byte{0, 5, 4, 't', 'e', 's', 't'}}}
	var encoded []byte
	for _, e := range extensions {
		if (e.kind == 16 && p.alpn == "" && failure != "unoffered_alpn") || (e.kind == 23 && failure == "no_ems") || (e.kind == 16 && failure == "no_alpn") {
			continue
		}
		if e.kind == 16 && failure == "bad_alpn" {
			e.data = []byte{0, 5, 4, 'e', 'v', 'i', 'l'}
		}
		encoded = append(encoded, wireExtension(e.kind, e.data)...)
	}
	if failure == "duplicate_ems" {
		encoded = append(encoded, wireExtension(23, nil)...)
	}
	if failure == "unoffered" {
		encoded = append(encoded, wireExtension(0x1234, nil)...)
	}
	if failure == "cipher" {
		suite = 0x1301
	}
	hello := append([]byte{0xfe, 0xfd}, p.serverRandom...)
	hello = append(hello, 0)
	hello = binary.BigEndian.AppendUint16(hello, suite)
	compression := byte(0)
	if failure == "compression" {
		compression = 1
	}
	hello = append(hello, compression)
	hello = binary.BigEndian.AppendUint16(hello, uint16(len(encoded)))
	hello = append(hello, encoded...)
	var certs []byte
	for _, c := range identity.certs {
		certs = append(certs, vec24(c.Raw)...)
	}
	certificate := vec24(certs)
	params := append([]byte{3, 0, 23, 65}, p.credentials.ephemeral.PublicKey().Bytes()...)
	if failure == "point" {
		params[4] = 5
	}
	signed := append(append(bytes.Clone(p.clientRandom), p.serverRandom...), params...)
	if failure == "signed_random" {
		signed[0] ^= 1
	}
	if failure == "wrong_signer" {
		key = ecKey(p.t)
	}
	hash := sha256.Sum256(signed)
	var signature []byte
	var err error
	scheme := uint16(0x0403)
	if rsaLeaf {
		scheme = 0x0401
		signature, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, hash[:])
	} else {
		signature, err = ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
	}
	if err != nil {
		p.t.Fatal(err)
	}
	if failure == "signature" {
		signature[len(signature)-1] ^= 1
	}
	exchange := binary.BigEndian.AppendUint16(bytes.Clone(params), scheme)
	exchange = binary.BigEndian.AppendUint16(exchange, uint16(len(signature)))
	exchange = append(exchange, signature...)
	p.serverMessages = [][]byte{wireMessage(2, 1, hello), wireMessage(11, 2, certificate), wireMessage(12, 3, exchange), wireMessage(14, 4, nil)}
	p.serverFinishedSequence = 5
	if request != nil {
		p.serverMessages = append(p.serverMessages[:3], wireMessage(13, 4, request), wireMessage(14, 5, nil))
		p.serverFinishedSequence = 6
		if failure == "duplicate_request" {
			p.serverMessages = append(p.serverMessages[:4], wireMessage(13, 5, request), wireMessage(14, 6, nil))
		}
	}
	packets := p.serverMessages
	if reorder {
		middle := len(certificate) / 2
		first := append(wireHeader(11, 2, len(certificate), middle, len(certificate)-middle), certificate[middle:]...)
		second := append(wireHeader(11, 2, len(certificate), 0, middle+7), certificate[:middle+7]...)
		packets = nil
		for i := len(p.serverMessages) - 1; i >= 3; i-- {
			packets = append(packets, p.serverMessages[i])
		}
		packets = append(packets, p.serverMessages[2], first, first, second, p.serverMessages[0])
	}
	for _, packet := range packets {
		status, _ := p.receive(packet, 22)
		if status < 0 {
			return status
		}
	}
	return 0
}
func (p *wirePeer) decrypt(wire []byte, client bool) []byte {
	p.t.Helper()
	_, epoch, _, body := wireUnpack(p.t, wire)
	if epoch != 1 {
		p.t.Fatal("protected record epoch")
	}
	at := 16
	iv := 36
	if client {
		at, iv = 0, 32
	}
	aad := append(bytes.Clone(wire[3:11]), wire[:3]...)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(body)-24))
	plain, err := wireGCM(p.t, p.keys[at:at+16]).Open(nil, append(bytes.Clone(p.keys[iv:iv+4]), body[:8]...), body[8:], aad)
	if err != nil {
		p.t.Fatal(err)
	}
	return plain
}
func (p *wirePeer) protect(kind byte, plain []byte, sequence ...uint64) []byte {
	seq := p.sendSequence
	if len(sequence) != 0 {
		seq = sequence[0]
	} else {
		p.sendSequence++
	}
	serial := make([]byte, 8)
	binary.BigEndian.PutUint64(serial, seq)
	serial[0], serial[1] = 0, 1
	explicit := bytes.Clone(serial)
	explicit[0], explicit[1] = 0x90, 0x91
	aad := append(bytes.Clone(serial), kind, 0xfe, 0xfd)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(plain)))
	ciphertext := wireGCM(p.t, p.keys[16:32]).Seal(nil, append(bytes.Clone(p.keys[36:40]), explicit...), plain, aad)
	return wireRecord(kind, seq, append(explicit, ciphertext...), 1)
}
func (p *wirePeer) derive(cke, transcript []byte) {
	p.t.Helper()
	if cke[12] != 65 {
		p.t.Fatal("native ECDHE point width")
	}
	point, err := ecdh.P256().NewPublicKey(cke[13:])
	if err != nil {
		p.t.Fatal(err)
	}
	shared, err := p.credentials.ephemeral.ECDH(point)
	if err != nil {
		p.t.Fatal(err)
	}
	hash := sha256.Sum256(transcript)
	p.master = wirePRF(shared, "extended master secret", hash[:], 48)
	p.keys = wirePRF(p.master, "key expansion", append(bytes.Clone(p.serverRandom), p.clientRandom...), 40)
	p.transcript = transcript
}
func (p *wirePeer) acceptFinished(wire []byte, seq uint16) {
	p.t.Helper()
	finished := p.decrypt(wire, true)
	hash := sha256.Sum256(p.transcript)
	if !bytes.Equal(finished[:12], wireHeader(20, seq, 12, 0, 12)) || !hmac.Equal(finished[12:], wirePRF(p.master, "client finished", hash[:], 12)) {
		p.t.Fatal("client Finished proof")
	}
	p.transcript = append(p.transcript, finished...)
	hash = sha256.Sum256(p.transcript)
	p.proof = wirePRF(p.master, "server finished", hash[:], 12)
	p.sendSequence = 0
	p.nativeFinished = wire
	if p.phase != wireFinished || p.checks != 0 {
		p.t.Fatal("client admitted before server Finished")
	}
}
func (p *wirePeer) clientFlight(retry bool) {
	p.t.Helper()
	flight := [][]byte{p.outgoing(), p.outgoing(), p.outgoing()}
	if retry {
		p.now += 1000
		for i := range flight {
			next := p.outgoing()
			if bytes.Equal(next[5:11], flight[i][5:11]) {
				p.t.Fatal("retransmitted record reused sequence")
			}
			if i == 0 && !bytes.Equal(next[13:], flight[i][13:]) {
				p.t.Fatal("retransmission changed transcript")
			}
			flight[i] = next
		}
	}
	kind, epoch, _, cke := wireUnpack(p.t, flight[0])
	if kind != 22 || epoch != 0 || cke[0] != 16 || binary.BigEndian.Uint16(cke[4:6]) != p.clientSequence+1 {
		p.t.Fatal("native ClientKeyExchange")
	}
	transcript := append(bytes.Clone(p.hello), bytes.Join(p.serverMessages, nil)...)
	p.derive(cke, append(transcript, cke...))
	kind, epoch, _, body := wireUnpack(p.t, flight[1])
	if kind != 20 || epoch != 0 || !bytes.Equal(body, []byte{1}) {
		p.t.Fatal("native CCS")
	}
	p.acceptFinished(flight[2], p.clientSequence+2)
}
func (p *wirePeer) authenticatedFlight(identity wireIdentity, selected, retry bool) {
	p.t.Helper()
	drain := func() [][]byte {
		var result [][]byte
		for {
			status, wire := p.rpc('N', nil)
			if status == 1 {
				return result
			}
			if status != 0 || len(wire) > 1200 || p.flags&64 == 0 || (p.flags&128 != 0) != selected {
				p.t.Fatal("client credential flight/erasure")
			}
			result = append(result, wire)
			p.want('S', []byte{1}, 0, nil)
		}
	}
	flight := drain()
	var original []byte
	if retry {
		p.now += 1000
		repeated := drain()
		if len(repeated) != len(flight) {
			p.t.Fatal("retransmitted flight width")
		}
		for i := range flight {
			if bytes.Equal(flight[i][5:11], repeated[i][5:11]) {
				p.t.Fatal("retransmitted record sequence")
			}
			if bytes.Equal(flight[i][3:5], []byte{0, 0}) && !bytes.Equal(flight[i][13:], repeated[i][13:]) {
				p.t.Fatal("certificate retransmission changed bytes")
			}
		}
		original = flight[len(flight)-1]
		flight = repeated
	}
	type assembly struct {
		kind           byte
		body, coverage []byte
	}
	messages := map[int]*assembly{}
	for _, wire := range flight[:len(flight)-2] {
		kind, epoch, _, fragment := wireUnpack(p.t, wire)
		if kind != 22 || epoch != 0 {
			p.t.Fatal("credential flight record")
		}
		total, seq, offset, size := uint24(fragment[1:4]), int(binary.BigEndian.Uint16(fragment[4:6])), uint24(fragment[6:9]), uint24(fragment[9:12])
		entry := messages[seq]
		if entry == nil {
			entry = &assembly{fragment[0], make([]byte, total), make([]byte, total)}
			messages[seq] = entry
		}
		if entry.kind != fragment[0] || len(fragment) != 12+size || offset+size > total {
			p.t.Fatal("invalid credential fragments")
		}
		for i, b := range fragment[12:] {
			at := offset + i
			if entry.coverage[at] != 0 && entry.body[at] != b {
				p.t.Fatal("overlapping credential bytes differ")
			}
			entry.body[at], entry.coverage[at] = b, 1
		}
	}
	var sequences []int
	for seq := range messages {
		sequences = append(sequences, seq)
	}
	sort.Ints(sequences)
	var canonical [][]byte
	for i, seq := range sequences {
		m := messages[seq]
		if seq != int(p.clientSequence)+1+i || bytes.Contains(m.coverage, []byte{0}) {
			p.t.Fatal("incomplete credential flight")
		}
		canonical = append(canonical, wireMessage(m.kind, uint16(seq), m.body))
	}
	wantKinds := []byte{11, 16}
	if selected {
		wantKinds = append(wantKinds, 15)
	}
	if len(canonical) != len(wantKinds) {
		p.t.Fatal("credential flight message count")
	}
	for i, m := range canonical {
		if m[0] != wantKinds[i] {
			p.t.Fatal("credential flight ordering")
		}
	}
	var certs []byte
	if selected {
		for _, c := range identity.certs {
			certs = append(certs, vec24(c.Raw)...)
		}
	}
	if !bytes.Equal(canonical[0][12:], vec24(certs)) {
		p.t.Fatal("client sent the wrong certificate")
	}
	transcript := append(append(bytes.Clone(p.hello), bytes.Join(p.serverMessages, nil)...), bytes.Join(canonical[:2], nil)...)
	p.derive(canonical[1], transcript)
	if selected {
		proof := canonical[2][12:]
		scheme, size := binary.BigEndian.Uint16(proof[:2]), int(binary.BigEndian.Uint16(proof[2:4]))
		if size != len(proof)-4 {
			p.t.Fatal("CertificateVerify size")
		}
		hash := sha256.Sum256(p.transcript)
		var err error
		switch key := identity.certs[0].PublicKey.(type) {
		case *rsa.PublicKey:
			if scheme != 0x401 {
				p.t.Fatal("RSA CertificateVerify scheme")
			}
			err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], proof[4:])
		case *ecdsa.PublicKey:
			if scheme != 0x403 || !ecdsa.VerifyASN1(key, hash[:], proof[4:]) {
				p.t.Fatal("ECDSA CertificateVerify")
			}
		}
		if err != nil {
			p.t.Fatal(err)
		}
		p.transcript = append(p.transcript, canonical[2]...)
	}
	kind, epoch, _, body := wireUnpack(p.t, flight[len(flight)-2])
	if kind != 20 || epoch != 0 || !bytes.Equal(body, []byte{1}) {
		p.t.Fatal("credential CCS")
	}
	last := flight[len(flight)-1]
	if original != nil && !bytes.Equal(p.decrypt(original, true), p.decrypt(last, true)) {
		p.t.Fatal("retransmitted Finished differs")
	}
	p.acceptFinished(last, p.clientSequence+1+uint16(len(canonical)))
}
func (p *wirePeer) finish(reversed, bad bool) int32 {
	proof := bytes.Clone(p.proof)
	if bad {
		proof[0] ^= 1
	}
	finished := p.protect(22, wireMessage(20, p.serverFinishedSequence, proof))
	if reversed {
		p.want('R', finished, 0, nil)
		if p.phase != wireFinished || p.checks != 0 {
			p.t.Fatal("CCS did not gate Finished")
		}
		status, _ := p.receive([]byte{1}, 20)
		return status
	}
	ccs := wireRecord(20, p.sequence, []byte{1}, 0)
	p.sequence++
	status, _ := p.rpc('R', append(ccs, finished...))
	return status
}
func (p *wirePeer) complete(rsaLeaf, renew, reorder, retry bool) {
	p.t.Helper()
	p.start(renew)
	if p.flight(rsaLeaf, "", reorder, nil) != 0 {
		p.t.Fatal("server flight")
	}
	p.clientFlight(retry)
	if p.finish(reorder, false) != 0 || p.phase != wireReady || p.checks != 1 || p.flags&32 == 0 || p.flags&16 == 0 {
		p.t.Fatalf("DTLS admission phase=%d checks=%d flags=%x", p.phase, p.checks, p.flags)
	}
}
func certRequest(types, schemes, names []byte) []byte {
	b := append([]byte{byte(len(types))}, types...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(schemes)))
	b = append(b, schemes...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(names)))
	return append(b, names...)
}
func standardRequest() []byte { return certRequest([]byte{1, 64}, []byte{4, 3, 4, 1}, nil) }
func encodedName(name []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(name))), name...)
}
func (p *wirePeer) fatal(failure int32, description byte, epoch uint16, decrypt, abort, sent bool) {
	p.t.Helper()
	if failure >= 0 || p.flags&8 == 0 {
		p.t.Fatal("fatal did not erase secrets")
	}
	p.want('Q', nil, 0, []byte{description, 0, 0, 0, 0, 0})
	status, wire := p.rpc('N', nil)
	kind, actualEpoch, _, body := wireUnpack(p.t, wire)
	if status != 0 || kind != 21 || actualEpoch != epoch || len(wire) > 39 {
		p.t.Fatal("fatal record metadata")
	}
	if decrypt {
		body = p.decrypt(wire, !p.isServer)
	}
	if !bytes.Equal(body, []byte{2, description}) {
		p.t.Fatal("fatal alert differs")
	}
	p.want('N', nil, 2, nil)
	status, _ = p.rpc('C', nil)
	if status != 2 {
		p.t.Fatal("cleared borrowed fatal")
	}
	if abort {
		p.want('A', nil, 0, wire)
		status, _ = p.rpc('C', nil)
		if status != 2 {
			p.t.Fatal("aborted fatal borrow lost")
		}
	}
	ack := byte(0)
	if sent {
		ack = 1
	}
	status, _ = p.rpc('S', []byte{ack})
	if status != failure {
		p.t.Fatal("fatal replaced original failure")
	}
	p.now += 100000
	p.want('N', nil, failure, nil)
	p.want('N', nil, failure, nil)
	status, meta := p.rpc('Q', nil)
	if status != 0 || !bytes.Equal(meta[:2], []byte{description, 0}) || (int32(binary.BigEndian.Uint32(meta[2:])) == 0) != sent {
		p.t.Fatal("fatal delivery status")
	}
	status, _ = p.rpc('C', nil)
	if status != 0 {
		p.t.Fatal("fatal cleanup")
	}
}

func exportRequest(label, context []byte, present bool, size uint16) []byte {
	b := make([]byte, 7)
	if present {
		b[0] = 1
	}
	binary.BigEndian.PutUint16(b[1:3], uint16(len(label)))
	binary.BigEndian.PutUint16(b[3:5], uint16(len(context)))
	binary.BigEndian.PutUint16(b[5:7], size)
	return append(append(b, label...), context...)
}
func (p *wirePeer) checkExports() {
	p.t.Helper()
	label := []byte("EXPERIMENTAL-salts-dtls")
	for i, context := range [][]byte{nil, {}, {0, 0xff, 1}, make([]byte, 1024)} {
		for _, size := range []uint16{1, 32, 65, 1024} {
			seed := append(bytes.Clone(p.clientRandom), p.serverRandom...)
			if i != 0 {
				seed = binary.BigEndian.AppendUint16(seed, uint16(len(context)))
				seed = append(seed, context...)
			}
			p.want('E', exportRequest(label, context, i != 0, size), 0, wirePRF(p.master, string(label), seed, int(size)))
		}
	}
	for _, invalid := range [][]byte{nil, []byte("client finished"), []byte("server finished"), []byte("master secret"), []byte("key expansion"), []byte("extended master secret"), []byte("key"), []byte("master secretary"), {0}, {0xff}, bytes.Repeat([]byte{'x'}, 256)} {
		status, out := p.rpc('E', exportRequest(invalid, nil, false, 32))
		if status >= 0 || len(out) != 0 {
			p.t.Fatal("invalid exporter label")
		}
	}
	for _, request := range [][]byte{exportRequest(label, make([]byte, 1025), true, 32), exportRequest(label, nil, false, 0), exportRequest(label, nil, false, 1025)} {
		status, out := p.rpc('E', request)
		if status >= 0 || len(out) != 0 {
			p.t.Fatal("invalid exporter bounds")
		}
	}
}

func TestScriptedDTLSClient(t *testing.T) {
	c := newWireCredentials(t)
	t.Run("complete_records_replay_close", func(t *testing.T) {
		for _, rsaLeaf := range []bool{false, true} {
			t.Run(fmt.Sprint(rsaLeaf), func(t *testing.T) {
				p := newWirePeer(t, c, "localhost", "accept", "test", nil, false, false)
				p.complete(rsaLeaf, false, false, false)
				status, _ := p.rpc('W', make([]byte, 1164))
				if status != -1 {
					t.Fatal("oversize write")
				}
				p.want('W', []byte("native application"), 0, nil)
				p.want('W', []byte("second queued"), 2, nil)
				waiting := p.protect(23, []byte("wait for send"), 8)
				p.want('R', waiting, 2, nil)
				if !bytes.Equal(p.decrypt(p.outgoing(), true), []byte("native application")) {
					t.Fatal("native application write")
				}
				p.want('R', waiting, 0, append([]byte{0, 13}, []byte("wait for send")...))
				first, second := p.protect(23, []byte("first"), 10), p.protect(23, []byte("second"), 9)
				p.want('R', append(bytes.Clone(first), second...), 0, []byte("\x00\x05first\x00\x06second"))
				p.want('R', append(bytes.Clone(first), second...), 0, nil)
				valid := p.protect(23, []byte("after bad tag"), 11)
				bad := bytes.Clone(valid)
				bad[len(bad)-1] ^= 1
				p.want('R', bad, 0, nil)
				p.want('R', valid, 0, []byte("\x00\x0dafter bad tag"))
				p.want('R', p.protect(23, nil, 12), 0, []byte{0, 0})
				p.want('O', nil, 0, nil)
				status, close := p.rpc('N', nil)
				if status != 0 || !bytes.Equal(p.decrypt(close, true), []byte{1, 0}) {
					t.Fatal("close_notify")
				}
				p.want('C', nil, 2, nil)
				p.want('S', []byte{1}, 0, nil)
				if p.phase != wireClosed || p.flags&8 == 0 {
					t.Fatal("authenticated close")
				}
				p.want('C', nil, 0, nil)
				if p.refs != 0 {
					t.Fatal("close retained policy")
				}
			})
		}
	})
	t.Run("cookie_and_fragment_loss", func(t *testing.T) {
		p := newWirePeer(t, c, "localhost", "accept", "test", nil, false, false)
		p.complete(false, true, true, true)
	})
	t.Run("negotiation_rejections", func(t *testing.T) {
		for _, failure := range []string{"no_ems", "no_alpn", "duplicate_ems", "unoffered", "bad_alpn", "cipher", "compression", "signature", "signed_random", "wrong_signer", "point"} {
			t.Run(failure, func(t *testing.T) {
				p := newWirePeer(t, c, "localhost", "accept", "test", nil, false, false)
				p.start(false)
				if p.flight(false, failure, false, nil) >= 0 || p.phase != wireFailed || p.checks != 0 || p.flags&8 == 0 {
					t.Fatal("invalid negotiation published state")
				}
			})
		}
	})
	t.Run("certificate_rejections", func(t *testing.T) {
		for _, failure := range []string{"wrong_root", "expired", "future", "purpose", "key_usage", "critical", "constraints", "hostname"} {
			t.Run(failure, func(t *testing.T) {
				hostname := "localhost"
				if failure == "hostname" {
					hostname = "wrong.example"
				}
				p := newWirePeer(t, c, hostname, "accept", "test", nil, false, false)
				p.start(false)
				if p.flight(false, failure, false, nil) >= 0 || p.phase != wireFailed || p.verify == 0 || p.checks != 0 || p.flags&8 == 0 {
					t.Fatal("certificate admitted")
				}
			})
		}
	})
	t.Run("fatal_plaintext", func(t *testing.T) {
		for i, failure := range []string{"signature", "wrong_root", "no_ems"} {
			t.Run(failure, func(t *testing.T) {
				p := newWirePeer(t, c, "localhost", "accept", "test", nil, false, false)
				p.start(false)
				status := p.flight(false, failure, false, nil)
				p.fatal(status, []byte{51, 46, 40}[i], 0, false, false, true)
			})
		}
	})
	t.Run("fatal_encrypted", func(t *testing.T) {
		for i, options := range [][3]bool{{false, false, true}, {true, false, true}, {false, true, true}, {true, false, false}} {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				policy := "accept"
				if options[0] {
					policy = "reject"
				}
				p := newWirePeer(t, c, "localhost", policy, "test", nil, false, true)
				p.start(false)
				if p.flight(false, "", false, nil) != 0 {
					t.Fatal("flight")
				}
				p.clientFlight(false)
				status := p.finish(false, !options[0])
				description := byte(51)
				if options[0] {
					description = 49
				}
				p.fatal(status, description, 1, true, options[1], options[2])
			})
		}
	})
	t.Run("peer_fatal", func(t *testing.T) {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
				p := newWirePeer(t, c, "localhost", "accept", "test", nil, false, true)
				p.start(false)
				var status int32
				if encrypted {
					if p.flight(false, "", false, nil) != 0 {
						t.Fatal("flight")
					}
					p.clientFlight(false)
					if p.finish(false, false) != 0 {
						t.Fatal("finish")
					}
					status, _ = p.receive([]byte{2, 40}, 21)
					if status != 0 || p.phase != wireReady {
						t.Fatal("plaintext killed ready")
					}
					packet := p.protect(21, []byte{2, 40})
					bad := bytes.Clone(packet)
					bad[len(bad)-1] ^= 1
					p.want('R', bad, 0, nil)
					if p.phase != wireReady {
						t.Fatal("forged fatal")
					}
					status, _ = p.rpc('R', packet)
				} else {
					status, _ = p.receive([]byte{2, 40}, 21)
				}
				if status >= 0 || p.flags&8 == 0 {
					t.Fatal("peer fatal")
				}
				p.want('Q', nil, 0, []byte{0, 40, 0, 0, 0, 0})
				p.want('N', nil, status, nil)
			})
		}
	})
	t.Run("old_plaintext_handshake", func(t *testing.T) {
		for i, payload := range [][]byte{{1}, wireMessage(0, 0, nil), wireMessage(14, 4, nil)} {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				p := newWirePeer(t, c, "localhost", "accept", "test", nil, false, false)
				p.complete(false, false, false, false)
				if status, _ := p.receive(payload, 22); status < 0 || p.phase != wireReady {
					t.Fatal("old handshake")
				}
				p.want('R', p.protect(23, []byte("alive")), 0, []byte("\x00\x05alive"))
				if status, _ := p.rpc('R', p.protect(22, []byte{1})); status >= 0 || p.phase != wireFailed {
					t.Fatal("authenticated malformed handshake")
				}
			})
		}
	})
	t.Run("exporter", func(t *testing.T) {
		for _, terminal := range []string{"disabled", "close", "abort", "bad_finished", "policy"} {
			t.Run(terminal, func(t *testing.T) {
				enabled := terminal != "disabled"
				policy := "accept"
				if terminal == "policy" {
					policy = "reject"
				}
				p := newWirePeer(t, c, "localhost", policy, "test", nil, false, enabled)
				request := exportRequest([]byte("EXPERIMENTAL-salts-dtls"), nil, false, 65)
				p.want('E', request, -5, nil)
				p.start(false)
				if p.flight(true, "", false, nil) != 0 {
					t.Fatal("flight")
				}
				p.clientFlight(true)
				p.want('E', request, -5, nil)
				status := p.finish(false, terminal == "bad_finished")
				if terminal == "bad_finished" || terminal == "policy" {
					if status >= 0 || p.flags&8 == 0 {
						t.Fatal("failure retained exporter")
					}
					p.want('E', request, -5, nil)
					return
				}
				if status != 0 || (p.flags&32 != 0) == enabled {
					t.Fatal("export retention")
				}
				if enabled {
					p.checkExports()
				} else {
					p.want('E', request, -5, nil)
				}
				p.want('W', []byte("pending application"), 0, nil)
				status, _ = p.rpc('N', nil)
				if status != 0 {
					t.Fatal("prepare")
				}
				if enabled {
					p.checkExports()
				}
				p.want('S', []byte{1}, 0, nil)
				op := byte('O')
				if terminal == "abort" {
					op = 'A'
				}
				p.want(op, nil, 0, nil)
				if p.flags&32 == 0 {
					t.Fatal("terminal master erasure")
				}
				p.want('E', request, -5, nil)
				if op == 'O' {
					p.outgoing()
				}
			})
		}
	})
	t.Run("requested_credentials", func(t *testing.T) {
		for _, rsaLeaf := range []bool{false, true} {
			for _, object := range []bool{false, true} {
				t.Run(fmt.Sprint(rsaLeaf, object), func(t *testing.T) {
					identity := c.leaf(t, rsaLeaf, "", true)
					p := newWirePeer(t, c, "localhost", "accept", "test", &identity, object, false)
					p.start(false)
					request := certRequest([]byte{1, 64}, []byte{4, 3, 4, 1}, encodedName(c.root.RawSubject))
					if p.flight(!rsaLeaf, "", object, request) != 0 {
						t.Fatal("request")
					}
					p.authenticatedFlight(identity, true, true)
					if p.finish(true, false) != 0 || p.phase != wireReady || p.checks != 1 || p.flags&64 == 0 {
						t.Fatal("credential admission")
					}
				})
			}
		}
	})
	t.Run("issuer_hints", func(t *testing.T) {
		identity := c.leaf(t, false, "intermediate", true)
		for i, name := range [][]byte{c.root.RawSubject, identity.certs[1].RawSubject} {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				p := newWirePeer(t, c, "localhost", "accept", "test", &identity, false, false)
				p.start(false)
				if p.flight(false, "", false, certRequest([]byte{1, 64}, []byte{4, 3, 4, 1}, encodedName(name))) != 0 {
					t.Fatal("request")
				}
				p.authenticatedFlight(identity, true, false)
				if p.finish(false, false) != 0 {
					t.Fatal("CA hint")
				}
			})
		}
	})
	t.Run("unsuitable_credentials", func(t *testing.T) {
		name, err := asn1.Marshal(pkix.Name{CommonName: "other issuer"}.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}
		requests := [][]byte{certRequest([]byte{1}, []byte{4, 3, 4, 1}, nil), certRequest([]byte{1, 64}, []byte{4, 1}, nil), certRequest([]byte{1, 64}, []byte{4, 3, 4, 1}, encodedName(name)), standardRequest(), certRequest([]byte{1, 64}, []byte{4, 1}, nil)}
		for i, request := range requests {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				identity := c.leaf(t, i == 4, "purpose", false)
				ptr := &identity
				if i == 3 {
					ptr = nil
				}
				p := newWirePeer(t, c, "localhost", "accept", "test", ptr, false, false)
				p.start(false)
				if p.flight(false, "", false, request) != 0 {
					t.Fatal("request")
				}
				p.authenticatedFlight(identity, false, false)
				if p.finish(false, false) != 0 || p.phase != wireReady {
					t.Fatal("optional identity")
				}
			})
		}
	})
	t.Run("unused_identity", func(t *testing.T) {
		identity := c.leaf(t, false, "purpose", false)
		p := newWirePeer(t, c, "localhost", "accept", "test", &identity, false, false)
		p.complete(false, false, false, false)
		if p.flags&64 == 0 || p.flags&128 != 0 {
			t.Fatal("unused identity retained/sent")
		}
	})
	t.Run("malformed_requests", func(t *testing.T) {
		names := encodedName(c.root.RawSubject)
		requests := [][]byte{{}, {0, 0, 2, 4, 3, 0, 0}, certRequest([]byte{1, 64}, []byte{4}, nil), certRequest([]byte{1, 64}, nil, nil), certRequest([]byte{1, 64}, []byte{4, 3, 4, 1}, []byte{0, 4, 48, 0}), certRequest([]byte{1, 64}, []byte{4, 3, 4, 1}, append(bytes.Clone(names), 0, 1, 255)), append(standardRequest(), 0), certRequest([]byte{1, 64}, []byte{4, 3, 4, 1}, append(bytes.Clone(names), 0, 4, 48, 2, 5, 0))}
		for i, request := range requests {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				identity := c.leaf(t, false, "purpose", false)
				p := newWirePeer(t, c, "localhost", "accept", "test", &identity, false, false)
				p.start(false)
				if p.flight(false, "", false, request) >= 0 || p.phase != wireFailed || p.checks != 0 || p.flags&64 == 0 || p.flags&8 == 0 {
					t.Fatal("malformed request admitted")
				}
			})
		}
	})
	t.Run("duplicate_request", func(t *testing.T) {
		identity := c.leaf(t, false, "", true)
		p := newWirePeer(t, c, "localhost", "accept", "test", &identity, false, false)
		p.start(false)
		if p.flight(false, "duplicate_request", false, standardRequest()) >= 0 || p.phase != wireFailed || p.flags&64 == 0 {
			t.Fatal("duplicate request")
		}
	})
	t.Run("abort_borrow", func(t *testing.T) {
		for _, credential := range []bool{false, true} {
			t.Run(fmt.Sprint(credential), func(t *testing.T) {
				identity := c.leaf(t, false, "purpose", false)
				var ptr *wireIdentity
				if credential {
					ptr = &identity
				}
				p := newWirePeer(t, c, "localhost", "accept", "test", ptr, false, false)
				if credential {
					p.start(false)
					if p.flight(false, "", false, standardRequest()) != 0 {
						t.Fatal("request")
					}
				} else {
					p.complete(false, false, false, false)
					p.want('W', []byte("pending private payload"), 0, nil)
				}
				status, wire := p.rpc('N', nil)
				if status != 0 {
					t.Fatal("borrow")
				}
				if credential {
					if wire[13] != 11 || p.flags&64 == 0 {
						t.Fatal("credential borrow")
					}
					p.want('R', wireRecord(20, 8, []byte{1}, 0), 2, nil)
				} else if !bytes.Equal(p.decrypt(wire, true), []byte("pending private payload")) {
					t.Fatal("application borrow")
				}
				p.want('C', nil, 2, nil)
				p.want('A', nil, 0, wire)
				if p.flags&8 == 0 || p.flags&1 == 0 {
					t.Fatal("abort erased borrow")
				}
				p.want('C', nil, 2, nil)
				p.want('S', []byte{1}, -5, nil)
				p.want('C', nil, 0, nil)
				if p.refs != 0 {
					t.Fatal("abort ref")
				}
			})
		}
	})
	t.Run("cookie_sequence_and_fast_retry", func(t *testing.T) {
		for _, newSequence := range []bool{false, true} {
			t.Run(fmt.Sprint(newSequence), func(t *testing.T) {
				p := newWirePeer(t, c, "localhost", "accept", "test", nil, false, false)
				p.start(false)
				old := p.hello
				body := old[12:]
				cookie := body[36 : 36+int(body[35])]
				seq := uint16(0)
				if newSequence {
					seq = 1
				}
				status, _ := p.receive(wireMessage(3, seq, append([]byte{0xfe, 0xfd, byte(len(cookie))}, cookie...)), 22)
				if status != 0 {
					t.Fatal("cookie")
				}
				_, _, _, repeated := wireUnpack(t, p.outgoing())
				if newSequence {
					if binary.BigEndian.Uint16(repeated[4:6]) != 2 || !bytes.Equal(repeated[12:], body) {
						t.Fatal("challenge sequence")
					}
					return
				}
				if !bytes.Equal(repeated, old) {
					t.Fatal("cookie retransmission")
				}
				if p.flight(false, "", false, nil) != 0 {
					t.Fatal("flight")
				}
				p.clientFlight(false)
				last := p.nativeFinished
				status, _ = p.receive(wireMessage(14, 4, nil), 22)
				if status != 0 {
					t.Fatal("fast retry")
				}
				p.clientFlight(false)
				if bytes.Equal(last[5:11], p.nativeFinished[5:11]) || p.finish(false, false) != 0 {
					t.Fatal("retry record sequence")
				}
			})
		}
	})
	t.Run("optional_alpn_intermediate", func(t *testing.T) {
		for _, invalid := range []bool{false, true} {
			t.Run(fmt.Sprint(invalid), func(t *testing.T) {
				p := newWirePeer(t, c, "localhost", "accept", "", nil, false, false)
				p.start(false)
				failure := "intermediate"
				if invalid {
					failure = "unoffered_alpn"
				}
				status := p.flight(false, failure, true, nil)
				if invalid {
					if status >= 0 || p.phase != wireFailed {
						t.Fatal("unoffered ALPN")
					}
					return
				}
				if status != 0 {
					t.Fatal("intermediate")
				}
				p.clientFlight(false)
				if p.finish(false, false) != 0 || p.phase != wireReady {
					t.Fatal("optional ALPN")
				}
			})
		}
	})
	t.Run("finished_fragments_and_forged_tags", func(t *testing.T) {
		for _, mode := range []string{"fragments", "wrong_size", "forged_tag"} {
			t.Run(mode, func(t *testing.T) {
				p := newWirePeer(t, c, "localhost", "accept", "test", nil, false, false)
				p.start(false)
				if mode == "forged_tag" {
					if status, _ := p.receive(wireMessage(20, 5, make([]byte, 12)), 22); status != 0 {
						t.Fatal("plaintext Finished")
					}
				}
				if p.flight(false, "", false, nil) != 0 {
					t.Fatal("flight")
				}
				p.clientFlight(false)
				if mode == "wrong_size" {
					status, _ := p.rpc('R', p.protect(22, wireMessage(20, 5, append(bytes.Clone(p.proof), 0))))
					if status >= 0 || p.phase != wireFailed || p.flags&8 == 0 || p.checks != 0 {
						t.Fatal("wrong Finished size")
					}
					return
				}
				if mode == "fragments" {
					for _, span := range [][2]int{{6, 6}, {0, 8}} {
						fragment := append(wireHeader(20, 5, 12, span[0], span[1]), p.proof[span[0]:span[0]+span[1]]...)
						p.want('R', p.protect(22, fragment), 0, nil)
						if p.phase != wireFinished || p.checks != 0 {
							t.Fatal("CCS fragment gate")
						}
					}
					if p.flags&4 == 0 {
						t.Fatal("missing pending proof")
					}
					if status, _ := p.receive([]byte{1}, 20); status != 0 {
						t.Fatal("CCS")
					}
				} else {
					valid := p.protect(22, wireMessage(20, 5, p.proof))
					bad := bytes.Clone(valid)
					bad[len(bad)-1] ^= 1
					p.want('R', bad, 0, nil)
					if p.phase != wireFinished || p.checks != 0 {
						t.Fatal("forged proof")
					}
					if status, _ := p.receive([]byte{1}, 20); status != 0 {
						t.Fatal("CCS")
					}
					p.want('R', valid, 0, nil)
					application := p.protect(23, []byte("atomic framing"))
					p.want('R', append(bytes.Clone(application), 23), 3, nil)
					p.want('R', application, 0, []byte("\x00\x0eatomic framing"))
				}
				if p.phase != wireReady || p.checks != 1 {
					t.Fatal("Finished admission")
				}
			})
		}
	})
}
