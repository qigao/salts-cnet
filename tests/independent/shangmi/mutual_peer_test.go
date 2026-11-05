package shangmiinterop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"

	peersm2 "github.com/iuboy/pollux-go/sm2"
	peerx509 "github.com/iuboy/pollux-go/smx509"
	"github.com/iuboy/pollux-go/tls13gm"
	"golang.org/x/crypto/cryptobyte"
)

// A finite test-only RFC 8446/8998 client: the upstream handshaker has no
// CertificateRequest state. Its independent primitives supply ECDHE, SM3
// transcript/HKDF, SM2 signatures and SM4 records. No Core/GmSSL code is used.
// Only the initial full handshake is admitted; no HRR, PSK or post-handshake auth.
func (p *recordPeer) mutualClient(server, client fixture, scenario string) error {
	transcript := tls13gm.NewTranscript()
	receive := func(kind byte) ([]byte, error) {
		msg, err := p.handshake()
		if err != nil {
			return nil, err
		}
		if msg[0] != kind {
			return nil, fmt.Errorf("expected handshake %d, got %d", kind, msg[0])
		}
		return msg[4:], nil
	}
	send := func(msg []byte) error {
		for remaining := msg; len(remaining) != 0; {
			n := len(remaining)
			if scenario == "fragmented" && p.writeCipher != nil && n > 7 {
				n = 7
			}
			if err := p.send(22, remaining[:n]); err != nil {
				return err
			}
			remaining = remaining[n:]
		}
		transcript.AddMessage(msg[0], msg[4:])
		return nil
	}
	ephemeral, err := tls13gm.GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		return err
	}
	defer ephemeral.D.SetInt64(0)
	share := peersm2.MarshalUncompressed(&ephemeral.PublicKey)
	ch := &tls13gm.ClientHelloMsg{LegacyVersion: 0x0303, CipherSuites: []uint16{0x00c6}, Extensions: []tls13gm.Extension{
		{Type: 43, Data: []byte{2, 3, 4}},
		{Type: 10, Data: []byte{0, 2, 0, 41}},
		{Type: 13, Data: []byte{0, 2, 7, 8}},
		{Type: 51, Data: append([]byte{0, 69, 0, 41, 0, 65}, share...)},
	}}
	if _, err = rand.Read(ch.Random[:]); err != nil {
		return err
	}
	msg, err := tls13gm.MarshalHandshakeMessage(ch)
	if err != nil {
		return err
	}
	if err = send(msg); err != nil {
		return err
	}
	body, err := receive(2)
	if err != nil {
		return err
	}
	s := cryptobyte.String(body)
	var version, cipher uint16
	var compression uint8
	var random []byte
	var sid cryptobyte.String
	if !s.ReadUint16(&version) || version != 0x0303 || !s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&sid) || !sid.Empty() || !s.ReadUint16(&cipher) || cipher != 0x00c6 ||
		!s.ReadUint8(&compression) || compression != 0 {
		return errors.New("invalid ShangMi ServerHello")
	}
	ext, err := mutualExtensions(s)
	if err != nil {
		return err
	}
	keyShare := ext[51]
	if len(ext) != 2 || !bytes.Equal(ext[43], []byte{3, 4}) || len(keyShare) != 69 ||
		!bytes.Equal(keyShare[:4], []byte{0, 41, 0, 65}) {
		return errors.New("invalid server negotiation")
	}
	pub, err := peersm2.UnmarshalUncompressed(keyShare[4:])
	if err != nil {
		return err
	}
	shared, err := tls13gm.CurveSM2ECDHE(ephemeral, pub)
	if err != nil {
		return err
	}
	defer clear(shared)
	transcript.AddMessage(2, body)
	early := tls13gm.DeriveEarlySecret(nil)
	defer clear(early)
	hs, err := tls13gm.DeriveHandshakeSecret(early, shared)
	if err != nil {
		return err
	}
	defer clear(hs)
	master, err := tls13gm.DeriveMasterSecret(hs)
	if err != nil {
		return err
	}
	defer clear(master)
	clientHS, err := tls13gm.DeriveSecret(hs, "c hs traffic", transcript.Sum())
	if err != nil {
		return err
	}
	defer clear(clientHS)
	serverHS, err := tls13gm.DeriveSecret(hs, "s hs traffic", transcript.Sum())
	if err != nil {
		return err
	}
	defer clear(serverHS)
	if err = p.keys(serverHS, clientHS); err != nil {
		return err
	}
	body, err = receive(8)
	if err != nil {
		return err
	}
	ext, err = mutualExtensions(body)
	if err != nil {
		return err
	}
	// supported_groups is permitted in EE; no other extensions were offered
	// that can be acknowledged here (in particular, no ALPN or early data).
	for kind := range ext {
		if kind != 10 {
			return fmt.Errorf("unexpected EE extension %d", kind)
		}
	}
	transcript.AddMessage(8, body)
	body, err = receive(13)
	if err != nil {
		return err
	}
	s = cryptobyte.String(body)
	var context cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&context) || !context.Empty() {
		return errors.New("invalid initial CertificateRequest context")
	}
	ext, err = mutualExtensions(s)
	if err != nil {
		return err
	}
	signatures := cryptobyte.String(ext[13])
	var schemes cryptobyte.String
	if !signatures.ReadUint16LengthPrefixed(&schemes) || !signatures.Empty() || len(schemes)%2 != 0 {
		return errors.New("invalid requested signature list")
	}
	found := false
	for !schemes.Empty() {
		var scheme uint16
		schemes.ReadUint16(&scheme)
		found = found || scheme == 0x0708
	}
	if !found {
		return errors.New("SM2 signature not requested")
	}
	transcript.AddMessage(13, body)
	body, err = receive(11)
	if err != nil {
		return err
	}
	leaf, err := mutualCertificate(body, server, false)
	if err != nil {
		return err
	}
	transcript.AddMessage(11, body)
	body, err = receive(15)
	if err != nil {
		return err
	}
	s = cryptobyte.String(body)
	var scheme uint16
	var signature cryptobyte.String
	if !s.ReadUint16(&scheme) || scheme != 0x0708 || !s.ReadUint16LengthPrefixed(&signature) || !s.Empty() ||
		!tls13gm.VerifyCertificateVerify(leaf, tls13gm.ServerCertificateVerifyContext, transcript.Sum(), signature) {
		return errors.New("server CertificateVerify failed")
	}
	transcript.AddMessage(15, body)
	body, err = receive(20)
	if err != nil {
		return err
	}
	expected, err := mutualFinished(serverHS, transcript.Sum())
	if err != nil {
		return err
	}
	if !hmac.Equal(body, expected) {
		return errors.New("server Finished failed")
	}
	transcript.AddMessage(20, body)
	clientAP, err := tls13gm.DeriveSecret(master, "c ap traffic", transcript.Sum())
	if err != nil {
		return err
	}
	defer clear(clientAP)
	serverAP, err := tls13gm.DeriveSecret(master, "s ap traffic", transcript.Sum())
	if err != nil {
		return err
	}
	defer clear(serverAP)
	cert := &tls13gm.CertificateMsg{}
	if scenario != "missing" {
		cert.CertificateList = []tls13gm.CertificateEntry{{Certificate: client.leaf.Raw}}
	}
	if scenario == "request_context" {
		cert.CertificateRequestContext = []byte{1}
	}
	msg, err = tls13gm.MarshalHandshakeMessage(cert)
	if err != nil {
		return err
	}
	if err = send(msg); err != nil {
		return err
	}
	// This marker proves negative cases reached the authenticated client flight.
	p.authFlightSent = true
	if scenario != "missing" {
		contextString := tls13gm.ClientCertificateVerifyContext
		if scenario == "server_context" {
			contextString = tls13gm.ServerCertificateVerifyContext
		}
		sig, err := tls13gm.SignCertificateVerify(client.key, contextString, transcript.Sum())
		if err != nil {
			return err
		}
		if scenario == "certificate_id" {
			sig, err = peersm2.SignWithSM2(rand.Reader, client.key, []byte(tls13gm.SM2IDCertificateVerify),
				tls13gm.BuildCertificateVerifyInput(contextString, transcript.Sum()))
			if err != nil {
				return err
			}
		}
		if scenario == "certificate_verify" {
			sig[len(sig)-1] ^= 1
		}
		scheme := uint16(0x0708)
		if scenario == "tlcp_signature" {
			scheme = 0x0704
		}
		msg, err = tls13gm.MarshalHandshakeMessage(&tls13gm.CertificateVerifyMsg{SignatureScheme: scheme, Signature: sig})
		if err != nil {
			return err
		}
		if err = send(msg); err != nil {
			return err
		}
	}
	verifyData, err := mutualFinished(clientHS, transcript.Sum())
	if err != nil {
		return err
	}
	if scenario == "finished" {
		verifyData[0] ^= 1
	}
	msg, err = tls13gm.MarshalHandshakeMessage(&tls13gm.FinishedMsg{VerifyData: verifyData})
	if err != nil {
		return err
	}
	if err = send(msg); err != nil {
		return err
	}
	return p.keys(serverAP, clientAP)
}

func mutualFinished(secret, hash []byte) ([]byte, error) {
	key, err := tls13gm.DeriveFinishedKey(secret)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return tls13gm.ComputeFinishedVerifyData(key, hash)
}

func mutualExtensions(data cryptobyte.String) (map[uint16][]byte, error) {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
		return nil, errors.New("invalid extension vector")
	}
	ext := make(map[uint16][]byte)
	for !list.Empty() {
		var kind uint16
		var value cryptobyte.String
		if !list.ReadUint16(&kind) || !list.ReadUint16LengthPrefixed(&value) {
			return nil, errors.New("truncated extension")
		}
		if _, duplicate := ext[kind]; duplicate {
			return nil, errors.New("duplicate extension")
		}
		ext[kind] = value
	}
	return ext, nil
}

func mutualCertificate(body cryptobyte.String, expected fixture, clientAuth bool) (*ecdsa.PublicKey, error) {
	var context, list cryptobyte.String
	if !body.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
		!body.ReadUint24LengthPrefixed(&list) || !body.Empty() || list.Empty() {
		return nil, errors.New("invalid peer certificate list")
	}
	var first []byte
	for count := 0; !list.Empty(); count++ {
		var der, extensions cryptobyte.String
		if count >= 8 || !list.ReadUint24LengthPrefixed(&der) || len(der) == 0 ||
			!list.ReadUint16LengthPrefixed(&extensions) || !extensions.Empty() {
			return nil, errors.New("invalid peer certificate entry")
		}
		if count == 0 {
			first = der
		}
	}
	// The test uses a direct-root leaf; match the independently generated DER
	// in addition to chain, time and DNS verification by the independent library.
	if !bytes.Equal(first, expected.leaf.Raw) {
		return nil, errors.New("unexpected peer identity")
	}
	leaf, err := peerx509.ParseCertificate(first)
	if err != nil {
		return nil, err
	}
	roots := peerx509.NewCertPool()
	roots.AddCert(expected.root)
	opts := peerx509.VerifyOptions{Roots: roots, DNSName: "localhost"}
	if clientAuth {
		opts.DNSName = ""
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("peer certificate does not permit signatures")
	}
	if err = peerx509.Verify(leaf, opts); err != nil {
		return nil, err
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("peer key is not SM2")
	}
	return pub, nil
}
