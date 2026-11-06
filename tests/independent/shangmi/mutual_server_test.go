package shangmiinterop

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	peersm2 "github.com/iuboy/pollux-go/sm2"
	"github.com/iuboy/pollux-go/tls13gm"
	"golang.org/x/crypto/cryptobyte"
)

// Reverse of the finite independent client: require and authenticate the
// native client's certificate, possession signature and Finished before data.
func (p *recordPeer) mutualServer(server, client fixture, scenario string) error {
	waitAfterRequest := scenario == "malformed_ca_early_reject" || scenario == "malformed_ca_no_signature_match_early_reject"
	if waitAfterRequest {
		scenario = strings.TrimSuffix(scenario, "_early_reject")
	}
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
	body, err := receive(1)
	if err != nil {
		return err
	}
	s := cryptobyte.String(body)
	var version uint16
	var random []byte
	var sid, ciphers, compression cryptobyte.String
	if !s.ReadUint16(&version) || version != 0x0303 || !s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&sid) || len(sid) > 32 || !s.ReadUint16LengthPrefixed(&ciphers) ||
		!hasScheme(ciphers, 0x00c6) || !s.ReadUint8LengthPrefixed(&compression) || !bytes.Equal(compression, []byte{0}) {
		return errors.New("invalid native ClientHello")
	}
	ext, err := mutualExtensions(s)
	if err != nil {
		return err
	}
	versions := cryptobyte.String(ext[43])
	var offered cryptobyte.String
	if !versions.ReadUint8LengthPrefixed(&offered) || !versions.Empty() || !hasScheme(offered, 0x0304) {
		return errors.New("TLS 1.3 not offered")
	}
	for _, required := range []struct{ extension, value uint16 }{{10, 41}, {13, 0x0708}} {
		list := cryptobyte.String(ext[required.extension])
		if !list.ReadUint16LengthPrefixed(&offered) || !list.Empty() || !hasScheme(offered, required.value) {
			return errors.New("ShangMi group/signature not offered")
		}
	}
	shares := cryptobyte.String(ext[51])
	var entries cryptobyte.String
	if !shares.ReadUint16LengthPrefixed(&entries) || !shares.Empty() {
		return errors.New("invalid key share vector")
	}
	var peerShare []byte
	for !entries.Empty() {
		var group uint16
		var share cryptobyte.String
		if !entries.ReadUint16(&group) || !entries.ReadUint16LengthPrefixed(&share) {
			return errors.New("truncated key share")
		}
		if group == 41 {
			if peerShare != nil {
				return errors.New("duplicate SM2 key share")
			}
			peerShare = share
		}
	}
	peerKey, err := peersm2.UnmarshalUncompressed(peerShare)
	if err != nil {
		return err
	}
	transcript.AddMessage(1, body)
	ephemeral, err := tls13gm.GenerateCurveSM2KeyPair(rand.Reader)
	if err != nil {
		return err
	}
	defer ephemeral.D.SetInt64(0)
	shared, err := tls13gm.CurveSM2ECDHE(ephemeral, peerKey)
	if err != nil {
		return err
	}
	defer clear(shared)
	sh := &tls13gm.ServerHelloMsg{LegacyVersion: 0x0303, LegacySessionID: sid, CipherSuite: 0x00c6,
		Extensions: []tls13gm.Extension{{Type: 43, Data: []byte{3, 4}},
			{Type: 51, Data: append([]byte{0, 41, 0, 65}, peersm2.MarshalUncompressed(&ephemeral.PublicKey)...)}}}
	if _, err = rand.Read(sh.Random[:]); err != nil {
		return err
	}
	msg, err := tls13gm.MarshalHandshakeMessage(sh)
	if err != nil {
		return err
	}
	if err = send(msg); err != nil {
		return err
	}
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
	if err = p.keys(clientHS, serverHS); err != nil {
		return err
	}
	msg, err = tls13gm.MarshalHandshakeMessage(&tls13gm.EncryptedExtensionsMsg{})
	if err != nil {
		return err
	}
	if err = send(msg); err != nil {
		return err
	}
	// Initial CertificateRequest: empty context, signature_algorithms = SM2.
	request := []byte{0, 0, 8, 0, 13, 0, 4, 0, 2, 7, 8}
	if scenario == "client_ca" || scenario == "malformed_ca" || scenario == "malformed_ca_no_signature_match" {
		name := client.root.RawSubject
		// certificate_authorities: vector<DistinguishedName<1..2^16-1>>.
		names := append([]byte{byte(len(name) >> 8), byte(len(name))}, name...)
		if scenario != "client_ca" {
			names = append(names, 0, 1, 0)
		}
		if scenario == "malformed_ca_no_signature_match" {
			request[9], request[10] = 8, 4
		}
		data := append([]byte{byte(len(names) >> 8), byte(len(names))}, names...)
		ext := append([]byte{0, 47, byte(len(data) >> 8), byte(len(data))}, data...)
		request = append(request, ext...)
		request[1], request[2] = byte((len(request)-3)>>8), byte(len(request)-3)
	}
	switch scenario {
	case "request_context":
		request = append([]byte{1, 1}, request[1:]...)
	case "missing_signature":
		request = []byte{0, 0, 0}
	case "duplicate_signature":
		request = append([]byte{0, 0, 16}, append(bytes.Clone(request[3:]), request[3:]...)...)
	}
	if err = send(append([]byte{13, byte(len(request) >> 16), byte(len(request) >> 8), byte(len(request))}, request...)); err != nil {
		return err
	}
	// The exact negative stimulus is the emitted CertificateRequest, not a
	// later certificate/signature flight that the client need not wait for.
	if scenario == "request_context" || scenario == "missing_signature" || scenario == "duplicate_signature" ||
		scenario == "malformed_ca" || scenario == "malformed_ca_no_signature_match" {
		p.authFlightSent = true
	}
	if waitAfterRequest {
		// Send no certificate tail and keep TCP open: a correct client must
		// reject this request itself, rather than fail on EOF or a later input.
		kind, data, readErr := p.record()
		if readErr != nil {
			var transport *net.OpError
			// A clean abrupt close is permitted. A received record's bad MAC,
			// malformed framing or truncation is never evidence of a valid alert.
			p.earlyRejectionObserved = errors.Is(readErr, io.EOF) ||
				(errors.As(readErr, &transport) && transport.Op == "read" && !transport.Timeout())
			return readErr
		}
		p.earlyRejectionObserved = kind == 21 && bytes.Equal(data, []byte{2, 50})
		return errors.New("native peer must reject malformed CA names with an authenticated decode_error alert")
	}
	msg, err = tls13gm.MarshalHandshakeMessage(&tls13gm.CertificateMsg{CertificateList: []tls13gm.CertificateEntry{{Certificate: server.leaf.Raw}}})
	if err != nil {
		return err
	}
	if err = send(msg); err != nil {
		return err
	}
	if scenario == "" {
		p.authFlightSent = true
	}
	context := tls13gm.ServerCertificateVerifyContext
	if scenario == "client_context" {
		context = tls13gm.ClientCertificateVerifyContext
	}
	signature, err := tls13gm.SignCertificateVerify(server.key, context, transcript.Sum())
	if err != nil {
		return err
	}
	if scenario == "certificate_id" {
		signature, err = peersm2.SignWithSM2(rand.Reader, server.key, []byte(tls13gm.SM2IDCertificateVerify), tls13gm.BuildCertificateVerifyInput(context, transcript.Sum()))
		if err != nil {
			return err
		}
	}
	if scenario == "certificate_verify" {
		signature[len(signature)-1] ^= 1
	}
	scheme := uint16(0x0708)
	if scenario == "tlcp_signature" {
		scheme = 0x0704
	}
	msg, err = tls13gm.MarshalHandshakeMessage(&tls13gm.CertificateVerifyMsg{SignatureScheme: scheme, Signature: signature})
	if err != nil {
		return err
	}
	if err = send(msg); err != nil {
		return err
	}
	if scenario == "client_context" || scenario == "certificate_id" || scenario == "certificate_verify" || scenario == "tlcp_signature" {
		p.authFlightSent = true
	}
	verifyData, err := mutualFinished(serverHS, transcript.Sum())
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
	p.authFlightSent = true
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
	body, err = receive(11)
	if err != nil {
		return err
	}
	clientKey, err := mutualCertificate(body, client, true)
	if err != nil {
		return err
	}
	transcript.AddMessage(11, body)
	body, err = receive(15)
	if err != nil {
		return err
	}
	s = cryptobyte.String(body)
	var sig cryptobyte.String
	if !s.ReadUint16(&scheme) || scheme != 0x0708 || !s.ReadUint16LengthPrefixed(&sig) || !s.Empty() ||
		!tls13gm.VerifyCertificateVerify(clientKey, tls13gm.ClientCertificateVerifyContext, transcript.Sum(), sig) {
		return errors.New("native client CertificateVerify failed")
	}
	transcript.AddMessage(15, body)
	body, err = receive(20)
	if err != nil {
		return err
	}
	expected, err := mutualFinished(clientHS, transcript.Sum())
	if err != nil {
		return err
	}
	if !hmac.Equal(body, expected) {
		return errors.New("native client Finished failed")
	}
	transcript.AddMessage(20, body)
	return p.keys(clientAP, serverAP)
}

func hasScheme(list cryptobyte.String, want uint16) bool {
	if len(list) == 0 || len(list)%2 != 0 {
		return false
	}
	found := false
	for !list.Empty() {
		var value uint16
		list.ReadUint16(&value)
		found = found || value == want
	}
	return found
}
