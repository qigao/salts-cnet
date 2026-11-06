package shangmiinterop

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/iuboy/pollux-go/tls13gm"
)

// The independent handshaker/primitives own key exchange, transcript, certificate
// and Finished verification. This test adapter supplies bounded TLS TCP records;
// no production GmSSL or Core crypto entrypoint is used on this side.
type recordPeer struct {
	net.Conn
	authFlightSent          bool
	readCipher, writeCipher *tls13gm.AEAD
	readSeq, writeSeq       uint64
	readSecret, writeSecret []byte
	altered                 bool
	pending                 []byte
}

func recordCipher(secret []byte) (*tls13gm.AEAD, error) {
	if len(secret) != 32 {
		return nil, errors.New("missing traffic secret")
	}
	key, err := tls13gm.HKDFExpandLabel(secret, "key", nil, 16)
	if err != nil {
		return nil, err
	}
	iv, err := tls13gm.HKDFExpandLabel(secret, "iv", nil, 12)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	defer clear(iv)
	return tls13gm.NewAEAD(key, iv)
}

func (p *recordPeer) keys(read, write []byte) error {
	var err error
	if len(p.pending) != 0 {
		return errors.New("unconsumed handshake at key transition")
	}
	p.readCipher, err = recordCipher(read)
	if err != nil {
		return err
	}
	p.writeCipher, err = recordCipher(write)
	if err != nil {
		return err
	}
	p.readSeq, p.writeSeq = 0, 0
	clear(p.readSecret)
	clear(p.writeSecret)
	p.readSecret, p.writeSecret = bytes.Clone(read), bytes.Clone(write)
	return nil
}

func (p *recordPeer) clearSecrets() { clear(p.readSecret); clear(p.writeSecret) }

func (p *recordPeer) sendKeyUpdate(request byte) error {
	if err := p.send(22, []byte{24, 0, 0, 1, request}); err != nil {
		return err
	}
	return p.advanceWriteKey()
}

func (p *recordPeer) advanceWriteKey() error {
	next, err := tls13gm.HKDFExpandLabel(p.writeSecret, "traffic upd", nil, 32)
	if err != nil {
		return err
	}
	p.writeCipher, err = recordCipher(next)
	if err != nil {
		clear(next)
		return err
	}
	clear(p.writeSecret)
	p.writeSecret, p.writeSeq = next, 0
	return nil
}

func (p *recordPeer) receiveKeyUpdate() error {
	return p.receiveKeyUpdateRequest(0)
}

func (p *recordPeer) receiveKeyUpdateRequest(request byte) error {
	kind, data, err := p.record()
	if err != nil {
		return err
	}
	if kind != 22 {
		return fmt.Errorf("expected KeyUpdate, got %d: %x", kind, data)
	}
	return p.consumeKeyUpdate(data, request)
}

func (p *recordPeer) consumeKeyUpdate(data []byte, request byte) error {
	if !bytes.Equal(data, []byte{24, 0, 0, 1, request}) {
		return fmt.Errorf("unexpected KeyUpdate payload: %x", data)
	}
	next, err := tls13gm.HKDFExpandLabel(p.readSecret, "traffic upd", nil, 32)
	if err != nil {
		return err
	}
	p.readCipher, err = recordCipher(next)
	if err != nil {
		clear(next)
		return err
	}
	clear(p.readSecret)
	p.readSecret, p.readSeq = next, 0
	return nil
}

func (p *recordPeer) send(kind byte, payload []byte) error {
	if len(payload) > 16384 {
		return errors.New("test record exceeds plaintext limit")
	}
	header := []byte{kind, 3, 3, 0, 0}
	if p.writeCipher != nil {
		header[0] = 23
		plain := append(bytes.Clone(payload), kind)
		binary.BigEndian.PutUint16(header[3:], uint16(len(plain)+p.writeCipher.Overhead()))
		var err error
		payload, err = p.writeCipher.Seal(p.writeSeq, plain, header)
		if err != nil {
			return err
		}
		p.writeSeq++
	} else {
		binary.BigEndian.PutUint16(header[3:], uint16(len(payload)))
	}
	data := append(header, payload...)
	for len(data) != 0 {
		n, err := p.Conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		data = data[n:]
	}
	return nil
}

func (p *recordPeer) record() (byte, []byte, error) {
	for skipped := 0; skipped < 4; skipped++ {
		var header [5]byte
		if _, err := io.ReadFull(p.Conn, header[:]); err != nil {
			return 0, nil, err
		}
		n := int(binary.BigEndian.Uint16(header[3:]))
		if header[1] != 3 || (header[2] != 1 && header[2] != 3) || n == 0 || n > 16640 {
			return 0, nil, errors.New("invalid TLS record header")
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(p.Conn, data); err != nil {
			return 0, nil, err
		}
		kind := header[0]
		if kind == 20 && bytes.Equal(data, []byte{1}) {
			continue
		}
		if p.readCipher != nil {
			if kind != 23 {
				return 0, nil, fmt.Errorf("expected encrypted record, got %d: %x", kind, data)
			}
			var err error
			data, err = p.readCipher.Open(p.readSeq, data, header[:])
			if err != nil {
				return 0, nil, err
			}
			p.readSeq++
			for len(data) != 0 && data[len(data)-1] == 0 {
				data = data[:len(data)-1]
			}
			if len(data) == 0 {
				return 0, nil, errors.New("missing inner content type")
			}
			kind, data = data[len(data)-1], data[:len(data)-1]
		}
		return kind, data, nil
	}
	return 0, nil, errors.New("too many compatibility CCS records")
}

func (p *recordPeer) handshake() ([]byte, error) {
	for {
		if len(p.pending) >= 4 {
			n := int(p.pending[1])<<16 | int(p.pending[2])<<8 | int(p.pending[3])
			if n > 65536 {
				return nil, errors.New("oversized handshake")
			}
			if len(p.pending) >= n+4 {
				msg := bytes.Clone(p.pending[:n+4])
				p.pending = p.pending[n+4:]
				return msg, nil
			}
		}
		kind, data, err := p.record()
		if err != nil {
			return nil, err
		}
		if kind != 22 {
			return nil, fmt.Errorf("expected handshake, got %d: %x", kind, data)
		}
		if len(p.pending)+len(data) > 65540 {
			return nil, errors.New("handshake buffer limit")
		}
		p.pending = append(p.pending, data...)
	}
}

func (p *recordPeer) expect(kind byte, data []byte) error {
	actualKind, actual, err := p.record()
	if err != nil {
		return err
	}
	if actualKind != kind || !bytes.Equal(actual, data) {
		return fmt.Errorf("unexpected record type=%d data=%x, want type=%d data=%x", actualKind, actual, kind, data)
	}
	return nil
}

func alterClientHello(msg []byte, scenario string) error {
	if len(msg) < 38 || msg[0] != 1 {
		return errors.New("missing ClientHello")
	}
	data := msg[38:]
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
	if _, err := vector(1); err != nil {
		return err
	}
	ciphers, err := vector(2)
	if err != nil {
		return err
	}
	if scenario == "standard_cipher" {
		if !bytes.Equal(ciphers, []byte{0, 0xc6}) {
			return errors.New("unexpected cipher offer")
		}
		copy(ciphers, []byte{0x13, 1})
		return nil
	}
	if _, err = vector(1); err != nil {
		return err
	}
	extensions, err := vector(2)
	if err != nil || len(data) != 0 {
		return errors.New("invalid extension vector")
	}
	data = extensions
	for len(data) != 0 {
		if len(data) < 2 {
			return io.ErrUnexpectedEOF
		}
		kind := binary.BigEndian.Uint16(data)
		data = data[2:]
		ext, err := vector(2)
		if err != nil {
			return err
		}
		switch {
		case scenario == "tls12_version" && kind == 43:
			if !bytes.Equal(ext, []byte{2, 3, 4}) {
				return errors.New("unexpected version offer")
			}
			ext[2] = 3
			return nil
		case scenario == "tlcp_signature" && kind == 13:
			if !bytes.Equal(ext, []byte{0, 2, 7, 8}) {
				return errors.New("unexpected signature offer")
			}
			ext[3] = 4
			return nil
		case scenario == "p256_group" && kind == 10:
			if !bytes.Equal(ext, []byte{0, 2, 0, 41}) {
				return errors.New("unexpected group offer")
			}
			ext[3] = 23
			return nil
		case scenario == "invalid_point" && kind == 51:
			if len(ext) != 71 || ext[6] != 4 {
				return errors.New("unexpected key share")
			}
			clear(ext[7:])
			return nil
		}
	}
	return errors.New("missing mutation target")
}

func (p *recordPeer) client(cfg tls13gm.ClientConfig, corrupt string) error {
	h, err := tls13gm.NewClientHandshakerWithConfig(cfg)
	if err != nil {
		return err
	}
	defer h.Zero()
	defer func() { secrets := h.Secrets(); secrets.ZeroAll() }()
	ch, err := h.ClientHello()
	if err != nil {
		return err
	}
	if corrupt != "" && corrupt != "finished" {
		if err = alterClientHello(ch, corrupt); err != nil {
			return err
		}
		p.altered = true
	}
	if err = p.send(22, ch); err != nil {
		return err
	}
	sh, err := p.handshake()
	if err != nil {
		return err
	}
	if err = h.HandleServerHello(sh); err != nil {
		return err
	}
	secrets := h.Secrets()
	if err = p.keys(secrets.ServerHandshakeTrafficSecret, secrets.ClientHandshakeTrafficSecret); err != nil {
		return err
	}
	for _, process := range []func([]byte) error{h.HandleEncryptedExtensions, h.HandleCertificate, h.HandleCertificateVerify, h.HandleServerFinished} {
		msg, err := p.handshake()
		if err != nil {
			return err
		}
		if err = process(msg); err != nil {
			return err
		}
	}
	finished, err := h.ClientFinished()
	if err != nil {
		return err
	}
	if corrupt == "finished" {
		finished[len(finished)-1] ^= 1
		p.altered = true
	}
	if err = p.send(22, finished); err != nil {
		return err
	}
	secrets = h.Secrets()
	return p.keys(secrets.ServerApplicationTrafficSecret, secrets.ClientApplicationTrafficSecret)
}

func (p *recordPeer) server(cfg tls13gm.ServerConfig, corrupt string) error {
	h, err := tls13gm.NewServerHandshakerWithConfig(cfg)
	if err != nil {
		return err
	}
	defer h.Zero()
	defer func() { secrets := h.Secrets(); secrets.ZeroAll() }()
	ch, err := p.handshake()
	if err != nil {
		return err
	}
	if err = h.HandleClientHello(ch); err != nil {
		return err
	}
	sh, ee, cert, cv, fin, err := h.ServerFlight()
	if err != nil {
		return err
	}
	if err = p.send(22, sh); err != nil {
		return err
	}
	secrets := h.Secrets()
	if err = p.keys(secrets.ClientHandshakeTrafficSecret, secrets.ServerHandshakeTrafficSecret); err != nil {
		return err
	}
	if corrupt == "certificate_verify" {
		cv[len(cv)-1] ^= 1
	}
	if corrupt == "finished" {
		fin[len(fin)-1] ^= 1
	}
	for _, msg := range [][]byte{ee, cert, cv, fin} {
		for len(msg) != 0 {
			n := len(msg)
			if corrupt == "fragmented" && n > 7 {
				n = 7
			}
			if err = p.send(22, msg[:n]); err != nil {
				return err
			}
			msg = msg[n:]
		}
	}
	finished, err := p.handshake()
	if err != nil {
		return err
	}
	if err = h.HandleClientFinished(finished); err != nil {
		return err
	}
	secrets = h.Secrets()
	return p.keys(secrets.ClientApplicationTrafficSecret, secrets.ServerApplicationTrafficSecret)
}
