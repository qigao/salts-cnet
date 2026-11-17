package independent

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"testing"
)

type wireServer struct {
	*wirePeer
	identity                        wireIdentity
	clientHello, finished, expected []byte
}

func newWireServer(t *testing.T, c *wireCredentials, rsaLeaf, object, exporter bool) *wireServer {
	args := []string{"accept", "strict"}
	if exporter {
		args = append(args, "exporter")
	}
	p := &wirePeer{nativeClient: startEndpoint(t, *serverEndpoint, args...), credentials: c, isServer: true}
	identity := c.leaf(t, rsaLeaf, "", false)
	private, err := x509.MarshalPKCS8PrivateKey(identity.key)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 14)
	if object {
		body[1] = 1
	}
	binary.BigEndian.PutUint32(body[2:6], uint32(len(identity.certs[0].Raw)))
	binary.BigEndian.PutUint32(body[6:10], uint32(len(private)))
	body = append(append(body, identity.certs[0].Raw...), private...)
	p.want('I', body, 0, nil)
	if p.refs != 0 {
		t.Fatal("stateless server retained policy")
	}
	return &wireServer{wirePeer: p, identity: identity}
}
func (p *wireServer) ingest(wire []byte) (int32, []byte) {
	return p.rpc('G', append([]byte{7, 4, 127, 0, 0, 1, 1, 0xbb}, wire...))
}
func (p *wireServer) plain(kind byte, body []byte) (int32, []byte) {
	wire := wireRecord(kind, p.sequence, body, 0)
	p.sequence++
	return p.ingest(wire)
}
func (p *wireServer) hello(cookie []byte, name string) []byte {
	sni := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3))
	sni = append(sni, 0)
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
	sni = append(sni, name...)
	extensions := wireExtension(0, sni)
	for _, e := range []struct {
		k uint16
		b []byte
	}{{10, []byte{0, 2, 0, 23}}, {11, []byte{1, 0}}, {13, []byte{0, 4, 4, 3, 4, 1}}, {23, nil}, {0xff01, []byte{0}}, {16, []byte{0, 5, 4, 't', 'e', 's', 't'}}} {
		extensions = append(extensions, wireExtension(e.k, e.b)...)
	}
	body := append([]byte{0xfe, 0xfd}, wireRange(0, 32)...)
	body = append(body, 0, byte(len(cookie)))
	body = append(body, cookie...)
	body = append(body, 0, 4, 0xc0, 0x2b, 0xc0, 0x2f, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	seq := uint16(0)
	if len(cookie) != 0 {
		seq = 1
	}
	return wireMessage(1, seq, body)
}
func (p *wireServer) connect(name string) int32 {
	p.t.Helper()
	status, challenge := p.plain(22, p.hello(nil, name))
	if status != 0 || p.phase != 0 || p.refs != 0 || len(challenge) != 60 {
		p.t.Fatal("stateless cookie challenge")
	}
	p.clientHello = p.hello(challenge[28:], name)
	status, _ = p.plain(22, p.clientHello)
	return status
}
func (p *wireServer) initial() {
	p.t.Helper()
	type assembly struct {
		kind          byte
		body, covered []byte
	}
	messages := map[uint16]*assembly{}
	for {
		status, wire := p.rpc('N', nil)
		if status == 1 {
			break
		}
		if status != 0 {
			p.t.Fatal("initial server flight")
		}
		kind, epoch, _, fragment := wireUnpack(p.t, wire)
		if kind != 22 || epoch != 0 {
			p.t.Fatal("server handshake record")
		}
		seq := binary.BigEndian.Uint16(fragment[4:6])
		total, offset, size := uint24(fragment[1:4]), uint24(fragment[6:9]), uint24(fragment[9:12])
		if len(fragment) != size+12 || offset+size > total {
			p.t.Fatal("fragment bounds")
		}
		entry := messages[seq]
		if entry == nil {
			entry = &assembly{fragment[0], make([]byte, total), make([]byte, total)}
			messages[seq] = entry
		}
		if entry.kind != fragment[0] {
			p.t.Fatal("fragment type")
		}
		for i, b := range fragment[12:] {
			at := offset + i
			if entry.covered[at] != 0 && entry.body[at] != b {
				p.t.Fatal("overlap")
			}
			entry.body[at], entry.covered[at] = b, 1
		}
		p.want('S', []byte{1}, 0, nil)
	}
	if len(messages) != 4 {
		p.t.Fatal("server message count")
	}
	var canonical []byte
	for seq := uint16(1); seq <= 4; seq++ {
		entry := messages[seq]
		if entry == nil || bytes.Contains(entry.covered, []byte{0}) {
			p.t.Fatal("incomplete server flight")
		}
		canonical = append(canonical, wireMessage(entry.kind, seq, entry.body)...)
	}
	hello := messages[1].body
	p.clientRandom = wireRange(0, 32)
	p.serverRandom = bytes.Clone(hello[2:34])
	offset := 35 + int(hello[34])
	suite := uint16(0xc02b)
	if _, ok := p.identity.key.(*rsa.PrivateKey); ok {
		suite = 0xc02f
	}
	if binary.BigEndian.Uint16(hello[offset:offset+2]) != suite {
		p.t.Fatal("selected suite")
	}
	extensions := hello[offset+5:]
	if int(binary.BigEndian.Uint16(hello[offset+3:offset+5])) != len(extensions) {
		p.t.Fatal("extension framing")
	}
	foundSNI, foundEMS := false, false
	for len(extensions) > 0 {
		kind, size := binary.BigEndian.Uint16(extensions), int(binary.BigEndian.Uint16(extensions[2:4]))
		body := extensions[4 : 4+size]
		if kind == 0 {
			foundSNI = len(body) == 0
		}
		if kind == 23 {
			foundEMS = len(body) == 0
		}
		extensions = extensions[4+size:]
	}
	if !foundSNI || !foundEMS || !bytes.Equal(messages[2].body[6:], p.identity.certs[0].Raw) {
		p.t.Fatal("SNI/EMS/certificate")
	}
	exchange := messages[3].body
	signature := exchange[73:]
	if int(binary.BigEndian.Uint16(exchange[71:73])) != len(signature) {
		p.t.Fatal("signature width")
	}
	signed := append(append(bytes.Clone(p.clientRandom), p.serverRandom...), exchange[:69]...)
	hash := sha256.Sum256(signed)
	switch key := p.identity.certs[0].PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature); err != nil {
			p.t.Fatal(err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, hash[:], signature) {
			p.t.Fatal("server key proof")
		}
	}
	scalar := make([]byte, 32)
	scalar[31] = 19
	ephemeral, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		p.t.Fatal(err)
	}
	public, err := ecdh.P256().NewPublicKey(exchange[4:69])
	if err != nil {
		p.t.Fatal(err)
	}
	shared, err := ephemeral.ECDH(public)
	if err != nil {
		p.t.Fatal(err)
	}
	cke := wireMessage(16, 2, append([]byte{65}, ephemeral.PublicKey().Bytes()...))
	transcript := append(append(bytes.Clone(p.clientHello), canonical...), cke...)
	hash = sha256.Sum256(transcript)
	p.master = wirePRF(shared, "extended master secret", hash[:], 48)
	p.keys = wirePRF(p.master, "key expansion", append(bytes.Clone(p.serverRandom), p.clientRandom...), 40)
	p.finished = wireMessage(20, 3, wirePRF(p.master, "client finished", hash[:], 12))
	hash = sha256.Sum256(append(transcript, p.finished...))
	p.expected = wireMessage(20, 5, wirePRF(p.master, "server finished", hash[:], 12))
	status, _ := p.plain(22, cke)
	if status != 0 || p.phase != 4 {
		p.t.Fatal("server CKE")
	}
}
func (p *wireServer) protectClient(kind byte, plain []byte, sequence uint64) []byte {
	serial := binary.BigEndian.AppendUint64(nil, sequence)
	serial[0], serial[1] = 0, 1
	aad := append(bytes.Clone(serial), kind, 0xfe, 0xfd)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(plain)))
	ciphertext := wireGCM(p.t, p.keys[:16]).Seal(nil, append(bytes.Clone(p.keys[32:36]), serial...), plain, aad)
	return wireRecord(kind, sequence, append(serial, ciphertext...), 1)
}
func (p *wireServer) admit() []byte {
	p.t.Helper()
	status, _ := p.ingest(p.protectClient(22, p.finished, 0))
	if status != 0 || p.phase != 4 {
		p.t.Fatal("CCS gate")
	}
	p.want('N', nil, 1, nil)
	status, _ = p.plain(20, []byte{1})
	if status != 0 || p.phase != 5 {
		p.t.Fatal("CCS")
	}
	kind, epoch, _, _ := wireUnpack(p.t, p.outgoing())
	if kind != 20 || epoch != 0 {
		p.t.Fatal("local CCS")
	}
	status, wire := p.rpc('N', nil)
	if status != 0 || p.phase != 5 {
		p.t.Fatal("Finished borrow")
	}
	p.want('W', []byte("too early"), -5, nil)
	p.want('E', exportRequest([]byte("EXPERIMENTAL-salts-dtls"), nil, false, 65), -5, nil)
	p.want('C', nil, 2, nil)
	p.want('X', nil, 2, nil)
	if !bytes.Equal(p.decrypt(wire, false), p.expected) {
		p.t.Fatal("server Finished")
	}
	p.want('S', []byte{1}, 0, nil)
	if p.phase != 6 {
		p.t.Fatal("server admission")
	}
	return wire
}
func TestScriptedDTLSServer(t *testing.T) {
	c := newWireCredentials(t)
	t.Run("fatal_epoch", func(t *testing.T) {
		for i, options := range [][4]bool{{false, false, true, true}, {true, false, true, false}, {true, true, true, false}, {true, false, false, false}, {true, false, true, true}} {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				p := newWireServer(t, c, false, false, true)
				if p.connect("localhost") != 0 {
					t.Fatal("connect")
				}
				p.initial()
				if options[0] {
					p.admit()
				}
				bad := bytes.Clone(p.finished)
				bad[len(bad)-1] ^= 1
				packet := p.protectClient(22, bad, 0)
				description := byte(51)
				epoch := uint16(0)
				if options[0] {
					epoch = 1
					packet = p.protectClient(22, bad, 2)
					if !options[3] {
						packet = p.protectClient(21, []byte{3, 40}, 2)
						description = 50
					}
				}
				status, _ := p.ingest(packet)
				p.fatal(status, description, epoch, options[0], options[1], options[2])
				p.want('X', nil, 0, nil)
			})
		}
	})
	t.Run("peer_fatal", func(t *testing.T) {
		for _, encrypted := range []bool{false, true} {
			t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
				p := newWireServer(t, c, false, false, true)
				if p.connect("localhost") != 0 {
					t.Fatal("connect")
				}
				var status int32
				if encrypted {
					p.initial()
					p.admit()
					status, _ = p.plain(21, []byte{2, 40})
					if status != 0 || p.phase != 6 {
						t.Fatal("plaintext fatal")
					}
					packet := p.protectClient(21, []byte{2, 40}, 2)
					bad := bytes.Clone(packet)
					bad[len(bad)-1] ^= 1
					status, _ = p.ingest(bad)
					if status != 0 || p.phase != 6 {
						t.Fatal("forged fatal")
					}
					status, _ = p.ingest(packet)
				} else {
					for {
						s, _ := p.rpc('N', nil)
						if s != 0 {
							break
						}
						p.want('S', []byte{1}, 0, nil)
					}
					status, _ = p.plain(21, []byte{2, 40})
				}
				if status >= 0 || p.flags&8 == 0 {
					t.Fatal("peer fatal")
				}
				p.want('Q', nil, 0, []byte{0, 40, 0, 0, 0, 0})
				p.want('N', nil, status, nil)
			})
		}
	})
	t.Run("old_plaintext", func(t *testing.T) {
		for i, payload := range [][]byte{{1}, wireMessage(0, 0, nil), wireMessage(16, 2, nil)} {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				p := newWireServer(t, c, false, false, false)
				if p.connect("localhost") != 0 {
					t.Fatal("connect")
				}
				p.initial()
				p.admit()
				if status, _ := p.plain(22, payload); status < 0 || p.phase != 6 {
					t.Fatal("old plaintext")
				}
				status, out := p.ingest(p.protectClient(23, []byte("alive"), 2))
				if status != 0 || !bytes.Equal(out, []byte("\x00\x05alive")) {
					t.Fatal("alive")
				}
				if status, _ := p.ingest(p.protectClient(22, []byte{1}, 3)); status >= 0 || p.phase != 9 {
					t.Fatal("authenticated malformed handshake")
				}
			})
		}
	})
	t.Run("exporter", func(t *testing.T) {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprint(enabled), func(t *testing.T) {
				p := newWireServer(t, c, false, false, enabled)
				request := exportRequest([]byte("EXPERIMENTAL-salts-dtls"), nil, false, 65)
				p.want('E', request, -5, nil)
				if p.connect("localhost") != 0 {
					t.Fatal("connect")
				}
				p.initial()
				p.want('E', request, -5, nil)
				p.admit()
				if (p.flags&32 != 0) == enabled {
					t.Fatal("export retention")
				}
				if enabled {
					p.checkExports()
					if status, _ := p.ingest(p.protectClient(22, p.finished, 1)); status != 0 {
						t.Fatal("Finished retry")
					}
					p.outgoing()
					p.outgoing()
					p.checkExports()
				} else {
					p.want('E', request, -5, nil)
				}
				p.want('O', nil, 0, nil)
				if p.flags&32 == 0 {
					t.Fatal("master erasure")
				}
				p.want('E', request, -5, nil)
				p.outgoing()
			})
		}
	})
	t.Run("strict_sni_identity", func(t *testing.T) {
		for _, rsaLeaf := range []bool{false, true} {
			t.Run(fmt.Sprint(rsaLeaf), func(t *testing.T) {
				p := newWireServer(t, c, rsaLeaf, true, false)
				if p.connect("localhost") != 0 {
					t.Fatal("connect")
				}
				p.initial()
				first := p.admit()
				if status, _ := p.ingest(p.protectClient(22, p.finished, 1)); status != 0 {
					t.Fatal("retry")
				}
				p.outgoing()
				repeat := p.outgoing()
				if bytes.Equal(first[5:11], repeat[5:11]) || !bytes.Equal(p.decrypt(repeat, false), p.expected) {
					t.Fatal("retransmit")
				}
				status, out := p.ingest(p.protectClient(23, []byte("strict data"), 2))
				if status != 0 || !bytes.Equal(out, []byte("\x00\x0bstrict data")) {
					t.Fatal("data")
				}
				p.want('O', nil, 0, nil)
				if !bytes.Equal(p.decrypt(p.outgoing(), false), []byte{1, 0}) || p.phase != 8 || p.flags&8 == 0 {
					t.Fatal("close")
				}
				p.want('X', nil, 2, nil)
				p.want('C', nil, 0, nil)
				if p.refs != 0 {
					t.Fatal("refs")
				}
				p.want('X', nil, 0, nil)
			})
		}
	})
	t.Run("wrong_sni", func(t *testing.T) {
		p := newWireServer(t, c, false, false, false)
		if p.connect("wrong.example") >= 0 || p.phase != 9 || p.flags&8 == 0 || p.refs != 1 {
			t.Fatal("strict SNI")
		}
	})
	t.Run("abort_final_borrow", func(t *testing.T) {
		p := newWireServer(t, c, false, false, true)
		if p.connect("localhost") != 0 {
			t.Fatal("connect")
		}
		p.initial()
		if status, _ := p.ingest(p.protectClient(22, p.finished, 0)); status != 0 {
			t.Fatal("Finished")
		}
		if status, _ := p.plain(20, []byte{1}); status != 0 {
			t.Fatal("CCS")
		}
		p.outgoing()
		status, wire := p.rpc('N', nil)
		if status != 0 {
			t.Fatal("borrow")
		}
		p.want('A', nil, 0, wire)
		if p.phase != 9 || p.flags&8 == 0 || p.flags&1 == 0 {
			t.Fatal("abort borrow")
		}
		p.want('C', nil, 2, nil)
		p.want('X', nil, 2, nil)
		p.want('S', []byte{1}, -5, nil)
		p.want('C', nil, 0, nil)
		p.want('X', nil, 0, nil)
	})
	t.Run("proof_and_bad_tag", func(t *testing.T) {
		for _, badProof := range []bool{false, true} {
			t.Run(fmt.Sprint(badProof), func(t *testing.T) {
				p := newWireServer(t, c, false, false, true)
				if p.connect("localhost") != 0 {
					t.Fatal("connect")
				}
				p.initial()
				proof := bytes.Clone(p.finished)
				if badProof {
					proof[len(proof)-1] ^= 1
				}
				packet := p.protectClient(22, proof, 0)
				if badProof {
					if status, _ := p.ingest(packet); status >= 0 || p.phase != 9 || p.flags&8 == 0 {
						t.Fatal("bad proof")
					}
				} else {
					packet[len(packet)-1] ^= 1
					if status, _ := p.ingest(packet); status != 0 || p.phase != 4 {
						t.Fatal("bad tag poisoned replay")
					}
					p.admit()
				}
			})
		}
	})
}
