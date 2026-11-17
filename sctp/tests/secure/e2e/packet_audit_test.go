package secure

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"strings"
	"testing"
)

// This formal peer sends a constant byte per nonempty binary user message.
// Observe the native echo after DTLS authentication and before Pion SCTP owns
// its reassembly copy. No wire bytes, read sizes or deadlines are changed.
type echoPacketAudit struct {
	net.Conn
	expected byte
}

// Keep the test oracle tied to the peer's byte formula, rather than trusting
// the caller-owned write slice to remain an accurate expected result. The
// slice must still remain unchanged; fail at the first boundary that loses it.
func auditEchoSource(payload []byte, expected byte, phase string) error {
	for i, b := range payload {
		if b != expected {
			end := min(i+32, len(payload))
			return fmt.Errorf("echo source changed %s: offset=%d expected=%02x actual=%x sha256=%x",
				phase, i, expected, payload[i:end], sha256.Sum256(payload))
		}
	}
	return nil
}

func TestEchoSourceAudit(t *testing.T) {
	payload := []byte{34, 34, 34}
	if err := auditEchoSource(payload, 34, "before write"); err != nil {
		t.Fatal(err)
	}
	payload[1] = 0xa5
	if err := auditEchoSource(payload, 34, "after read"); err == nil ||
		!strings.Contains(err.Error(), "after read: offset=1 expected=22 actual=a522") {
		t.Fatalf("missing source mutation evidence: %v", err)
	}
	if payload[1] != 0xa5 {
		t.Fatal("source audit changed caller storage")
	}
}

func (c *echoPacketAudit) Read(out []byte) (int, error) {
	n, err := c.Conn.Read(out)
	if err == nil {
		if auditErr := auditEchoPacket(out[:n], c.expected); auditErr != nil {
			return 0, auditErr
		}
	}
	return n, err
}

func packetCRC(wire []byte) uint32 {
	table := crc32.MakeTable(crc32.Castagnoli)
	crc := crc32.Update(0, table, wire[:8])
	crc = crc32.Update(crc, table, []byte{0, 0, 0, 0})
	return crc32.Update(crc, table, wire[12:])
}

func auditEchoPacket(wire []byte, expected byte) error {
	if len(wire) < 12 {
		return fmt.Errorf("native SCTP echo packet shorter than common header: %d", len(wire))
	}
	if binary.LittleEndian.Uint32(wire[8:12]) != packetCRC(wire) {
		return fmt.Errorf("native SCTP echo CRC mismatch after DTLS authentication")
	}
	for at := 12; at < len(wire); {
		if len(wire)-at < 4 {
			return fmt.Errorf("native SCTP echo truncated chunk header at %d", at)
		}
		size := int(binary.BigEndian.Uint16(wire[at+2 : at+4]))
		if size < 4 || size > len(wire)-at {
			return fmt.Errorf("native SCTP echo invalid chunk size=%d at=%d", size, at)
		}
		if wire[at] == 64 { // RFC 8260 I-DATA; this peer requires interleaving.
			if size < 20 {
				return fmt.Errorf("native SCTP echo truncated I-DATA at %d", at)
			}
			value := wire[at+4 : at+size]
			begin := wire[at+1]&2 != 0
			word := binary.BigEndian.Uint32(value[12:16]) // PPID on B, FSN otherwise.
			if !begin || word == 53 {
				for i, b := range value[16:] {
					if b != expected {
						end := i + 32
						if end > len(value)-16 {
							end = len(value) - 16
						}
						return fmt.Errorf("native SCTP echo payload mismatch before reassembly: tsn=%d sid=%d mid=%d begin=%t ppid_or_fsn=%d offset=%d expected=%02x actual=%x",
							binary.BigEndian.Uint32(value[:4]), binary.BigEndian.Uint16(value[4:6]),
							binary.BigEndian.Uint32(value[8:12]), begin, word, i, expected, value[16+i:16+end])
					}
				}
			}
		}
		padded := (size + 3) &^ 3
		if padded > len(wire)-at {
			if size != len(wire)-at {
				return fmt.Errorf("native SCTP echo truncated chunk padding at %d", at)
			}
			padded = size
		}
		at += padded
	}
	return nil
}

func TestEchoPacketAudit(t *testing.T) {
	packet := func(ppid uint32, payload []byte) []byte {
		wire := make([]byte, 32+len(payload))
		binary.BigEndian.PutUint16(wire[:2], 5000)
		binary.BigEndian.PutUint16(wire[2:4], 5000)
		wire[12], wire[13] = 64, 3
		binary.BigEndian.PutUint16(wire[14:16], uint16(20+len(payload)))
		binary.BigEndian.PutUint32(wire[28:32], ppid)
		copy(wire[32:], payload)
		binary.LittleEndian.PutUint32(wire[8:12], packetCRC(wire))
		return wire
	}
	continuation := packet(5, []byte{35, 0xa5, 35})
	continuation[13] = 0
	binary.LittleEndian.PutUint32(continuation[8:12], packetCRC(continuation))
	badCRC := packet(53, []byte{35, 35, 35})
	badCRC[32] ^= 1
	for _, c := range []struct {
		name    string
		wire    []byte
		invalid bool
	}{
		{"binary", packet(53, []byte{35, 35, 35}), false},
		{"dcep_ack", packet(50, []byte{2}), false},
		{"empty_binary", packet(57, []byte{0}), false},
		{"authenticated_wrong_byte", packet(53, []byte{35, 0xa5, 35}), true},
		{"wrong_continuation_byte", continuation, true},
		{"bad_crc", badCRC, true},
		{"truncated_header", []byte{0}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := append([]byte(nil), c.wire...)
			err := auditEchoPacket(c.wire, 35)
			if (err != nil) != c.invalid {
				t.Fatalf("invalid=%v: %v", c.invalid, err)
			}
			for i := range before {
				if c.wire[i] != before[i] {
					t.Fatal("audit modified peer packet")
				}
			}
		})
	}
}
