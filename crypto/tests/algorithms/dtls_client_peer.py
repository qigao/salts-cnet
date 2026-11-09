"""Independent finite DTLS1.2 wire oracle; simulated send terminals, no NativeIO.

Certificates, ECDHE signatures, transcript/EMS/Finished and AEAD are computed by
Python/cryptography, with no native private key or PRF output supplied to it.
This is a scripted protocol peer, not third-party DTLS-stack qualification.
"""
import datetime
import hashlib
import hmac
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from dtls_handshake_peer import header, prf

EXECUTABLE = sys.argv[1]
ZERO, COOKIE, HELLO, CERTIFICATE, KEY, DONE, FINISHED, READY, CLOSING, CLOSED, FAILED = range(11)


def vec24(data):
    return len(data).to_bytes(3, "big") + data


def message(kind, sequence, body):
    return header(kind, sequence, len(body), 0, len(body)) + body


def record(kind, sequence, body, epoch=0, version=b"\xfe\xfd"):
    return bytes([kind]) + version + struct.pack("!H", epoch) + sequence.to_bytes(6, "big") + struct.pack("!H", len(body)) + body


def unpack_record(wire):
    if len(wire) < 13 or int.from_bytes(wire[11:13], "big") != len(wire)-13:
        raise AssertionError("bad native record framing")
    return wire[0], int.from_bytes(wire[3:5], "big"), int.from_bytes(wire[5:11], "big"), wire[13:]


def extension(kind, data):
    return struct.pack("!HH", kind, len(data)) + data


def point(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def export_request(label=b"EXPERIMENTAL-salts-dtls", context=None, size=65):
    data = context if context is not None else b""
    return bytes([context is not None])+struct.pack("!HHH", len(label), len(data), size)+label+data


def check_export(test, peer, client_random, server_random, master):
    values = []
    for context in (None, b"", b"binary\0context\xff", bytes(range(256))*4):
        label = b"EXPERIMENTAL-salts-dtls"
        seed = client_random+server_random+(struct.pack("!H", len(context))+context if context is not None else b"")
        for size in (1, 32, 65, 1024):
            status, value = peer.rpc("E", export_request(label, context, size))
            test.assertEqual(status, 0)
            test.assertTrue(hmac.compare_digest(value, prf(master, label, seed, size)), "exporter mismatch")
        values.append(value)
    test.assertFalse(hmac.compare_digest(values[0], values[1]), "absent/empty context collision")
    for label in (b"client finished", b"server finished", b"master secret", b"key expansion", b"extended master secret",
                  b"key", b"master secretary", b"", b"x\0y", b"\xff", b"x"*256):
        test.assertEqual(peer.rpc("E", export_request(label)), (-1, b""))
    test.assertEqual(peer.rpc("E", export_request(context=b"x"*1025)), (-1, b""))
    test.assertEqual(peer.rpc("E", export_request(size=0)), (-1, b""))
    test.assertEqual(peer.rpc("E", export_request(size=1025)), (-1, b""))


def drain_fatal(test, peer, failure, description, epoch, decrypt=None, abort=False, sent=True):
    test.assertLess(failure, 0)
    test.assertTrue(peer.flags & 8)  # All record/master secrets erased before send.
    status, metadata = peer.rpc("Q")
    test.assertEqual((status, metadata), (0, bytes([description, 0])+bytes(4)))
    status, wire = peer.rpc("N")
    test.assertEqual(status, 0)
    kind, actual_epoch, _, body = unpack_record(wire)
    test.assertEqual((kind, actual_epoch), (21, epoch))
    test.assertLessEqual(len(wire), 39)
    test.assertEqual(decrypt(wire) if decrypt else body, bytes([2, description]))
    test.assertEqual(peer.rpc("N"), (2, b""))
    test.assertEqual(peer.rpc("C")[0], 2)
    if abort:
        test.assertEqual(peer.rpc("A"), (0, wire))
        test.assertEqual(peer.rpc("C")[0], 2)
    test.assertEqual(peer.rpc("S", bytes([sent]))[0], failure)
    test.assertEqual(peer.rpc("N", now=peer.now+100000), (failure, b""))
    test.assertEqual(peer.rpc("N"), (failure, b""))
    status, metadata = peer.rpc("Q")
    test.assertEqual(status, 0)
    test.assertEqual(metadata[:2], bytes([description, 0]))
    test.assertEqual(struct.unpack("!i", metadata[2:])[0] == 0, sent)
    test.assertEqual(peer.rpc("C")[0], 0)


class Credentials:
    def __init__(self):
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DTLS root")])
        self.root = self.ca(self.root_key, self.root_name, self.root_name, self.root_key)
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ephemeral = ec.derive_private_key(7, ec.SECP256R1())

    def base(self, name, issuer, key, before=None, after=None):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(before or self.now-datetime.timedelta(days=1))
                .not_valid_after(after or self.now+datetime.timedelta(days=30)))

    def ca(self, key, name, issuer, signer, constraint=None):
        builder = (self.base(name, issuer, key).add_extension(x509.BasicConstraints(ca=True, path_length=2), True)
                   .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False))
        if constraint:
            builder = builder.add_extension(x509.NameConstraints([x509.DNSName(constraint)], None), True)
        return builder.sign(signer, hashes.SHA256())

    def leaf(self, rsa_leaf=False, failure="", client=False):
        key = self.rsa_key if rsa_leaf else self.ec_key
        issuer, signer, extra = self.root_name, self.root_key, []
        if failure in ("constraints", "intermediate"):
            signer = ec.generate_private_key(ec.SECP256R1())
            issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "constrained CA")])
            extra = [self.ca(signer, issuer, self.root_name, self.root_key, ".allowed.test" if failure == "constraints" else None)]
        if failure == "wrong_root":
            signer = ec.generate_private_key(ec.SECP256R1())
        before, after = None, None
        if failure == "expired":
            before, after = self.now-datetime.timedelta(days=3), self.now-datetime.timedelta(days=2)
        if failure == "future":
            before, after = self.now+datetime.timedelta(days=1), self.now+datetime.timedelta(days=2)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        builder = (self.base(name, issuer, key, before, after).add_extension(x509.BasicConstraints(False, None), True)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
                   .add_extension(x509.KeyUsage(failure != "key_usage", False, failure == "key_usage", False, False, False, False, None, None), True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client or failure == "purpose" else ExtendedKeyUsageOID.SERVER_AUTH]), False)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False))
        if failure == "critical":
            builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"), True)
        return key, [builder.sign(signer, hashes.SHA256())] + extra


class Peer:
    def __init__(self, test, credentials, hostname="localhost", policy="accept", alpn="test", identity=None, object_input=False, exporter=False):
        self.test, self.credentials = test, credentials
        self.now, self.sequence = 0, 0
        self.errors = tempfile.TemporaryFile()
        self.alpn = alpn
        self.child = subprocess.Popen([EXECUTABLE, hostname, policy, alpn]+(["exporter"] if exporter else []), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors)
        root = der(credentials.root)
        if identity:
            key, chain = identity
            certs = b"".join(der(c) for c in chain)
            private = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            body = bytes([object_input])+struct.pack("!III", len(root), len(certs), len(private))+root+certs+private
            self.test.assertEqual(self.rpc("J", body)[0], 0)
            self.test.assertFalse(self.flags & 64)
        else:
            self.test.assertEqual(self.rpc("I", root)[0], 0)
        self.test.assertEqual(self.references, 0 if policy == "none" else 1)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.child.stdin.close()
        try:
            code = self.child.wait(timeout=5)
            if not args[0]:
                self.test.assertEqual(code, 0, self.diagnostics())
        finally:
            if self.child.poll() is None:
                self.child.kill()
                self.child.wait(timeout=5)
            self.child.stdout.close()
            self.errors.close()

    def diagnostics(self):
        self.errors.seek(0)
        return self.errors.read().decode(errors="replace")

    def read(self, n):
        value = b""
        while len(value) < n:
            part = self.child.stdout.read(n-len(value))
            if not part:
                raise AssertionError("native endpoint exited: " + self.diagnostics())
            value += part
        return value

    def rpc(self, op, payload=b"", now=None):
        if now is not None:
            self.now = now
        self.child.stdin.write(op.encode() + struct.pack("!QI", self.now, len(payload)) + payload)
        self.child.stdin.flush()
        status, self.phase, self.flags, self.checks, self.references, self.verify, self.index, n = struct.unpack("!iBBHiiII", self.read(24))
        return status, self.read(n)

    def outgoing(self):
        status, wire = self.rpc("N")
        self.test.assertEqual(status, 0, self.diagnostics())
        self.test.assertTrue(self.flags & 1)
        self.test.assertEqual(self.rpc("S", b"\x01")[0], 0)
        return wire

    def receive(self, payload, kind=22, epoch=0):
        wire = record(kind, self.sequence, payload, epoch)
        self.sequence += 1
        return self.rpc("R", wire)

    def start(self, renew=False):
        first = self.outgoing()
        kind, epoch, _, first_message = unpack_record(first)
        self.test.assertEqual((kind, epoch, first_message[0], first_message[4:6]), (22, 0, 1, b"\0\0"))
        original = first_message[12:]
        self.client_random = original[2:34]
        for index in range(2 if renew else 1):
            cookie = hashlib.sha256(b"independent cookie" + bytes([index]) + original).digest()
            self.test.assertEqual(self.receive(message(3, 0, b"\xfe\xfd" + bytes([len(cookie)]) + cookie))[0], 0)
            _, _, _, canonical = unpack_record(self.outgoing())
            body = canonical[12:]
            self.test.assertEqual(body[:35], original[:35])
            self.test.assertEqual(body[35], 32)
            self.test.assertEqual(body[36:68], cookie)
            self.test.assertEqual(body[68:], original[36:])
            self.client_sequence = int.from_bytes(canonical[4:6], "big")
        self.hello = canonical
        self.test.assertEqual(self.phase, HELLO)
        return canonical

    def flight(self, rsa_leaf=False, failure="", reorder=False, request=None):
        key, certs = self.credentials.leaf(rsa_leaf, failure)
        self.server_random = bytes(range(64, 96))
        cipher = 0xc02f if rsa_leaf else 0xc02b
        extensions = [(0, b""), (11, b"\x03\x00\x01\x02"), (23, b""), (0xff01, b"\0"), (16, b"\0\x05\x04test")]
        if not self.alpn and failure != "unoffered_alpn":
            extensions = [(k, v) for k, v in extensions if k != 16]
        if failure in ("no_ems", "no_alpn"):
            extensions = [(k, v) for k, v in extensions if k != (23 if failure == "no_ems" else 16)]
        if failure == "duplicate_ems":
            extensions.append((23, b""))
        if failure == "unoffered":
            extensions.append((0x1234, b""))
        if failure == "bad_alpn":
            extensions[-1] = (16, b"\0\x05\x04evil")
        encoded = b"".join(extension(k, v) for k, v in extensions)
        hello = b"\xfe\xfd" + self.server_random + b"\0" + struct.pack("!H", 0x1301 if failure == "cipher" else cipher) + bytes([failure == "compression"]) + struct.pack("!H", len(encoded)) + encoded
        certificate = vec24(b"".join(vec24(der(cert)) for cert in certs))
        params = b"\x03\0\x17\x41" + point(self.credentials.ephemeral)
        if failure == "point":
            params = params[:4] + b"\x05" + params[5:]
        signed = self.client_random + self.server_random + params
        if failure == "signed_random":
            signed = bytes([signed[0] ^ 1]) + signed[1:]
        if failure == "wrong_signer":
            key = ec.generate_private_key(ec.SECP256R1())
        signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256()) if rsa_leaf else key.sign(signed, ec.ECDSA(hashes.SHA256()))
        if failure == "signature":
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        exchange = params + (b"\x04\x01" if rsa_leaf else b"\x04\x03") + struct.pack("!H", len(signature)) + signature
        self.server_messages = [message(2, 1, hello), message(11, 2, certificate), message(12, 3, exchange), message(14, 4, b"")]
        if request is not None:
            self.server_messages[3:] = [message(13, 4, request), message(14, 5, b"")]
            if failure == "duplicate_request":
                self.server_messages[4:] = [message(13, 5, request), message(14, 6, b"")]
        self.server_finished_sequence = 6 if request is not None else 5
        packets = self.server_messages
        if reorder:
            middle = len(certificate)//2
            fragments = [header(11, 2, len(certificate), middle, len(certificate)-middle)+certificate[middle:],
                         header(11, 2, len(certificate), 0, middle+7)+certificate[:middle+7]]
            packets = list(reversed(packets[3:])) + [packets[2], fragments[0], fragments[0], fragments[1], packets[0]]
        for packet in packets:
            status, _ = self.receive(packet)
            if status < 0:
                return status
        return 0

    def client_flight(self, retry=False):
        flight = [self.outgoing() for _ in range(3)]
        if retry:
            self.now += 1000
            repeated = [self.outgoing() for _ in range(3)]
            for old, new in zip(flight, repeated):
                self.test.assertNotEqual(old[5:11], new[5:11])
            self.test.assertEqual(flight[0][13:], repeated[0][13:])
            flight = repeated
        kind, epoch, _, cke = unpack_record(flight[0])
        self.test.assertEqual((kind, epoch, cke[0], cke[12]), (22, 0, 16, 65))
        self.test.assertEqual(int.from_bytes(cke[4:6], "big"), self.client_sequence+1)
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), cke[13:])
        shared = self.credentials.ephemeral.exchange(ec.ECDH(), public)
        self.transcript = self.hello + b"".join(self.server_messages) + cke
        self.master = prf(shared, b"extended master secret", hashlib.sha256(self.transcript).digest(), 48)
        self.keys = prf(self.master, b"key expansion", self.server_random+self.client_random, 40)
        self.test.assertEqual(unpack_record(flight[1])[0:2], (20, 0))
        self.test.assertEqual(flight[1][13:], b"\x01")
        finished = self.decrypt(flight[2], client=True)
        self.test.assertEqual(finished[:12], header(20, self.client_sequence+2, 12, 0, 12))
        self.test.assertTrue(hmac.compare_digest(finished[12:], prf(self.master, b"client finished", hashlib.sha256(self.transcript).digest(), 12)))
        self.transcript += finished
        self.proof = prf(self.master, b"server finished", hashlib.sha256(self.transcript).digest(), 12)
        self.send_sequence = 0
        self.native_finished_wire = flight[2]
        self.test.assertEqual(self.phase, FINISHED)
        self.test.assertEqual(self.checks, 0)

    def authenticated_client_flight(self, identity, selected=True, retry=False):
        def drain():
            result = []
            while True:
                status, wire = self.rpc("N")
                if status == 1:
                    break
                self.test.assertEqual(status, 0, self.diagnostics())
                self.test.assertLessEqual(len(wire), 1200)
                self.test.assertTrue(self.flags & 64)  # No private key needed by retransmission.
                self.test.assertEqual(bool(self.flags & 128), selected)
                result.append(wire)
                self.test.assertEqual(self.rpc("S", b"\x01")[0], 0)
            return result

        flight = drain()
        if retry:
            self.now += 1000
            repeated = drain()
            self.test.assertEqual(len(flight), len(repeated))
            for old, new in zip(flight, repeated):
                self.test.assertNotEqual(old[5:11], new[5:11])
                if old[3:5] == b"\0\0":
                    self.test.assertEqual(old[13:], new[13:])
            original_finished = flight[-1]
            flight = repeated
        else:
            original_finished = None
        messages = {}
        for wire in flight[:-2]:
            kind, epoch, _, fragment = unpack_record(wire)
            self.test.assertEqual((kind, epoch), (22, 0))
            hs, total, seq, offset, length = (fragment[0], int.from_bytes(fragment[1:4], "big"),
                int.from_bytes(fragment[4:6], "big"), int.from_bytes(fragment[6:9], "big"), int.from_bytes(fragment[9:12], "big"))
            entry = messages.setdefault(seq, (hs, bytearray(total), bytearray(total)))
            self.test.assertEqual(entry[0], hs)
            self.test.assertEqual(len(fragment), length+12)
            self.test.assertLessEqual(offset+length, total)
            for at, value in enumerate(fragment[12:], offset):
                if entry[2][at]:
                    self.test.assertEqual(entry[1][at], value)
                entry[1][at], entry[2][at] = value, 1
        sequences = sorted(messages)
        self.test.assertEqual(sequences, list(range(self.client_sequence+1, self.client_sequence+1+len(messages))))
        canonical = []
        for seq in sequences:
            hs, body, coverage = messages[seq]
            self.test.assertTrue(all(coverage))
            canonical.append(message(hs, seq, bytes(body)))
        self.test.assertEqual([m[0] for m in canonical], [11, 16, 15] if selected else [11, 16])
        expected = b"".join(vec24(der(c)) for c in identity[1]) if selected else b""
        self.test.assertEqual(canonical[0][12:], vec24(expected))
        cke = canonical[1]
        self.test.assertEqual(cke[12], 65)
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), cke[13:])
        self.transcript = self.hello+b"".join(self.server_messages)+b"".join(canonical[:2])
        digest = hashlib.sha256(self.transcript).digest()
        shared = self.credentials.ephemeral.exchange(ec.ECDH(), public)
        self.master = prf(shared, b"extended master secret", digest, 48)
        self.keys = prf(self.master, b"key expansion", self.server_random+self.client_random, 40)
        if selected:
            proof = canonical[2][12:]
            scheme, n = struct.unpack("!HH", proof[:4])
            self.test.assertEqual(n, len(proof)-4)
            key = identity[1][0].public_key()
            if isinstance(key, rsa.RSAPublicKey):
                self.test.assertEqual(scheme, 0x0401)
                key.verify(proof[4:], digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
            else:
                self.test.assertEqual(scheme, 0x0403)
                key.verify(proof[4:], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            self.transcript += canonical[2]
        self.test.assertEqual(unpack_record(flight[-2])[0:2], (20, 0))
        self.test.assertEqual(flight[-2][13:], b"\x01")
        finished = self.decrypt(flight[-1], client=True)
        if original_finished:
            self.test.assertEqual(self.decrypt(original_finished, client=True), finished)
        self.test.assertEqual(finished[:12], header(20, self.client_sequence+1+len(canonical), 12, 0, 12))
        self.test.assertTrue(hmac.compare_digest(finished[12:], prf(self.master, b"client finished", hashlib.sha256(self.transcript).digest(), 12)))
        self.transcript += finished
        self.proof = prf(self.master, b"server finished", hashlib.sha256(self.transcript).digest(), 12)
        self.send_sequence = 0
        self.native_finished_wire = flight[-1]
        self.test.assertEqual(self.phase, FINISHED)
        self.test.assertEqual(self.checks, 0)

    def decrypt(self, wire, client=False):
        kind, epoch, _, payload = unpack_record(wire)
        self.test.assertEqual(epoch, 1)
        key = self.keys[:16] if client else self.keys[16:32]
        salt = self.keys[32:36] if client else self.keys[36:40]
        aad = wire[3:11] + wire[:3] + struct.pack("!H", len(payload)-24)
        return AESGCM(key).decrypt(salt+payload[:8], payload[8:], aad)

    def protect(self, kind, plain, sequence=None):
        if sequence is None:
            sequence = self.send_sequence
            self.send_sequence += 1
        explicit = b"\x90\x91" + sequence.to_bytes(6, "big")
        serial = b"\0\1" + sequence.to_bytes(6, "big")
        aad = serial + bytes([kind]) + b"\xfe\xfd" + struct.pack("!H", len(plain))
        ciphertext = AESGCM(self.keys[16:32]).encrypt(self.keys[36:40]+explicit, plain, aad)
        return record(kind, sequence, explicit+ciphertext, 1)

    def finish(self, reversed_ccs=False, bad_proof=False):
        proof = bytes([self.proof[0] ^ 1])+self.proof[1:] if bad_proof else self.proof
        finished = self.protect(22, message(20, self.server_finished_sequence, proof))
        if reversed_ccs:
            self.test.assertEqual(self.rpc("R", finished)[0], 0)
            self.test.assertEqual(self.phase, FINISHED)
            self.test.assertEqual(self.checks, 0)
            return self.receive(b"\x01", 20)[0]
        ccs = record(20, self.sequence, b"\x01")
        self.sequence += 1
        return self.rpc("R", ccs+finished)[0]


class DTLSClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.credentials = Credentials()

    def request(self, types=b"\x01\x40", schemes=b"\x04\x03\x04\x01", names=b""):
        return bytes([len(types)])+types+struct.pack("!H", len(schemes))+schemes+struct.pack("!H", len(names))+names

    def test_fatal_before_ccs_uses_plaintext_epoch_and_preserves_original_failure(self):
        for failure, description in (("signature",51),("wrong_root",46),("no_ems",40)):
            with self.subTest(failure=failure),Peer(self,self.credentials) as peer:
                peer.start()
                status=peer.flight(failure=failure)
                drain_fatal(self,peer,status,description,0)

    def test_authenticated_bad_finished_and_policy_send_encrypted_fatal_after_erasure(self):
        for policy, abort, sent in ((False,False,True),(True,False,True),(False,True,True),(True,False,False)):
            with self.subTest(policy=policy,abort=abort,sent=sent),Peer(self,self.credentials,
                    policy="reject" if policy else "accept",exporter=True) as peer:
                peer.start();self.assertEqual(peer.flight(),0);peer.client_flight()
                status=peer.finish(bad_proof=not policy)
                drain_fatal(self,peer,status,49 if policy else 51,1,
                    decrypt=lambda wire:peer.decrypt(wire,client=True),abort=abort,sent=sent)

    def test_peer_fatal_is_consumed_without_echo_and_plaintext_cannot_kill_ready(self):
        for encrypted in (False,True):
            with self.subTest(encrypted=encrypted),Peer(self,self.credentials,exporter=True) as peer:
                peer.start()
                if encrypted:
                    self.assertEqual(peer.flight(),0);peer.client_flight();self.assertEqual(peer.finish(),0)
                    self.assertEqual(peer.receive(b"\x02\x28",kind=21),(0,b""))
                    self.assertEqual(peer.phase,READY)
                    packet=peer.protect(21,b"\x02\x28")
                    bad=packet[:-1]+bytes([packet[-1]^1])
                    self.assertEqual(peer.rpc("R",bad),(0,b""));self.assertEqual(peer.phase,READY)
                    status=peer.rpc("R",packet)[0]
                else:
                    status=peer.receive(b"\x02\x28",kind=21)[0]
                self.assertLess(status,0);self.assertTrue(peer.flags&8)
                self.assertEqual(peer.rpc("Q"),(0,b"\0\x28"+bytes(4)))
                self.assertEqual(peer.rpc("N"),(status,b""))

    def test_old_plaintext_handshakes_cannot_terminate_ready(self):
        for payload in (b"\x01", message(0, 0, b""), message(14, 4, b"")):
            with self.subTest(payload=payload), Peer(self, self.credentials) as peer:
                self.complete(peer)
                self.assertGreaterEqual(peer.receive(payload)[0], 0)
                self.assertEqual(peer.phase, READY)
                self.assertEqual(peer.rpc("R", peer.protect(23, b"alive")), (0, b"\0\x05alive"))
                # The same malformed handshake is fatal when authenticated.
                self.assertLess(peer.rpc("R", peer.protect(22, b"\x01"))[0], 0)
                self.assertEqual(peer.phase, FAILED)

    def test_exporter_is_opt_in_authenticated_and_erased_at_close_or_failure(self):
        for enabled, terminal in ((False, "close"), (True, "close"), (True, "abort"), (True, "bad_finished"), (True, "policy")):
            with self.subTest(enabled=enabled, terminal=terminal), Peer(self, self.credentials, exporter=enabled,
                    policy="reject" if terminal == "policy" else "accept") as peer:
                self.assertEqual(peer.rpc("E", export_request()), (-5, b""))
                peer.start()
                self.assertEqual(peer.flight(rsa_leaf=True), 0)
                peer.client_flight(retry=True)
                self.assertEqual(peer.rpc("E", export_request()), (-5, b""))
                status = peer.finish(bad_proof=terminal == "bad_finished")
                if terminal in ("bad_finished", "policy"):
                    self.assertLess(status, 0)
                    self.assertTrue(peer.flags & 8)
                    self.assertEqual(peer.rpc("E", export_request()), (-5, b""))
                    continue
                self.assertEqual(status, 0)
                self.assertEqual(bool(peer.flags & 32), not enabled)
                if enabled:
                    check_export(self, peer, peer.client_random, peer.server_random, peer.master)
                else:
                    self.assertEqual(peer.rpc("E", export_request()), (-5, b""))
                self.assertEqual(peer.rpc("W", b"pending application")[0], 0)
                self.assertEqual(peer.rpc("N")[0], 0)
                if enabled:
                    check_export(self, peer, peer.client_random, peer.server_random, peer.master)
                self.assertEqual(peer.rpc("S", b"\x01")[0], 0)
                self.assertEqual(peer.rpc("A" if terminal == "abort" else "O")[0], 0)
                self.assertTrue(peer.flags & 32)
                self.assertEqual(peer.rpc("E", export_request()), (-5, b""))
                if terminal == "close":
                    peer.outgoing()

    def test_client_proof_and_ems_with_requested_credentials(self):
        for rsa_leaf in (False, True):
            identity = self.credentials.leaf(rsa_leaf, client=True)
            for object_input in (False, True):
                with self.subTest(rsa=rsa_leaf, object=object_input), Peer(self, self.credentials, identity=identity, object_input=object_input) as peer:
                    peer.start()
                    name = self.credentials.root.subject.public_bytes()
                    request = self.request(names=struct.pack("!H", len(name))+name)
                    self.assertEqual(peer.flight(rsa_leaf=not rsa_leaf, request=request, reorder=object_input), 0, peer.diagnostics())
                    peer.authenticated_client_flight(identity, retry=True)
                    self.assertEqual(peer.finish(reversed_ccs=True), 0, peer.diagnostics())
                    self.assertEqual(peer.phase, READY)
                    self.assertEqual(peer.checks, 1)
                    self.assertTrue(peer.flags & 64)

    def test_request_ca_hint_matches_root_or_intermediate(self):
        identity = self.credentials.leaf(False, "intermediate", client=True)
        for name in (self.credentials.root.subject, identity[1][1].subject):
            encoded = name.public_bytes()
            with self.subTest(issuer=name.rfc4514_string()), Peer(self, self.credentials, identity=identity) as peer:
                peer.start()
                self.assertEqual(peer.flight(request=self.request(names=struct.pack("!H", len(encoded))+encoded)), 0)
                peer.authenticated_client_flight(identity)
                self.assertEqual(peer.finish(), 0)
                self.assertEqual(peer.phase, READY)

    def test_requested_signature_list_also_constrains_certificate_signatures(self):
        identity = self.credentials.leaf(True, client=True)  # RSA key, ECDSA issuer.
        with Peer(self, self.credentials, identity=identity) as peer:
            peer.start()
            self.assertEqual(peer.flight(request=self.request(schemes=b"\x04\x01")), 0)
            peer.authenticated_client_flight(identity, selected=False)
            self.assertEqual(peer.finish(), 0)

    def test_no_suitable_identity_sends_empty_certificate_without_proof(self):
        identity = self.credentials.leaf(False, "purpose")
        other = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other issuer")]).public_bytes()
        requests = [self.request(types=b"\x01"), self.request(schemes=b"\x04\x01"),
                    self.request(names=struct.pack("!H", len(other))+other)]
        for index, request in enumerate(requests+[self.request()]):
            with self.subTest(case=index), Peer(self, self.credentials, identity=identity if index < 3 else None) as peer:
                peer.start()
                self.assertEqual(peer.flight(request=request), 0)
                peer.authenticated_client_flight(identity, selected=False)
                self.assertEqual(peer.finish(), 0)  # Explicit optional-auth server behavior.
                self.assertEqual(peer.phase, READY)

    def test_unused_identity_is_never_sent_or_retained_after_final_flight(self):
        identity = self.credentials.leaf(False, "purpose")
        with Peer(self, self.credentials, identity=identity) as peer:
            self.complete(peer)
            self.assertTrue(peer.flags & 64)
            self.assertFalse(peer.flags & 128)

    def test_malformed_certificate_requests_fail_before_client_flight(self):
        identity = self.credentials.leaf(False, "purpose")
        good_name = self.credentials.root.subject.public_bytes()
        names = struct.pack("!H", len(good_name))+good_name
        requests = [b"", b"\0\0\x02\x04\x03\0\0", self.request(schemes=b"\x04"),
                    self.request(schemes=b""), self.request(names=b"\0\x04\x30\0"),
                    self.request(names=names+b"\0\x01\xff"), self.request()+b"\0",
                    self.request(names=names+b"\0\x04\x30\x02\x05\0")]
        for index, request in enumerate(requests):
            with self.subTest(case=index), Peer(self, self.credentials, identity=identity) as peer:
                peer.start()
                self.assertLess(peer.flight(request=request), 0)
                self.assertEqual(peer.phase, FAILED)
                self.assertEqual(peer.checks, 0)
                self.assertTrue(peer.flags & 64)
                self.assertTrue(peer.flags & 8)

    def test_pending_client_certificate_keeps_wire_alive_through_abort(self):
        identity = self.credentials.leaf(False, "purpose")
        with Peer(self, self.credentials, identity=identity) as peer:
            peer.start()
            self.assertEqual(peer.flight(request=self.request()), 0)
            status, wire = peer.rpc("N")
            self.assertEqual(status, 0)
            self.assertEqual(wire[13], 11)
            self.assertTrue(peer.flags & 64)
            self.assertEqual(peer.rpc("R", record(20, 8, b"\1")), (2, b""))
            self.assertEqual(peer.rpc("C")[0], 2)
            self.assertEqual(peer.rpc("A"), (0, wire))
            self.assertTrue(peer.flags & 8)
            self.assertTrue(peer.flags & 64)
            self.assertEqual(peer.rpc("C")[0], 2)
            self.assertLess(peer.rpc("S", b"\x01")[0], 0)
            self.assertEqual(peer.rpc("C")[0], 0)
            self.assertEqual(peer.references, 0)

    def test_duplicate_certificate_request_fails_before_a_client_proof(self):
        identity = self.credentials.leaf(False, client=True)
        with Peer(self, self.credentials, identity=identity) as peer:
            peer.start()
            self.assertLess(peer.flight(request=self.request(), failure="duplicate_request"), 0)
            self.assertEqual(peer.phase, FAILED)
            self.assertEqual(peer.checks, 0)
            self.assertTrue(peer.flags & 64)

    def complete(self, peer, rsa_leaf=False, renew=False, reorder=False, retry=False):
        peer.start(renew)
        self.assertEqual(peer.flight(rsa_leaf, reorder=reorder), 0, peer.diagnostics())
        peer.client_flight(retry)
        self.assertEqual(peer.finish(reversed_ccs=reorder), 0, peer.diagnostics())
        self.assertEqual(peer.phase, READY)
        self.assertEqual(peer.checks, 1)
        self.assertTrue(peer.flags & 32)  # Master no longer needed after Finished.
        self.assertTrue(peer.flags & 16)  # Ephemeral private key already erased.

    def test_complete_suites_records_replay_and_close(self):
        for rsa_leaf in (False, True):
            with self.subTest(rsa=rsa_leaf), Peer(self, self.credentials) as peer:
                self.complete(peer, rsa_leaf)
                self.assertEqual(peer.rpc("W", bytes(1164))[0], -1)
                self.assertEqual(peer.rpc("W", b"native application")[0], 0)
                self.assertEqual(peer.rpc("W", b"second queued")[0], 2)
                waiting = peer.protect(23, b"wait for send", 8)
                self.assertEqual(peer.rpc("R", waiting), (2, b""))
                self.assertEqual(peer.decrypt(peer.outgoing(), client=True), b"native application")
                self.assertEqual(peer.rpc("R", waiting), (0, b"\0\x0dwait for send"))
                first = peer.protect(23, b"first", 10)
                second = peer.protect(23, b"second", 9)
                self.assertEqual(peer.rpc("R", first+second), (0, b"\0\x05first\0\x06second"))
                self.assertEqual(peer.rpc("R", first+second), (0, b""))
                valid = peer.protect(23, b"after bad tag", 11)
                bad = valid[:-1] + bytes([valid[-1] ^ 1])
                self.assertEqual(peer.rpc("R", bad), (0, b""))
                self.assertEqual(peer.rpc("R", valid), (0, b"\0\x0dafter bad tag"))
                self.assertEqual(peer.rpc("R", peer.protect(23, b"", 12)), (0, b"\0\0"))
                self.assertEqual(peer.rpc("O")[0], 0)
                status, wire = peer.rpc("N")
                self.assertEqual(status, 0)
                self.assertEqual(peer.decrypt(wire, client=True), b"\x01\0")
                self.assertEqual(peer.rpc("C")[0], 2)
                self.assertEqual(peer.rpc("S", b"\x01")[0], 0)
                self.assertEqual(peer.phase, CLOSED)
                self.assertTrue(peer.flags & 8)
                self.assertEqual(peer.rpc("C")[0], 0)
                self.assertEqual(peer.references, 0)

    def test_cookie_renewal_fragment_reordering_and_final_flight_loss(self):
        with Peer(self, self.credentials) as peer:
            self.complete(peer, renew=True, reorder=True, retry=True)
            self.assertEqual(peer.rpc("R", peer.protect(21, b"\x01\0"))[0], 0)
            self.assertEqual(peer.phase, CLOSING)
            self.assertEqual(peer.decrypt(peer.outgoing(), client=True), b"\x01\0")
            self.assertEqual(peer.phase, CLOSED)

    def test_new_challenge_sequence_with_the_same_cookie_is_not_a_retransmission(self):
        with Peer(self, self.credentials) as peer:
            peer.start()
            old = peer.hello[12:]
            cookie = old[36:36+old[35]]
            self.assertEqual(peer.receive(message(3, 1, b"\xfe\xfd"+bytes([len(cookie)])+cookie))[0], 0)
            _, _, _, hello = unpack_record(peer.outgoing())
            self.assertEqual(int.from_bytes(hello[4:6], "big"), 2)
            self.assertEqual(hello[12:], old)
            self.assertEqual(peer.phase, HELLO)

    def test_recognized_peer_flights_trigger_bounded_retries_before_rto(self):
        with Peer(self, self.credentials) as peer:
            peer.start()
            cookie = peer.hello[48:80]  # Complete message header + CH fixed prefix.
            self.assertEqual(peer.receive(message(3, 0, b"\xfe\xfd\x20"+cookie))[0], 0)
            _, _, _, repeated = unpack_record(peer.outgoing())
            self.assertEqual(repeated, peer.hello)
            self.assertEqual(peer.flight(), 0)
            peer.client_flight()
            old_finished = peer.native_finished_wire
            self.assertEqual(peer.receive(message(14, 4, b""))[0], 0)
            peer.client_flight()
            self.assertNotEqual(peer.native_finished_wire[5:11], old_finished[5:11])
            self.assertEqual(peer.finish(), 0)
            self.assertEqual(peer.phase, READY)

    def test_optional_alpn_and_a_real_intermediate_path(self):
        with Peer(self, self.credentials, alpn="") as peer:
            peer.start()
            self.assertEqual(peer.flight(failure="intermediate", reorder=True), 0, peer.diagnostics())
            peer.client_flight()
            self.assertEqual(peer.finish(), 0, peer.diagnostics())
            self.assertEqual(peer.phase, READY)
        with Peer(self, self.credentials, alpn="") as peer:
            peer.start()
            self.assertLess(peer.flight(failure="unoffered_alpn"), 0)
            self.assertEqual(peer.phase, FAILED)

    def test_abort_preserves_an_encrypted_send_borrow_until_terminal(self):
        with Peer(self, self.credentials) as peer:
            self.complete(peer)
            self.assertEqual(peer.rpc("W", b"pending private payload")[0], 0)
            status, wire = peer.rpc("N")
            self.assertEqual(status, 0)
            self.assertEqual(peer.decrypt(wire, client=True), b"pending private payload")
            self.assertEqual(peer.rpc("A"), (0, wire))
            self.assertTrue(peer.flags & 8)
            self.assertTrue(peer.flags & 1)
            self.assertEqual(peer.rpc("C")[0], 2)
            self.assertEqual(peer.references, 1)
            self.assertEqual(peer.rpc("S", b"\x01")[0], -5)
            self.assertFalse(peer.flags & 1)
            self.assertEqual(peer.rpc("C")[0], 0)
            self.assertEqual(peer.references, 0)

    def test_finished_fragments_are_authenticated_and_ccs_still_gates_ready(self):
        with Peer(self, self.credentials) as peer:
            peer.start()
            self.assertEqual(peer.flight(), 0)
            peer.client_flight()
            for offset, size in ((6, 6), (0, 8)):
                fragment = header(20, 5, 12, offset, size) + peer.proof[offset:offset+size]
                self.assertEqual(peer.rpc("R", peer.protect(22, fragment))[0], 0)
                self.assertEqual(peer.phase, FINISHED)
                self.assertEqual(peer.checks, 0)
            self.assertTrue(peer.flags & 4)
            self.assertEqual(peer.receive(b"\x01", 20)[0], 0)
            self.assertEqual(peer.phase, READY)
            self.assertEqual(peer.checks, 1)
        with Peer(self, self.credentials) as peer:
            peer.start()
            self.assertEqual(peer.flight(), 0)
            peer.client_flight()
            wrong_size = peer.protect(22, message(20, 5, peer.proof+b"\0"))
            self.assertLess(peer.rpc("R", wrong_size)[0], 0)
            self.assertEqual(peer.phase, FAILED)
            self.assertTrue(peer.flags & 8)
            self.assertEqual(peer.checks, 0)

    def test_negotiation_and_proof_rejections_publish_no_keys_or_application(self):
        failures = ("no_ems", "no_alpn", "duplicate_ems", "unoffered", "bad_alpn", "cipher", "compression",
                    "signature", "signed_random", "wrong_signer", "point")
        for failure in failures:
            with self.subTest(failure=failure), Peer(self, self.credentials) as peer:
                peer.start()
                self.assertLess(peer.flight(failure=failure), 0)
                self.assertEqual(peer.phase, FAILED)
                self.assertEqual(peer.checks, 0)
                self.assertTrue(peer.flags & 8)

    def test_certificate_path_time_identity_usage_and_constraints(self):
        for failure in ("wrong_root", "expired", "future", "purpose", "key_usage", "critical", "constraints", "hostname"):
            with self.subTest(failure=failure), Peer(self, self.credentials, "wrong.example" if failure == "hostname" else "localhost") as peer:
                peer.start()
                self.assertLess(peer.flight(failure=failure), 0, peer.diagnostics())
                self.assertEqual(peer.phase, FAILED)
                self.assertNotEqual(peer.verify, 0)
                self.assertEqual(peer.checks, 0)
                self.assertTrue(peer.flags & 8)

    def test_authenticated_wrong_finished_and_policy_failure_are_terminal(self):
        for reject_policy in (False, True):
            with self.subTest(policy=reject_policy), Peer(self, self.credentials, policy="reject" if reject_policy else "accept") as peer:
                peer.start()
                self.assertEqual(peer.flight(), 0)
                peer.client_flight()
                self.assertLess(peer.finish(bad_proof=not reject_policy), 0)
                self.assertEqual(peer.phase, FAILED)
                self.assertEqual(peer.checks, 1 if reject_policy else 0)
                self.assertTrue(peer.flags & 8)
                self.assertEqual(peer.rpc("W", b"forbidden")[0], -5)
                self.assertEqual(peer.rpc("C")[0], 0)
                self.assertEqual(peer.references, 0)

    def test_plaintext_finished_and_forged_tags_cannot_poison_authenticated_proof(self):
        with Peer(self, self.credentials) as peer:
            peer.start()
            poison = message(20, 5, bytes(12))
            self.assertEqual(peer.receive(poison)[0], 0)
            self.assertEqual(peer.flight(), 0)
            peer.client_flight()
            valid = peer.protect(22, message(20, 5, peer.proof))
            forged = valid[:-1] + bytes([valid[-1] ^ 1])
            self.assertEqual(peer.rpc("R", forged), (0, b""))
            self.assertEqual(peer.phase, FINISHED)
            self.assertEqual(peer.checks, 0)
            self.assertEqual(peer.receive(b"\x01", 20)[0], 0)
            self.assertEqual(peer.rpc("R", valid)[0], 0)
            self.assertEqual(peer.phase, READY)
            self.assertEqual(peer.checks, 1)
            # Validate all outer records before callbacks from an otherwise valid prefix.
            application = peer.protect(23, b"atomic framing")
            self.assertEqual(peer.rpc("R", application+b"\x17"), (3, b""))
            self.assertEqual(peer.rpc("R", application), (0, b"\0\x0eatomic framing"))


if __name__ == "__main__":
    unittest.main(argv=[str(Path(__file__).name)], verbosity=2)
