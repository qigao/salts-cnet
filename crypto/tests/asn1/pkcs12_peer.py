"""Formal PFX producer/oracle tests. OpenSSL-backed cryptography is test-only.

RFC 7292 encoding/KDF composed independently from the native implementation.
Exercise both encrypted safe contents and shrouded keys before importing into
real TLS contexts. All parser/admission assertions live here, not in CMake.
"""
import datetime
import hashlib
import hmac
import os
import subprocess
import sys
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from pathlib import Path

DATA = bytes.fromhex("2a864886f70d010701")
ENCRYPTED = bytes.fromhex("2a864886f70d010706")
BAGS = bytes.fromhex("2a864886f70d010c0a01")
CERT = bytes.fromhex("2a864886f70d01091601")
SHA256 = bytes.fromhex("608648016503040201")
PBES2 = bytes.fromhex("2a864886f70d01050d")
PBKDF2 = bytes.fromhex("2a864886f70d01050c")
PRF = bytes.fromhex("2a864886f70d0209")
AES256 = bytes.fromhex("60864801650304012a")
SM3 = bytes.fromhex("2a811ccf55018311")
HMAC_SM3 = SM3+b"\2"
SM4 = bytes.fromhex("2a811ccf55016802")


def tlv(tag, value):
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, "big")
    return bytes([tag]) + length + value


def seq(*values):
    return tlv(0x30, b"".join(values))


def integer(n):
    raw = n.to_bytes(max(1, (n.bit_length()+7)//8), "big")
    return tlv(2, (b"\0" if raw[0] & 128 else b"") + raw)


def oid(value):
    return tlv(6, value)


def octets(value):
    return tlv(4, value)


def content(kind, value):
    return seq(oid(kind), tlv(0xa0, value))


def encrypt(plain, password, iterations=10000, sm4=False):
    salt, iv = os.urandom(16), os.urandom(16)
    key = hashlib.pbkdf2_hmac("sm3" if sm4 else "sha256", password, salt, iterations if iterations <= 1000000 else 10000, 16 if sm4 else 32)
    count = 16 - len(plain) % 16
    enc = Cipher(algorithms.SM4(key) if sm4 else algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(plain + bytes([count]) * count) + enc.finalize()
    params = seq(seq(oid(PBKDF2), seq(octets(salt), integer(iterations), seq(oid(HMAC_SM3 if sm4 else PRF), tlv(5, b"")))),
                 seq(oid(SM4 if sm4 else AES256), octets(iv)))
    return seq(oid(PBES2), params), ciphertext


def wrap(safes, password, iterations=10000, digest="sha256", salt=None):
    return wrap_auth(seq(*safes), password, iterations, digest, salt)


def wrap_auth(auth, password, iterations=10000, digest="sha256", salt=None):
    salt = os.urandom(16) if salt is None else salt
    bmp = password.decode("utf-8").encode("utf-16-be") + b"\0\0"
    block = hashlib.new(digest).block_size
    repeated = lambda data: (data * ((block * ((len(data)+block-1)//block) + len(data)-1)//len(data)))[:block*((len(data)+block-1)//block)]
    key = hashlib.new(digest, bytes([3]) * block + repeated(salt) + repeated(bmp)).digest()
    for _ in range(min(iterations, 10000)-1):
        key = hashlib.new(digest, key).digest()
    tag = hmac.new(key, auth, digest).digest()
    suffix = {"sm3": 0, "sha256": 1, "sha384": 2, "sha512": 3, "sha224": 4, "sha512_224": 5, "sha512_256": 6}[digest]
    algorithm = seq(oid(SM3 if digest == "sm3" else SHA256[:-1] + bytes([suffix])), tlv(5, b""))
    return seq(integer(3), content(DATA, octets(auth)), seq(seq(algorithm, octets(tag)), octets(salt), integer(iterations)))


def key_bag(key, password, encrypted=True):
    plain = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    if encrypted:
        algorithm, ciphertext = encrypt(plain, password)
        plain = seq(algorithm, octets(ciphertext))
    return seq(oid(BAGS + bytes([2 if encrypted else 1])), tlv(0xa0, plain))


def cert_bag(cert):
    return seq(oid(BAGS + b"\3"), tlv(0xa0, seq(oid(CERT), tlv(0xa0, octets(cert.public_bytes(serialization.Encoding.DER))))))


def fields(der):
    # Test-only DER views used to preserve an independent producer's encrypted
    # safes exactly while raising its fixed 2048-round integrity KDF policy.
    values = []
    offset = 0
    while offset < len(der):
        start = offset
        tag, n = der[offset], der[offset+1]
        offset += 2
        if n & 128:
            width = n & 127
            n = int.from_bytes(der[offset:offset+width], "big")
            offset += width
        value = der[offset:offset+n]
        offset += n
        values.append((tag, value, der[start:offset]))
    return values


def identity(ec_key=False):
    key = ec.generate_private_key(ec.SECP256R1()) if ec_key else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PFX test root")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name).public_key(root_key.public_key())
            .serial_number(1).not_valid_before(now-datetime.timedelta(hours=1)).not_valid_after(now+datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True).sign(root_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(root_name).public_key(key.public_key())
            .serial_number(2).not_valid_before(now-datetime.timedelta(hours=1)).not_valid_after(now+datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True).sign(root_key, hashes.SHA256()))
    return key, leaf, root


class PFX(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.identities = [identity(), identity(True)]

    def native(self, pfx, password, ok=True, kind="single"):
        proc = subprocess.run([PEER, password.hex(), kind], input=pfx, capture_output=True, timeout=15, check=True)
        status = int(proc.stdout)
        self.assertEqual(status == 0, ok, f"native status {status}: {proc.stderr.decode(errors='replace')}")
        return status

    def test_independent_safes_and_passwords(self):
        for key, leaf, root in self.identities:
            for password in [b"", b"p\0ass", "证书密钥".encode()]:
                for encrypted_safe in [False, True]:
                    for shrouded in [False, True]:
                        with self.subTest(ec=isinstance(key, ec.EllipticCurvePrivateKey), password=password, encrypted_safe=encrypted_safe, shrouded=shrouded):
                            bags = seq(cert_bag(root), key_bag(key, password, shrouded), cert_bag(leaf))
                            if encrypted_safe:
                                algorithm, ciphertext = encrypt(bags, password)
                                safe = content(ENCRYPTED, seq(integer(0), seq(oid(DATA), algorithm, tlv(0x80, ciphertext))))
                            else:
                                safe = content(DATA, octets(bags))
                            self.native(wrap([safe], password), password)

    def test_mac_sha2(self):
        key, leaf, _ = self.identities[0]
        safe = content(DATA, octets(seq(key_bag(key, b"pass"), cert_bag(leaf))))
        for digest in ["sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256", "sm3"]:
            with self.subTest(digest=digest):
                self.native(wrap([safe], b"pass", digest=digest), b"pass")

    def test_cryptography_producer(self):
        for key, leaf, root in self.identities:
            builder = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(10000)
                       .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC).hmac_hash(hashes.SHA256()))
            pfx = pkcs12.serialize_key_and_certificates(b"native", key, leaf, [root], builder.build(b"password"))
            outer = fields(fields(pfx)[0][1])
            mac = fields(outer[2][1])
            rounds = int.from_bytes(mac[2][1], "big") if len(mac) == 3 else 1
            # cryptography fixes MAC rounds independently of kdf_rounds; a weak
            # MAC provides a cheap password oracle even with strong encryption.
            self.native(pfx, b"password", rounds >= 10000)
            auth = fields(fields(outer[1][1])[1][1])[0][1]
            hardened = wrap_auth(auth, b"password")
            parsed_key, parsed_cert, parsed_cas = pkcs12.load_key_and_certificates(hardened, b"password")
            self.assertEqual(parsed_cert, leaf)
            self.assertEqual(len(parsed_cas), 1)
            self.assertIsNotNone(parsed_key)
            self.native(hardened, b"password")

    def test_integrity_precedes_safe_algorithm_admission(self):
        unsupported = content(bytes.fromhex("2a864886f70d010703"), seq())
        authenticated = wrap([unsupported], b"pass")
        # Public crypto_tls_stream_result values: ENOTSUP=-11, EIO=-5.
        self.assertEqual(self.native(authenticated, b"pass", False), -11)
        self.assertEqual(self.native(authenticated, b"wrong", False), -5)

    def test_sm3_sm4_password_privacy(self):
        key, leaf, _ = self.identities[0]
        plain = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        algorithm, ciphertext = encrypt(plain, b"pass", sm4=True)
        keybag = seq(oid(BAGS+b"\2"), tlv(0xa0, seq(algorithm, octets(ciphertext))))
        algorithm, ciphertext = encrypt(seq(keybag, cert_bag(leaf)), b"pass", sm4=True)
        safe = content(ENCRYPTED, seq(integer(0), seq(oid(DATA), algorithm, tlv(0x80, ciphertext))))
        self.native(wrap([safe], b"pass", digest="sm3"), b"pass")
        self.native(wrap([safe], b"pass", digest="sm3"), b"wrong", False)

    def test_aggregate_kdf_budget(self):
        key, leaf, _ = self.identities[0]
        identity_safe = content(DATA, octets(seq(key_bag(key, b"pass", False), cert_bag(leaf))))
        algorithm, ciphertext = encrypt(seq(), b"pass", 700000)
        slow = content(ENCRYPTED, seq(integer(0), seq(oid(DATA), algorithm, tlv(0x80, ciphertext))))
        # 10,000 + 2*700,000 is admitted; adding another safe exceeds the
        # 2,000,000-round whole-import budget before its next derivation.
        self.native(wrap([identity_safe, slow, slow], b"pass"), b"pass")
        self.native(wrap([identity_safe, slow, slow, slow], b"pass"), b"pass", False)
        for salt in [bytes(8), bytes(64)]:
            self.native(wrap([identity_safe], b"pass", salt=salt), b"pass")

    def test_reject_unsupported_content_and_attributes(self):
        key, leaf, _ = self.identities[0]
        keybag = key_bag(key, b"pass")
        certbag = cert_bag(leaf)
        local_id = seq(oid(bytes.fromhex("2a864886f70d010915")), tlv(0x31, octets(b"id")))
        friendly = seq(oid(bytes.fromhex("2a864886f70d010914")), tlv(0x31, tlv(0x1e, "identity".encode("utf-16-be"))))
        key_parts = fields(keybag)[0][1]
        for attributes, ok in [(tlv(0x31, local_id), True), (tlv(0x31, friendly), True),
                               (tlv(0x31, local_id+local_id), False), (tlv(0x31, b""), False),
                               (tlv(0x31, seq(oid(b"\x2a\x03"), tlv(0x31, octets(b"x")))), False)]:
            with self.subTest(attributes=attributes.hex()):
                bags = seq(seq(key_parts, attributes), certbag)
                self.native(wrap([content(DATA, octets(bags))], b"pass"), b"pass", ok)
        good = content(DATA, octets(seq(keybag, certbag)))
        self.native(wrap([content(DATA, octets(seq()))] * 8 + [good], b"pass"), b"pass", False)
        unknown = seq(oid(BAGS+b"\x06"), tlv(0xa0, seq()))
        for safe in [content(DATA, octets(seq(keybag, certbag, unknown))),
                     content(DATA, octets(seq(*[keybag] * 3, certbag))),
                     content(DATA, octets(seq(*[certbag] * 33))),
                     content(bytes.fromhex("2a864886f70d010703"), seq())]:
            self.native(wrap([safe], b"pass"), b"pass", False)
        # Valid MAC but wrong privacy password, key padding and malformed inner
        # safes must fail independently of outer integrity verification.
        wrongkey = key_bag(key, b"wrong")
        self.native(wrap([content(DATA, octets(seq(wrongkey, certbag)))], b"pass"), b"pass", False)
        algorithm, ciphertext = encrypt(b"not DER", b"pass")
        malformed = content(ENCRYPTED, seq(integer(0), seq(oid(DATA), algorithm, tlv(0x80, ciphertext))))
        self.native(wrap([malformed], b"pass"), b"pass", False)

    def test_reject_invalid_inputs(self):
        key, leaf, root = self.identities[0]
        safe = content(DATA, octets(seq(key_bag(key, b"pass"), cert_bag(leaf), cert_bag(root))))
        valid = wrap([safe], b"pass")
        self.native(valid, b"wrong", False)
        for index in [0, len(valid)//2, len(valid)-1]:
            bad = bytearray(valid)
            bad[index] ^= 1
            self.native(bad, b"pass", False)
        for bad in [valid[:-1], valid+b"\0", b"", bytes(65537)]:
            self.native(bad, b"pass", False)
        for iterations in [9999, 1000001]:
            self.native(wrap([safe], b"pass", iterations=iterations), b"pass", False)
        for salt in [b"short", bytes(65)]:
            self.native(wrap([safe], b"pass", salt=salt), b"pass", False)
        self.native(valid, b"\xff", False)
        self.native(valid, "😀".encode(), False)
        self.native(valid, bytes(1025), False)
        self.native(valid, b"pass", False, "tlcp")
        for bags in [seq(cert_bag(leaf)), seq(key_bag(key, b"pass")),
                     seq(key_bag(key, b"pass"), cert_bag(leaf), cert_bag(leaf)),
                     seq(key_bag(self.identities[1][0], b"pass"), cert_bag(leaf)),
                     seq(key_bag(key, b"pass"), cert_bag(leaf), cert_bag(self.identities[1][2])),
                     seq(key_bag(key, b"pass"), key_bag(key, b"pass"), cert_bag(leaf))]:
            self.native(wrap([content(DATA, octets(bags))], b"pass"), b"pass", False)
        auth = seq(safe)
        self.native(seq(integer(3), content(DATA, octets(auth))), b"pass", False)


def write_fixture(output, certificate_path, *key_paths):
    import base64
    import re
    certs = re.findall(br"-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----", Path(certificate_path).read_bytes())
    if not certs or not key_paths:
        raise ValueError("certificate and key inputs required")
    certs = [seq(oid(BAGS+b"\3"), tlv(0xa0, seq(oid(CERT), tlv(0xa0, octets(base64.b64decode(c)))))) for c in reversed(certs)]
    keys = []
    password = b"memory\0sign"
    for path in reversed(key_paths):
        raw = Path(path).read_bytes()
        match = re.fullmatch(br"\s*-----BEGIN PRIVATE KEY-----([^-]+)-----END PRIVATE KEY-----\s*", raw)
        if not match:
            raise ValueError("one plaintext PKCS8 input required")
        algorithm, ciphertext = encrypt(base64.b64decode(match[1]), password)
        keys.append(seq(oid(BAGS+b"\2"), tlv(0xa0, seq(algorithm, octets(ciphertext)))))
    # Independent key and certificate safe ordering, with both privacy layers.
    algorithm, ciphertext = encrypt(seq(*certs), password)
    safes = [content(ENCRYPTED, seq(integer(0), seq(oid(DATA), algorithm, tlv(0x80, ciphertext)))),
             content(DATA, octets(seq(*keys)))]
    with open(output, "wb") as target:
        target.write(wrap(safes, password))


if __name__ == "__main__":
    if len(sys.argv) >= 5 and sys.argv[1] == "--fixture":
        write_fixture(*sys.argv[2:])
    else:
        PEER = sys.argv.pop(1)
        unittest.main()
