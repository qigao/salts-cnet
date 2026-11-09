"""Formal bidirectional PKCS#8 interop with independent hashlib/cryptography.

Only this test uses Python's OpenSSL-backed algorithms. No native project link.
The fixed SM2 scalar=1 public point is the published curve generator.
RFC 5958/5915 containers, RFC 8018 PBES2 SHA256/AES256 and SM3/SM4 profiles.
"""
import hashlib
import subprocess
import sys
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PEER = sys.argv.pop(1)
PASSWORD = b"p\0ass"
KEY = bytes(31) + b"\1"
PUB = bytes.fromhex(
    "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
    "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")
EC = bytes.fromhex("2a8648ce3d0201")
SM2 = bytes.fromhex("2a811ccf5501822d")
PBES2 = bytes.fromhex("2a864886f70d01050d")
PBKDF2 = bytes.fromhex("2a864886f70d01050c")
HMAC_SM3 = bytes.fromhex("2a811ccf5501831102")
SM4_CBC = bytes.fromhex("2a811ccf55016802")
HMAC_SHA256 = bytes.fromhex("2a864886f70d0209")
AES256_CBC = bytes.fromhex("60864801650304012a")


def tlv(tag, data):
    n = len(data)
    length = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, "big")
    return bytes([tag]) + length + data


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def integer(n):
    data = n.to_bytes(max(1, (n.bit_length()+7)//8), "big")
    return tlv(2, (b"\0" if data[0] & 128 else b"") + data)


def fields(data):
    result = []
    while data:
        tag, n, data = data[0], data[1], data[2:]
        if n & 128:
            count = n & 127
            n, data = int.from_bytes(data[:count], "big"), data[count:]
        if n > len(data):
            raise ValueError("truncated DER from peer")
        result.append((tag, data[:n]))
        data = data[n:]
    return result


def only_sequence(data):
    values = fields(data)
    if len(values) != 1 or values[0][0] != 0x30:
        raise ValueError("expected one DER sequence")
    return fields(values[0][1])


def private_info(include_curve=True, include_public=True):
    optional = []
    if include_curve:
        optional.append(tlv(0xa0, tlv(6, SM2)))
    if include_public:
        optional.append(tlv(0xa1, tlv(3, b"\0" + PUB)))
    inner = seq(integer(1), tlv(4, KEY), *optional)
    return seq(integer(0), seq(tlv(6, EC), tlv(6, SM2)), tlv(4, inner))


def encrypt_info(plain, salt, explicit_length=True, null_prf=False, *, aes=False,
                 password=PASSWORD, iterations=10000, key_length=None,
                 prf_oid=None, cipher_oid=None, iv=bytes(range(16, 32)), padding=None):
    width = 32 if aes else 16
    # Negative policy fixtures vary the declared count, keeping actual work
    # bounded at 10000. The native C suite also imports a valid 10001 key.
    derived = hashlib.pbkdf2_hmac("sha256" if aes else "sm3", password, salt, 10000, width)
    if padding is None:
        padding = bytes([16 - len(plain) % 16]) * (16 - len(plain) % 16)
    algorithm = algorithms.AES(derived) if aes else algorithms.SM4(derived)
    # Invalid-IV fixtures alter only the encoded IV length.
    cryptor = Cipher(algorithm, modes.CBC(bytes(range(16, 32)))).encryptor()
    cipher = cryptor.update(plain + padding) + cryptor.finalize()
    if prf_oid is None:
        prf_oid = HMAC_SHA256 if aes else HMAC_SM3
    if cipher_oid is None:
        cipher_oid = AES256_CBC if aes else SM4_CBC
    parameters = [tlv(4, salt), integer(iterations)]
    if explicit_length:
        parameters.append(integer(width if key_length is None else key_length))
    if prf_oid:
        parameters.append(seq(tlv(6, prf_oid), *([tlv(5, b"")] if null_prf else [])))
    params = seq(*parameters)
    alg = seq(tlv(6, PBES2), seq(seq(tlv(6, PBKDF2), params), seq(tlv(6, cipher_oid), tlv(4, iv))))
    return seq(alg, tlv(4, cipher))


class SM2KeyInterop(unittest.TestCase):
    def test_aes256_decrypts_independent_optional_fields_and_salt_bounds(self):
        for curve, public in [(True, True), (False, True), (True, False), (False, False)]:
            for keylen, null_prf, salt_size in [(True, True, 16), (False, False, 32), (True, False, 64)]:
                with self.subTest(curve=curve, public=public, keylen=keylen, null_prf=null_prf, salt_size=salt_size):
                    der = encrypt_info(private_info(curve, public), bytes(range(salt_size)), keylen, null_prf, aes=True)
                    peer = subprocess.run([PEER, "decrypt-aes256"], input=der, capture_output=True, timeout=30)
                    self.assertEqual(peer.returncode, 0, peer.stderr)
                    self.assertEqual(peer.stdout, KEY)

    def test_aes256_rejects_algorithm_policy_padding_and_key_binding_negatives(self):
        good = private_info()
        wrong_key = bytearray(good)
        wrong_key[67] = 2
        # Encrypt with SHA256/AES256, then independently change declarations;
        # malformed or mismatched inputs must fail before key publication.
        cases = [
            {"key_length": 16}, {"key_length": 24}, {"key_length": 33},
            {"prf_oid": b""}, {"prf_oid": HMAC_SM3},
            {"prf_oid": HMAC_SHA256[:-1] + b"\x0a"},
            {"cipher_oid": SM4_CBC}, {"cipher_oid": AES256_CBC[:-1] + b"\x02"},
            {"iterations": 9999}, {"iterations": 10001}, {"iterations": 16777216},
            {"password": b"wrong"}, {"iv": bytes(15)}, {"iv": bytes(17)},
            {"padding": bytes(10)}, {"padding": bytes([17]) * 10},
            {"padding": b"\x09" + bytes([10]) * 9},
        ]
        for options in cases:
            with self.subTest(options=options):
                der = encrypt_info(good, bytes(range(16)), aes=True, **options)
                peer = subprocess.run([PEER, "decrypt-aes256"], input=der, capture_output=True, timeout=30)
                self.assertEqual(peer.returncode, 3, peer.stderr)
                self.assertEqual(peer.stdout, b"")
        for salt in [bytes(15), bytes(65)]:
            der = encrypt_info(good, salt, aes=True)
            peer = subprocess.run([PEER, "decrypt-aes256"], input=der, capture_output=True, timeout=30)
            self.assertEqual(peer.returncode, 3)
            self.assertEqual(peer.stdout, b"")
        for plain in [bytes(wrong_key), good + b"\0"]:
            der = encrypt_info(plain, bytes(range(16)), aes=True)
            peer = subprocess.run([PEER, "decrypt-aes256"], input=der, capture_output=True, timeout=30)
            self.assertEqual(peer.returncode, 3)
            self.assertEqual(peer.stdout, b"")

    def test_independent_decrypts_aes256_exports_and_profiles_do_not_fall_back(self):
        encodings = []
        for _ in range(2):
            peer = subprocess.run([PEER, "encrypt-aes256"], capture_output=True, check=True, timeout=30)
            encodings.append(peer.stdout)
            outer = only_sequence(peer.stdout)
            self.assertEqual([tag for tag, _ in outer], [0x30, 4])
            alg = fields(outer[0][1])
            self.assertEqual(alg[0], (6, PBES2))
            kdf, scheme = fields(alg[1][1])
            kdf_fields = fields(kdf[1])
            self.assertEqual(kdf_fields[0], (6, PBKDF2))
            salt, iterations, keylen, prf = fields(kdf_fields[1][1])
            self.assertEqual((salt[0], len(salt[1])), (4, 16))
            self.assertEqual(iterations, (2, b"\x27\x10"))
            self.assertEqual(keylen, (2, b"\x20"))
            self.assertEqual(fields(prf[1]), [(6, HMAC_SHA256), (5, b"")])
            cipher_oid, iv = fields(scheme[1])
            self.assertEqual(cipher_oid, (6, AES256_CBC))
            self.assertEqual((iv[0], len(iv[1])), (4, 16))
            derived = hashlib.pbkdf2_hmac("sha256", PASSWORD, salt[1], 10000, 32)
            cryptor = Cipher(algorithms.AES(derived), modes.CBC(iv[1])).decryptor()
            plain = cryptor.update(outer[1][1]) + cryptor.finalize()
            self.assertEqual(plain[-10:], bytes([10]) * 10)
            self.assertEqual(plain[:-10], private_info())
            wrong_profile = subprocess.run([PEER, "decrypt"], input=peer.stdout, capture_output=True, timeout=30)
            self.assertEqual(wrong_profile.returncode, 3)
            self.assertEqual(wrong_profile.stdout, b"")
        self.assertNotEqual(encodings[0], encodings[1])
        sm4 = subprocess.run([PEER, "encrypt"], capture_output=True, check=True, timeout=30)
        wrong_profile = subprocess.run([PEER, "decrypt-aes256"], input=sm4.stdout, capture_output=True, timeout=30)
        self.assertEqual(wrong_profile.returncode, 3)
        self.assertEqual(wrong_profile.stdout, b"")

    def test_core_rejects_validly_encrypted_invalid_key_containers(self):
        good = private_info()
        wrong_scalar = bytearray(good)
        wrong_scalar[67] = 2  # A valid scalar whose embedded public key is wrong.
        wrong_curve = bytearray(good)
        wrong_curve[79] ^= 1  # Inner curve must agree with outer curveSM2.
        with_attributes = seq(integer(0), seq(tlv(6, EC), tlv(6, SM2)),
                              tlv(4, seq(integer(1), tlv(4, KEY))), tlv(0xa0, b""))
        noncanonical_inner = seq(integer(0), seq(tlv(6, EC), tlv(6, SM2)),
                                tlv(4, b"\x30\x81\x25" + integer(1) + tlv(4, KEY)))
        for plain in [bytes(wrong_scalar), bytes(wrong_curve), with_attributes,
                      noncanonical_inner, private_info(False, False) + b"\0"]:
            der = encrypt_info(plain, bytes(range(16)))
            peer = subprocess.run([PEER, "decrypt"], input=der, capture_output=True, timeout=30)
            self.assertEqual(peer.returncode, 3)
            self.assertEqual(peer.stdout, b"")

    def test_core_decrypts_independent_variants(self):
        for curve, public, keylen, null_prf, salt_size in [
            (True, True, True, False, 16), (False, True, False, True, 32),
            (True, False, True, True, 64), (False, False, False, False, 16)]:
            with self.subTest(curve=curve, public=public, keylen=keylen, null_prf=null_prf, salt_size=salt_size):
                der = encrypt_info(private_info(curve, public), bytes(range(salt_size)), keylen, null_prf)
                peer = subprocess.run([PEER, "decrypt"], input=der, capture_output=True, timeout=30)
                self.assertEqual(peer.returncode, 0, peer.stderr)
                self.assertEqual(peer.stdout, KEY)

    def test_independent_decrypts_core_with_fresh_randomness(self):
        encodings = []
        for _ in range(2):
            peer = subprocess.run([PEER, "encrypt"], capture_output=True, check=True, timeout=30)
            encodings.append(peer.stdout)
            outer = only_sequence(peer.stdout)
            self.assertEqual([tag for tag, _ in outer], [0x30, 4])
            alg = fields(outer[0][1])
            self.assertEqual(alg[0], (6, PBES2))
            kdf, scheme = fields(alg[1][1])
            kdf_fields = fields(kdf[1])
            self.assertEqual(kdf_fields[0], (6, PBKDF2))
            salt, iterations, keylen, prf = fields(kdf_fields[1][1])
            self.assertEqual((salt[0], len(salt[1])), (4, 16))
            self.assertEqual(iterations, (2, b"\x27\x10"))
            self.assertEqual(keylen, (2, b"\x10"))
            self.assertEqual(fields(prf[1]), [(6, HMAC_SM3)])
            cipher_oid, iv = fields(scheme[1])
            self.assertEqual(cipher_oid, (6, SM4_CBC))
            self.assertEqual((iv[0], len(iv[1])), (4, 16))
            derived = hashlib.pbkdf2_hmac("sm3", PASSWORD, salt[1], 10000, 16)
            cryptor = Cipher(algorithms.SM4(derived), modes.CBC(iv[1])).decryptor()
            plain = cryptor.update(outer[1][1]) + cryptor.finalize()
            self.assertEqual(plain[-10:], bytes([10])*10)
            self.assertEqual(plain[:-10], private_info())
        self.assertNotEqual(encodings[0], encodings[1])


if __name__ == "__main__":
    unittest.main()
