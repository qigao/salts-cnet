"""Independent strict-SNI client oracle for the private server, using existing
Python crypto primitives. It verifies the RFC6066 acknowledgment in the exact
Finished transcript; it never alters a third-party peer's wire/transcript.
"""
import hashlib
import hmac
import struct
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dtls_handshake_peer import header, prf
from dtls_client_peer import Credentials, Peer, der, extension, message, point, record, unpack_record, export_request, check_export, drain_fatal

EXECUTABLE=sys.argv[1]
ADDRESS=bytes([4,127,0,0,1,1,0xbb])


class Server(Peer):
    def __init__(self,test,credentials,rsa_leaf=False,object_input=False,exporter=False):
        self.test,self.credentials,self.now=test,credentials,0
        self.errors=tempfile.TemporaryFile()
        self.child=subprocess.Popen([EXECUTABLE,"accept","strict"]+(["exporter"] if exporter else []),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.errors)
        self.key,self.certs=credentials.leaf(rsa_leaf)
        self.rsa=rsa_leaf
        self.cert=der(self.certs[0])
        private=self.key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        body=bytes([0,object_input])+struct.pack("!III",len(self.cert),len(private),0)+self.cert+private
        test.assertEqual(self.rpc("I",body)[0],0)
        test.assertEqual(self.references,0)
        self.plain_sequence=0

    def ingest(self,wire):
        return self.rpc("G",bytes([len(ADDRESS)])+ADDRESS+wire)

    def send_plain(self,kind,body):
        wire=record(kind,self.plain_sequence,body)
        self.plain_sequence+=1
        return self.ingest(wire)

    def hello(self,cookie,name):
        extensions=(extension(0,struct.pack("!H",len(name)+3)+b"\0"+struct.pack("!H",len(name))+name)
                    +extension(10,b"\0\x02\0\x17")+extension(11,b"\x01\0")+extension(13,b"\0\x04\x04\x03\x04\x01")
                    +extension(23,b"")+extension(0xff01,b"\0")+extension(16,b"\0\x05\x04test"))
        body=(b"\xfe\xfd"+bytes(range(32))+b"\0"+bytes([len(cookie)])+cookie
              +b"\0\x04\xc0\x2b\xc0\x2f\x01\0"+struct.pack("!H",len(extensions))+extensions)
        return message(1,1 if cookie else 0,body)

    def connect(self,name=b"localhost"):
        status,challenge=self.send_plain(22,self.hello(b"",name))
        self.test.assertEqual(status,0)
        self.test.assertEqual(self.phase,0)
        self.test.assertEqual(self.references,0)
        self.test.assertEqual(len(challenge),60)
        self.client_hello=self.hello(challenge[28:],name)
        return self.send_plain(22,self.client_hello)[0]

    def initial(self):
        bodies={}
        while True:
            status,wire=self.rpc("N")
            if status==1:
                break
            self.test.assertEqual(status,0,self.diagnostics())
            kind,epoch,_,fragment=unpack_record(wire)
            self.test.assertEqual((kind,epoch),(22,0))
            hs,total,seq,offset,length=(fragment[0],int.from_bytes(fragment[1:4],"big"),int.from_bytes(fragment[4:6],"big"),
                                      int.from_bytes(fragment[6:9],"big"),int.from_bytes(fragment[9:12],"big"))
            self.test.assertEqual(len(fragment),length+12)
            self.test.assertLessEqual(offset+length,total)
            entry=bodies.setdefault(seq,(hs,bytearray(total),bytearray(total)))
            self.test.assertEqual(entry[0],hs)
            for at,value in enumerate(fragment[12:],offset):
                if entry[2][at]:
                    self.test.assertEqual(entry[1][at],value)
                entry[1][at],entry[2][at]=value,1
            self.test.assertEqual(self.rpc("S",b"\x01")[0],0)
        self.test.assertEqual(sorted(bodies),[1,2,3,4])
        for hs,body,covered in bodies.values():
            self.test.assertTrue(all(covered))
        self.messages=[message(bodies[seq][0],seq,bytes(bodies[seq][1])) for seq in sorted(bodies)]
        hello=bytes(bodies[1][1])
        self.server_random=hello[2:34]
        offset=35+hello[34]
        self.test.assertEqual(int.from_bytes(hello[offset:offset+2],"big"),0xc02f if self.rsa else 0xc02b)
        ext=hello[offset+5:]
        self.test.assertEqual(int.from_bytes(hello[offset+3:offset+5],"big"),len(ext))
        extensions={}
        while ext:
            kind,size=struct.unpack("!HH",ext[:4]);extensions[kind]=ext[4:4+size];ext=ext[4+size:]
        self.test.assertIn(0,extensions)
        self.test.assertEqual(extensions[0],b"")
        self.test.assertEqual(extensions[23],b"")
        self.test.assertEqual(bytes(bodies[2][1])[6:],self.cert)
        exchange=bytes(bodies[3][1]);signature=exchange[73:]
        self.test.assertEqual(int.from_bytes(exchange[71:73],"big"),len(signature))
        signed=bytes(range(32))+self.server_random+exchange[:69]
        if self.rsa:
            self.certs[0].public_key().verify(signature,signed,padding.PKCS1v15(),hashes.SHA256())
        else:
            self.certs[0].public_key().verify(signature,signed,ec.ECDSA(hashes.SHA256()))
        ephemeral=ec.derive_private_key(19,ec.SECP256R1())
        public=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),exchange[4:69])
        cke=message(16,2,b"\x41"+point(ephemeral))
        transcript=self.client_hello+b"".join(self.messages)+cke
        shared=ephemeral.exchange(ec.ECDH(),public)
        master=prf(shared,b"extended master secret",hashlib.sha256(transcript).digest(),48)
        self.master=master
        self.keys=prf(master,b"key expansion",self.server_random+bytes(range(32)),40)
        self.finished=message(20,3,prf(master,b"client finished",hashlib.sha256(transcript).digest(),12))
        self.expected=message(20,5,prf(master,b"server finished",hashlib.sha256(transcript+self.finished).digest(),12))
        self.test.assertEqual(self.send_plain(22,cke)[0],0)
        self.test.assertEqual(self.phase,4)

    def protect_client(self,kind,plain,sequence):
        serial=b"\0\1"+sequence.to_bytes(6,"big")
        aad=serial+bytes([kind])+b"\xfe\xfd"+struct.pack("!H",len(plain))
        encrypted=AESGCM(self.keys[:16]).encrypt(self.keys[32:36]+serial,plain,aad)
        return record(kind,sequence,serial+encrypted,1)

    def decrypt_server(self,wire):
        _,epoch,_,body=unpack_record(wire)
        self.test.assertEqual(epoch,1)
        aad=wire[3:11]+wire[:3]+struct.pack("!H",len(body)-24)
        return AESGCM(self.keys[16:32]).decrypt(self.keys[36:40]+body[:8],body[8:],aad)

    def admit(self):
        self.test.assertEqual(self.ingest(self.protect_client(22,self.finished,0))[0],0)
        self.test.assertEqual(self.phase,4)
        self.test.assertEqual(self.rpc("N")[0],1)
        self.test.assertEqual(self.send_plain(20,b"\x01")[0],0)
        self.test.assertEqual(self.phase,5)
        self.test.assertEqual(unpack_record(self.outgoing())[0:2],(20,0))
        status,wire=self.rpc("N")
        self.test.assertEqual(status,0)
        self.test.assertEqual(self.phase,5)
        self.test.assertEqual(self.rpc("W",b"too early")[0],-5)
        self.test.assertEqual(self.rpc("E",export_request()),(-5,b""))
        self.test.assertEqual(self.rpc("C")[0],2)
        self.test.assertEqual(self.rpc("X")[0],2)
        self.test.assertTrue(hmac.compare_digest(self.decrypt_server(wire),self.expected))
        self.test.assertEqual(self.rpc("S",b"\x01")[0],0)
        self.test.assertEqual(self.phase,6)
        return wire


class StrictServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.credentials=Credentials()

    def test_fatal_epoch_tracks_actual_local_ccs_and_preserves_pending_wire(self):
        for ready,abort,sent,proof in ((False,False,True,True),(True,False,True,False),(True,True,True,False),(True,False,False,False),(True,False,True,True)):
            with self.subTest(ready=ready,abort=abort,sent=sent,proof=proof),Server(self,self.credentials,exporter=True) as peer:
                self.assertEqual(peer.connect(),0);peer.initial()
                if ready:
                    peer.admit()
                    if not proof:
                        status=peer.ingest(peer.protect_client(21,b"\x03\x28",2))[0]
                        description=50
                    else:
                        bad=peer.finished[:-1]+bytes([peer.finished[-1]^1])
                        status=peer.ingest(peer.protect_client(22,bad,2))[0]
                        description=51
                else:
                    bad=peer.finished[:-1]+bytes([peer.finished[-1]^1])
                    status=peer.ingest(peer.protect_client(22,bad,0))[0]
                    description=51
                drain_fatal(self,peer,status,description,1 if ready else 0,
                    decrypt=peer.decrypt_server if ready else None,abort=abort,sent=sent)
                self.assertEqual(peer.rpc("X")[0],0)

    def test_received_fatal_is_not_reflected_and_bad_tags_do_not_terminate(self):
        for encrypted in (False,True):
            with self.subTest(encrypted=encrypted),Server(self,self.credentials,exporter=True) as peer:
                self.assertEqual(peer.connect(),0)
                if encrypted:
                    peer.initial();peer.admit()
                    self.assertEqual(peer.send_plain(21,b"\x02\x28"),(0,b""));self.assertEqual(peer.phase,6)
                    packet=peer.protect_client(21,b"\x02\x28",2)
                    bad=packet[:-1]+bytes([packet[-1]^1])
                    self.assertEqual(peer.ingest(bad),(0,b""));self.assertEqual(peer.phase,6)
                    status=peer.ingest(packet)[0]
                else:
                    # Drain initial flight before accepting another datagram.
                    while peer.rpc("N")[0]==0:
                        self.assertEqual(peer.rpc("S",b"\x01")[0],0)
                    status=peer.send_plain(21,b"\x02\x28")[0]
                self.assertLess(status,0);self.assertTrue(peer.flags&8)
                self.assertEqual(peer.rpc("Q"),(0,b"\0\x28"+bytes(4)))
                self.assertEqual(peer.rpc("N"),(status,b""))

    def test_old_plaintext_handshakes_cannot_terminate_ready(self):
        for payload in (b"\x01", message(0, 0, b""), message(16, 2, b"")):
            with self.subTest(payload=payload), Server(self, self.credentials) as peer:
                self.assertEqual(peer.connect(), 0)
                peer.initial()
                peer.admit()
                self.assertGreaterEqual(peer.send_plain(22, payload)[0], 0)
                self.assertEqual(peer.phase, 6)
                self.assertEqual(peer.ingest(peer.protect_client(23, b"alive", 2)), (0, b"\0\x05alive"))
                self.assertLess(peer.ingest(peer.protect_client(22, b"\x01", 3))[0], 0)
                self.assertEqual(peer.phase, 9)

    def test_exporter_requires_ready_and_explicit_retention_then_erases_at_close(self):
        for enabled in (False,True):
            with self.subTest(enabled=enabled),Server(self,self.credentials,exporter=enabled) as peer:
                self.assertEqual(peer.rpc("E",export_request()),(-5,b""))
                self.assertEqual(peer.connect(),0)
                peer.initial()
                self.assertEqual(peer.rpc("E",export_request()),(-5,b""))
                peer.admit()
                self.assertEqual(bool(peer.flags&32),not enabled)
                if enabled:
                    check_export(self,peer,bytes(range(32)),peer.server_random,peer.master)
                    self.assertEqual(peer.ingest(peer.protect_client(22,peer.finished,1))[0],0)
                    peer.outgoing();peer.outgoing()
                    check_export(self,peer,bytes(range(32)),peer.server_random,peer.master)
                else:
                    self.assertEqual(peer.rpc("E",export_request()),(-5,b""))
                self.assertEqual(peer.rpc("O")[0],0)
                self.assertTrue(peer.flags&32)
                self.assertEqual(peer.rpc("E",export_request()),(-5,b""))
                peer.outgoing()

    def test_strict_sni_and_full_transcript_with_both_identity_kinds(self):
        for rsa_leaf in (False,True):
            with self.subTest(rsa=rsa_leaf),Server(self,self.credentials,rsa_leaf,object_input=True) as peer:
                self.assertEqual(peer.connect(),0)
                peer.initial()
                first=peer.admit()
                self.assertEqual(peer.ingest(peer.protect_client(22,peer.finished,1))[0],0)
                peer.outgoing()
                repeated=peer.outgoing()
                self.assertNotEqual(first[5:11],repeated[5:11])
                self.assertEqual(peer.decrypt_server(repeated),peer.expected)
                self.assertEqual(peer.ingest(peer.protect_client(23,b"strict data",2)),(0,b"\0\x0bstrict data"))
                self.assertEqual(peer.rpc("O")[0],0)
                self.assertEqual(peer.decrypt_server(peer.outgoing()),b"\x01\0")
                self.assertEqual(peer.phase,8)
                self.assertTrue(peer.flags&8)
                self.assertEqual(peer.rpc("X")[0],2)
                self.assertEqual(peer.rpc("C")[0],0)
                self.assertEqual(peer.references,0)
                self.assertEqual(peer.rpc("X")[0],0)

    def test_wrong_sni_is_terminal_and_does_not_become_a_static_context(self):
        with Server(self,self.credentials) as peer:
            self.assertLess(peer.connect(b"wrong.example"),0)
            self.assertEqual(peer.phase,9)
            self.assertTrue(peer.flags&8)
            self.assertEqual(peer.references,1)

    def test_abort_during_encrypted_final_send_preserves_wire_until_terminal(self):
        with Server(self,self.credentials,exporter=True) as peer:
            self.assertEqual(peer.connect(),0)
            peer.initial()
            self.assertEqual(peer.ingest(peer.protect_client(22,peer.finished,0))[0],0)
            self.assertEqual(peer.send_plain(20,b"\x01")[0],0)
            peer.outgoing()  # Actual local CCS terminal, not the final Finished.
            status,wire=peer.rpc("N")
            self.assertEqual(status,0)
            self.assertEqual(peer.rpc("A"),(0,wire))
            self.assertEqual(peer.phase,9)
            self.assertTrue(peer.flags&8)
            self.assertTrue(peer.flags&1)
            self.assertEqual(peer.rpc("C")[0],2)
            self.assertEqual(peer.rpc("X")[0],2)
            self.assertEqual(peer.rpc("S",b"\x01")[0],-5)
            self.assertEqual(peer.rpc("C")[0],0)
            self.assertEqual(peer.rpc("X")[0],0)

    def test_authenticated_bad_finished_fails_but_bad_tag_cannot_poison_replay(self):
        for bad_proof in (False,True):
            with self.subTest(proof=bad_proof),Server(self,self.credentials,exporter=True) as peer:
                self.assertEqual(peer.connect(),0)
                peer.initial()
                if bad_proof:
                    bad=peer.finished[:-1]+bytes([peer.finished[-1]^1])
                    self.assertLess(peer.ingest(peer.protect_client(22,bad,0))[0],0)
                    self.assertEqual(peer.phase,9)
                    self.assertTrue(peer.flags&8)
                else:
                    valid=peer.protect_client(22,peer.finished,0)
                    forged=valid[:-1]+bytes([valid[-1]^1])
                    self.assertEqual(peer.ingest(forged),(0,b""))
                    self.assertEqual(peer.phase,4)
                    peer.admit()


if __name__=="__main__":
    unittest.main(argv=[__file__],verbosity=2)
