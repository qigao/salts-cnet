"""Negative obligations for the production native-link ownership audit."""
from collections import Counter
import unittest

import audit_native_crypto_owner as audit


def coff_member(names, selection=None, member="unit.obj"):
    """DUMPBIN /SYMBOLS section-auxiliary format from Microsoft's reference."""
    auxiliary = "    Section length 40, #relocs 1, #linenums 0, checksum 459FF65F"
    if selection is not None:
        auxiliary += f", selection {selection}"
    return (f"Archive member name at 100: {member}\nCOFF SYMBOL TABLE\n"
            "000 00000000 SECT1 notype Static | .text$mn\n" + auxiliary + "\n" +
            "\n".join(f"{index + 2:03X} 00000000 SECT1 notype () External | {name}"
                      for index, name in enumerate(names)) + "\nString Table Size = 0x10 bytes\n")


class NativeCryptoOwnerAudit(unittest.TestCase):
    def test_archive_keeps_duplicate_strong_members(self):
        for system, text in (
            ("Linux", "a.o:\n00000000 T tls_init\nb.o:\n00000000 T tls_init\n"
                      "         U tls_send\n00000000 W weak_helper\n"),
            ("Darwin", "a.o:\n00000000 T _tls_init\nb.o:\n00000000 T _tls_init\n"),
            ("Windows", "001 00000000 SECT1 notype () External | tls_init\n"
                        "002 00000000 SECT2 notype () External | tls_init\n"
                        "003 00000000 UNDEF notype () External | tls_send\n"),
        ):
            with self.subTest(system=system):
                table = audit.archive_definitions(text, system)
                self.assertEqual(table["tls_init"], 2)
                self.assertNotIn("tls_send", table)
        native = Counter({name: 1 for name in audit.NATIVE_SYMBOLS})
        facade = Counter({name: 1 for name in audit.FACADE_SYMBOLS})
        audit.validate_archives(native, facade)
        native["tls_init"] = 2
        with self.assertRaisesRegex(ValueError, "duplicated"):
            audit.validate_archives(native, facade)

    def test_llvm_nm_windows_archive_members_are_retained(self):
        text = (
            "C:/build/libsalts_crypto.a:tls.c.obj: 00000010 T tls_init\n"
            "C:/build/libsalts_crypto.a:tls.c.obj: 00000020 T tls_send\n"
            "C:/build/libsalts_crypto.a:other.c.obj: 00000030 T helper\n"
        )
        table = audit.archive_definitions(text, "Windows")
        self.assertEqual(table["tls_init"], 1)
        self.assertEqual(table["tls_send"], 1)
        self.assertEqual(audit.nm_archive_members(text, "Windows")["tls_init"],
                         {"tls.c.obj"})

    def test_coff_mergeable_crt_and_strings_are_classified_by_section(self):
        # COMDAT mergeable CRT/string definitions do not count as duplicate
        # strong symbols in either physical archive.
        names = ("_vfprintf_l", "fprintf", "vsnprintf", "snprintf", "ctime", "time",
                 "_Atomic_load32", "??_C@_03ICHNJLJF@key@", "unlisted_inline")
        for selection in (2, 3, 4, 6):
            with self.subTest(selection=selection):
                gmssl_text = coff_member(audit.NATIVE_SYMBOLS)
                gmssl_text += coff_member(names, selection, "gmssl-first.obj")
                gmssl_text += coff_member(names, selection, "gmssl-second.obj")
                crypto_text = coff_member(audit.FACADE_SYMBOLS)
                crypto_text += coff_member(names, selection, "crypto-first.obj")
                crypto_text += coff_member(names, selection, "crypto-second.obj")
                gmssl = audit.archive_definitions(gmssl_text, "Windows")
                crypto = audit.archive_definitions(crypto_text, "Windows")
                audit.validate_archives(gmssl, crypto)

    def test_coff_required_entries_remain_physical_in_every_comdat_kind(self):
        for selection in (1, 2, 3, 4, 5, 6):
            with self.subTest(selection=selection):
                gmssl_text = coff_member(audit.NATIVE_SYMBOLS, selection)
                crypto_text = coff_member(audit.FACADE_SYMBOLS, selection)
                gmssl = audit.archive_definitions(gmssl_text, "Windows")
                crypto = audit.archive_definitions(crypto_text, "Windows")
                audit.validate_archives(gmssl, crypto)
                for name in audit.NATIVE_SYMBOLS:
                    bad = audit.archive_definitions(
                        gmssl_text + coff_member((name,), selection, "duplicate.obj"),
                        "Windows")
                    with self.subTest(symbol=name), self.assertRaisesRegex(ValueError, "duplicated"):
                        audit.validate_archives(bad, crypto)
                for name in audit.FACADE_SYMBOLS:
                    bad = audit.archive_definitions(
                        crypto_text + coff_member((name,), selection, "duplicate.obj"),
                        "Windows")
                    with self.subTest(symbol=name), self.assertRaisesRegex(ValueError, "duplicated"):
                        audit.validate_archives(gmssl, bad)

    def test_coff_noduplicates_and_ordinary_sections_stay_strong(self):
        for selection in (None, 0, 1, 5):
            # Associative COMDATs are deliberately conservative: no inference
            # that their associated section will discard the duplicate.
            for name in ("tls_init", "native_unlisted", "fprintf", "__not_a_name_exemption"):
                with self.subTest(selection=selection, symbol=name):
                    text = coff_member((name,), selection, "first.obj")
                    text += coff_member((name,), selection, "second.obj")
                    table = audit.archive_definitions(text, "Windows")
                    self.assertEqual(table[name], 2)
                    table.update({symbol: 1 for symbol in audit.ARCHIVE_SYMBOLS if symbol != name})
                    with self.assertRaises(ValueError):
                        audit.validate_archive(table, audit.ARCHIVE_SYMBOLS, "synthetic")

    def test_coff_section_numbers_are_local_to_each_member(self):
        text = coff_member(("inline_helper",), 2, "first.obj")
        text += coff_member(("native_unlisted",), None, "second.obj")
        text += coff_member(("native_unlisted",), None, "third.obj")
        for remove in ("COFF SYMBOL TABLE\n", "String Table Size = 0x10 bytes\n"):
            with self.subTest(removed_boundary=remove):
                table = audit.archive_definitions(text.replace(remove, ""), "Windows")
                self.assertNotIn("inline_helper", table)
                self.assertEqual(table["native_unlisted"], 2)

    def test_coff_unknown_or_malformed_metadata_fails_closed(self):
        for selection in (7, 99, "unrecognized"):
            with self.subTest(selection=selection), self.assertRaisesRegex(ValueError, "selection"):
                audit.archive_definitions(coff_member(("fprintf",), selection), "Windows")
        for text in (
            "Section length 40, selection 2\n",
            "001 00000000 SECT1 notype External without-symbol-delimiter\n",
            "000 00000000 SECT1 notype Static | .text\n"
            "    Section length 40, selection 1\n"
            "002 00000000 SECT1 notype Static | .text\n"
            "    Section length 40, selection 2\n",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                audit.archive_definitions(text, "Windows")

    def test_real_member_required_in_all_link_map_formats(self):
        for system in ("Linux", "Darwin", "Windows"):
            if system == "Darwin":
                prefix = "[ 1] /vcpkg/lib/libgmssl.a(tls.c.o)\n"
                text = prefix + "\n".join(
                    f"0x1000 0x10 [ 1] _{name}" for name in audit.NATIVE_SYMBOLS)
            elif system == "Windows":
                text = "\n".join(
                    f" 0001:00000010 {name} 0000000140001000 f gmssl:tls.c.obj"
                    for name in audit.NATIVE_SYMBOLS)
            else:
                prefix = " .text 0x1000 0x100 /vcpkg/lib/libgmssl.a(tls.c.o)\n"
                text = prefix + "\n".join(
                    f" 0x00001000 {name}" for name in audit.NATIVE_SYMBOLS)
            with self.subTest(system=system):
                audit.validate_runtime_map(text, system)
                with self.assertRaises(ValueError):
                    audit.validate_runtime_map(text.replace("gmssl", "salts_crypto"), system)
                with self.assertRaises(ValueError):
                    audit.validate_runtime_map(text + "\n" + text, system)
                with self.assertRaises(ValueError):
                    audit.validate_runtime_map("", system)

    def test_llvm_mingw_map_member_must_match_gmssl_archive(self):
        symbols = "\n".join(
            f"00001000 00000000 0                 {name}"
            for name in audit.NATIVE_SYMBOLS)
        text = ("Address  Size     Align Out     In      Symbol\n"
                "00001000 00001000 16         tls.c.obj:(.text)\n" + symbols + "\n")
        members = {name: {"tls.c.obj"} for name in audit.NATIVE_SYMBOLS}
        audit.validate_runtime_map(text, "Windows", members)
        members["tls_init"] = {"foreign_tls.c.obj"}
        with self.assertRaises(ValueError):
            audit.validate_runtime_map(text, "Windows", members)

    def test_cross_archive_duplicates_and_embedded_second_tls_rejected(self):
        gmssl = Counter({name: 1 for name in audit.NATIVE_SYMBOLS})
        crypto = Counter({name: 1 for name in audit.FACADE_SYMBOLS})
        audit.validate_archives(gmssl, crypto)
        with self.assertRaisesRegex(ValueError, "cross-archive"):
            audit.validate_archives(gmssl | Counter({"salts_crypto_sha256": 1}), crypto)
        with self.assertRaisesRegex(ValueError, "cross-archive"):
            audit.validate_archives(gmssl, crypto | Counter({"tls_set_io": 1}))
        with self.assertRaisesRegex(ValueError, "embeds native TLS"):
            audit.validate_archives(gmssl, crypto | Counter({"tlcp_second_engine": 1}))

    def test_facade_link_map_is_optional_but_must_be_crypto_owned(self):
        native = (" .text 0x1000 0x100 /vcpkg/lib/libgmssl.a(tls.c.o)\n" +
                  "\n".join(f" 0x00001000 {name}" for name in audit.NATIVE_SYMBOLS))
        facade = ("\n .text 0x2000 0x100 /sdk/lib/libsalts_crypto.a(crypto_tls.c.o)\n"
                  " 0x00002000 crypto_tls_session_handshake\n")
        audit.validate_runtime_map(native, "Linux")
        audit.validate_runtime_map(native + facade, "Linux")
        with self.assertRaisesRegex(ValueError, "facade"):
            audit.validate_runtime_map(native + facade.replace("libsalts_crypto", "libgmssl"),
                                       "Linux")

    def test_windows_llvm_mingw_facade_member_is_separately_verified(self):
        names = "\n".join(f"00001000 00000000 0                 {name}"
                          for name in audit.NATIVE_SYMBOLS)
        text = ("Address  Size     Align Out     In      Symbol\n"
                "00001000 00001000 16         tls.c.obj:(.text)\n" + names + "\n"
                "00002000 00001000 16         crypto_tls.c.obj:(.text)\n"
                "00002010 00000000 0                 crypto_tls_session_handshake\n")
        gmssl = {name: {"tls.c.obj"} for name in audit.NATIVE_SYMBOLS}
        crypto = {"crypto_tls_session_handshake": {"crypto_tls.c.obj"}}
        audit.validate_runtime_map(text, "Windows", gmssl, crypto)
        with self.assertRaisesRegex(ValueError, "facade"):
            audit.validate_runtime_map(
                text, "Windows", gmssl,
                {"crypto_tls_session_handshake": {"other_crypto_tls.c.obj"}})

    def test_consumers_cannot_hide_a_second_archive(self):
        audit.validate_peer_map("LOAD libcnet.so\n0x1000 cnet_client_init\n")
        for text in (
            "LOAD crypto/libsalts_crypto.a\n",
            "[ 4] /build/crypto/libsalts_crypto.a(tls.c.o)\n",
            " 0001:00000100 tls_init 0000000140010000 f salts_crypto:tls.obj\n",
            "LOAD /unexpected/libgmssl.a\n",
            "0x1000 tls_do_handshake\n",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                audit.validate_peer_map(text)

    def test_external_runtime_rejected_on_each_platform(self):
        for system, text, expected in (
            ("Linux", " (NEEDED) Shared library: [libgmssl.so.3]\n", "libgmssl.so.3"),
            ("Darwin", "image:\n\t/other/libcrypto.3.dylib (compatibility version 3.0.0)\n",
             "libcrypto.3.dylib"),
            ("Windows", "    gmssl.dll\n", "gmssl.dll"),
        ):
            with self.subTest(system=system):
                names = audit.dependencies(text, system)
                self.assertIn(expected, names)
                with self.assertRaises(ValueError):
                    audit.validate_dependencies(names)
        self.assertEqual(
            audit.dependencies("Import {\n  Name: KERNEL32.dll\n}\n", "Windows"),
            ["KERNEL32.dll"])
        audit.validate_dependencies(["libsaltscore_cnet.so.0.1", "bcrypt.dll", "crypt32.dll"])


if __name__ == "__main__":
    unittest.main()
