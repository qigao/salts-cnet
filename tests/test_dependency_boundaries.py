"""Test the standalone dependency-closure gate without external packages."""
from pathlib import Path
import importlib.util
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tools/check_dependency_boundaries.py"
spec = importlib.util.spec_from_file_location("dependency_gate", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DependencyGateTest(unittest.TestCase):
    def check_text(self, content: str, suffix: str = ".c") -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ("source" + suffix)
            path.write_text(content, encoding="utf-8")
            return module.check_repository(Path(directory))

    def test_native_historical_symbol_is_not_cmeta_runtime(self):
        self.assertEqual(self.check_text("int cmeta_fs_stat(void *arg);\n"), [])

    def test_legacy_cmake_package_and_target_rejected(self):
        output = self.check_text("find_package(Salts CONFIG REQUIRED)\n"
                                 "target_link_libraries(app PRIVATE Salts::CFlow)\n",
                                 ".cmake")
        self.assertEqual(len(output), 2)


    def test_native_cpp_type_namespace_is_not_a_cmake_target(self):
        sample = (
            "#include <cmeta_uuid.h>\n"
            "namespace Salts { struct UUID { unsigned char bytes[16]; }; }\n"
            "Salts::UUID id{};\n"
            "static_assert(sizeof(Salts::UUID) == 16, \"UUID ABI\");\n"
        )
        self.assertEqual(self.check_text(sample, ".cpp"), [])
        self.assertEqual(self.check_text(sample, ".hpp"), [])

    def test_same_high_level_name_is_still_denied_as_cmake_link_target(self):
        sample = "target_link_libraries(app PRIVATE Salts::UUID)\n"
        self.assertEqual(len(self.check_text(sample, ".cmake")), 1)
        self.assertEqual(len(self.check_text(sample, ".cpp")), 0)

    def test_cmeta_reflection_remains_denied_in_c_and_cpp(self):
        for suffix in (".c", ".cpp", ".hpp"):
            self.assertEqual(
                len(self.check_text("#include <cmeta/struct.h>\n", suffix)),
                1)
            self.assertEqual(
                len(self.check_text("CMETA_STRUCT(MyType, (int, x));\n", suffix)),
                1)

    def test_native_salts_targets_are_allowed(self):
        content = ("add_library(Salts::Platform ALIAS saltscore_platform)\n"
                   "target_link_libraries(app PRIVATE Salts::Core Salts::NativeIO)\n")
        self.assertEqual(self.check_text(content, ".cmake"), [])

    def test_owned_native_extra_targets_allowed_without_old_aliases(self):
        content = ("add_library(Salts::Unicode ALIAS saltscore_unicode)\n"
                   "target_link_libraries(app PRIVATE Salts::IDNA Salts::CSerde Salts::TinyTest)\n")
        self.assertEqual(self.check_text(content, ".cmake"), [])

    def test_migrated_simd_target_is_denied(self):
        self.assertEqual(len(self.check_text(
            "target_link_libraries(app PRIVATE Salts::SIMD)\n", ".cmake")), 1)

    def test_canonical_crypto_is_allowed_but_split_tls_is_not(self):
        self.assertEqual(
            self.check_text("target_link_libraries(app PRIVATE Salts::Crypto)\n",
                            ".cmake"), [])
        self.assertEqual(len(self.check_text(
            "target_link_libraries(app PRIVATE Salts::TLS)\n", ".cmake")), 1)
        self.assertEqual(len(self.check_text(
            "target_link_libraries(app PRIVATE Crypto::TLS)\n", ".cmake")), 1)

    def test_single_static_crypto_negative_guard_is_not_a_dependency(self):
        guard = (
            "foreach(_forbidden IN ITEMS\n"
            "  Salts::TLS Salts::TLSCipherBIO Salts::CryptoProvider\n"
            "  Crypto::TLS Crypto::TLSCipherBIO Crypto::Provider)\n"
            '  if(TARGET "${_forbidden}")\n'
            '    message(FATAL_ERROR "Second static Crypto owner is forbidden")\n'
            "  endif()\n"
            "endforeach()\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cmake = root / "tests" / "cnet-crypto-static"
            cmake.mkdir(parents=True)
            guard_file = cmake / "CMakeLists.txt"
            guard_file.write_text(guard, encoding="utf-8")
            self.assertEqual(module.check_repository(root), [])

            # Any real provider link next to negative guard remains forbidden.
            guard_file.write_text(
                guard + "target_link_libraries(app PRIVATE Crypto::TLS)\n",
                encoding="utf-8")
            self.assertEqual(len(module.check_repository(root)), 1)

            # Same deny-list words in another file still trigger scan.
            guard_file.write_text(guard, encoding="utf-8")
            (root / "extra.cmake").write_text(guard, encoding="utf-8")
            self.assertEqual(len(module.check_repository(root)), 2)

            # A renamed or non-fatal guard cannot hide dependencies.
            (root / "extra.cmake").unlink()
            guard_file.write_text(
                guard.replace("foreach(_forbidden IN ITEMS",
                              "set(_forbidden"), encoding="utf-8")
            self.assertEqual(len(module.check_repository(root)), 2)

    def test_deleted_consumer_guard_path_has_no_special_exemption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cmake = root / "crypto" / "tests" / "mobile"
            cmake.mkdir(parents=True)
            guard_file = cmake / "CMakeLists.txt"
            guard = (
                "foreach(_split IN ITEMS Salts::TLS Crypto::Crypto)\n"
                "  if(TARGET ${_split})\n"
                "    message(FATAL_ERROR \"split target present\")\n"
                "  endif()\n"
                "endforeach()\n")
            guard_file.write_text(guard, encoding="utf-8")
            self.assertEqual(len(module.check_repository(root)), 2)
            guard_file.write_text(
                guard + "target_link_libraries(app PRIVATE Crypto::Crypto)\n",
                encoding="utf-8")
            self.assertEqual(len(module.check_repository(root)), 3)
            guard_file.write_text(
                guard.replace("message(FATAL_ERROR", "message(STATUS"),
                encoding="utf-8")
            self.assertEqual(len(module.check_repository(root)), 2)

    def test_negative_split_provider_guard_does_not_mask_real_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            d = root / "crypto" / "tests" / "owner"
            d.mkdir(parents=True)
            f = d / "CMakeLists.txt"
            guard = (
                "foreach(_split IN ITEMS Salts::TLS Crypto::ASN1)\n"
                '  if(TARGET "' + chr(36) + '{_split}")\n'
                '    message(FATAL_ERROR "Split provider forbidden")\n'
                "  endif()\n"
                "endforeach()\n"
            )
            f.write_text(guard, encoding="utf-8")
            self.assertEqual(module.check_repository(root), [])
            f.write_text(guard +
                "target_link_libraries(app PRIVATE Crypto::ASN1)\n",
                encoding="utf-8")
            self.assertEqual(len(module.check_repository(root)), 1)
            f.write_text(guard.replace(
                'message(FATAL_ERROR "Split provider forbidden")',
                'message(STATUS "Provider enabled")'), encoding="utf-8")
            # Both Salts::TLS and Crypto::ASN1 are now exposed, so both
            # must remain independently RED. Never weaken the scanner.
            self.assertEqual(len(module.check_repository(root)), 2)

    def test_first_party_asn1_rejects_alternate_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            d = root / "crypto" / "tests" / "owner"
            d.mkdir(parents=True)
            f = d / "CMakeLists.txt"
            f.write_text(
                "if(TARGET SaltsCore::ASN1 OR TARGET Crypto::ASN1)\n"
                '  message(FATAL_ERROR "No duplicate ASN1")\n'
                "endif()\n", encoding="utf-8")
            self.assertEqual(module.check_repository(root), [])
            f.write_text("target_link_libraries(app PRIVATE Crypto::ASN1)\n",
                         encoding="utf-8")
            self.assertEqual(len(module.check_repository(root)), 1)

    def test_canonical_asn1_allowed_but_legacy_targets_rejected(self):
        self.assertEqual(
            self.check_text("target_link_libraries(app PRIVATE Salts::ASN1)\n",
                            ".cmake"), [])
        for obsolete in ("Salts::CryptoASN1", "Salts::ASN1Legacy",
                         "SaltsCore::ASN1", "Crypto::ASN1"):
            with self.subTest(obsolete=obsolete):
                self.assertEqual(len(self.check_text(
                    f"target_link_libraries(app PRIVATE {obsolete})\n",
                    ".cmake")), 1)

    def test_deleted_installed_consumer_paths_have_no_exemption(self):
        guards = {
            "asn1/tests/installed/CMakeLists.txt": (
                'foreach(_forbidden IN ITEMS Salts::Crypto Salts::CMeta Salts::Core\n'
                '  GmSSL::GmSSL Crypto::ASN1 SaltsNet::Asn1Parser)\n'
                '  if(TARGET "${_forbidden}")\n'
                '    message(FATAL_ERROR "Unexpected imported target")\n'
                '  endif()\n'
                'endforeach()\n'
            ),
            "crypto/tests/asn1/installed/CMakeLists.txt": (
                'if(TARGET SaltsCore::ASN1 OR TARGET Crypto::ASN1)\n'
                '  message(FATAL_ERROR "Duplicate ASN1 owner")\n'
                'endif()\n'
            ),
        }
        for rel, guard in guards.items():
            with self.subTest(path=rel), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                p = root / rel
                p.parent.mkdir(parents=True)
                p.write_text(guard, encoding="utf-8")
                self.assertTrue(module.check_repository(root))

    def test_negative_guards_in_unapproved_paths_still_fail(self):
        guard = ('foreach(_split IN ITEMS Salts::TLS Crypto::ASN1)\n'
                 '  if(TARGET ${_split})\n'
                 '    message(FATAL_ERROR "split owner")\n'
                 '  endif()\n'
                 'endforeach()\n')
        # Both Salts::TLS and Crypto::ASN1 are forbidden outside an approved guard.
        self.assertEqual(len(self.check_text(guard, ".cmake")), 2)

    def test_comments_are_not_links_but_compiled_dependencies_are(self):
        self.assertEqual(self.check_text(
            '/* Description:\n * Never link Crypto::TLS or private code\n */\n'), [])
        self.assertEqual(self.check_text(
            '# This check forbids Crypto::TLS\n', ".cmake"), [])
        self.assertEqual(len(self.check_text(
            '/* unrelated comment */\n#include <cflow/executor.h>\n')), 1)
        self.assertEqual(len(self.check_text(
            '#if 0\n#include <cmeta/struct.h>\n#endif\n')), 1)

    def test_alternate_namespaces_rejected(self):
        content = ("target_link_libraries(a PRIVATE SaltsCore::Platform)\n"
                   "target_link_libraries(b PRIVATE Crypto::TLS)\n"
                   "target_link_libraries(c PRIVATE SaltsCrypto::Crypto)\n")
        self.assertEqual(len(self.check_text(content, ".cmake")), 3)

    def test_reflection_and_actor_includes_rejected(self):
        self.assertEqual(len(self.check_text("#include <cmeta/struct.h>\n"
                                             "#include <cflow/executor.h>\n"
                                             "#include <cstl.h>\n")), 3)

    def test_metadata_macro_rejected(self):
        self.assertEqual(len(self.check_text("CMETA_STRUCT(vstr, (const char *, data));\n")), 1)


if __name__ == "__main__":
    unittest.main()
