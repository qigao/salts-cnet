"""Native source identity is provided by the pinned GmSSL vcpkg package."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "local_native_source", ROOT / "crypto/tools/check_local_native_source.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class NativeSourceAdmission(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads(CHECK.LOCK.read_text(encoding="utf-8"))

    def test_reviewed_vcpkg_source_and_all_extensions(self):
        self.assertEqual(CHECK.verify(), 15)

    def test_unrecognized_or_duplicated_extension_rejected(self):
        for mutate in ("missing", "duplicate", "traversal"):
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(self.lock)
                if mutate == "missing":
                    changed["original_inputs"].pop()
                elif mutate == "duplicate":
                    changed["original_inputs"][1]["path"] = changed["original_inputs"][0]["path"]
                else:
                    changed["original_inputs"][1]["path"] = "../unsafe.h"
                with self.assertRaises(ValueError):
                    CHECK.verify_lock(changed)

    def test_wrong_package_tree_or_version_rejected(self):
        for key, value in (("port_tree", "0"*40), ("port_version", 15)):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.lock)
                changed["package"][key] = value
                with self.assertRaises(ValueError):
                    CHECK.verify_lock(changed)

    def test_wrong_release_reference_or_baseline_rejected(self):
        for key, value in (
            ("registry_reference", "master"),
            ("registry_reference", "v0.1.1"),
            ("registry_commit", "0" * 40),
        ):
            with self.subTest(key=key, value=value):
                changed = copy.deepcopy(self.lock)
                changed["package"][key] = value
                with self.assertRaisesRegex(ValueError, "unreviewed GmSSL"):
                    CHECK.verify_lock(changed)
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "vcpkg-configuration.json"
            original = json.loads(CHECK.REGISTRY.read_text(encoding="utf-8"))
            for key, value in (
                ("reference", "master"),
                ("reference", CHECK.EXPECTED_REGISTRY),
                ("baseline", "v0.1.0"),
                ("baseline", "0" * 40),
            ):
                with self.subTest(key=key, value=value):
                    wrong = copy.deepcopy(original)
                    wrong["registries"][0][key] = value
                    config.write_text(json.dumps(wrong), encoding="utf-8")
                    with patch.object(CHECK, "REGISTRY", config):
                        with self.assertRaisesRegex(ValueError, "GmSSL registry must"):
                            CHECK.verify_manifest(self.lock)

    def test_changed_extension_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "gmssl-extensions"
            shutil.copytree(CHECK.NATIVE, root)
            example = root / self.lock["original_inputs"][0]["path"]
            example.write_bytes(example.read_bytes() + b"\n/* corrupted */\n")
            with patch.object(CHECK, "NATIVE", root):
                with self.assertRaisesRegex(ValueError, "modified original"):
                    CHECK.verify()

    def test_local_gmssl_source_mirror_cannot_return(self):
        with tempfile.TemporaryDirectory() as temp:
            local = Path(temp) / "native-gmssl"
            local.mkdir()
            (local / "duplicate.c").write_text("int duplicate(void) { return 0; }")
            with patch.object(CHECK, "LOCAL_NATIVE", local):
                with self.assertRaisesRegex(ValueError, "mirrored native"):
                    CHECK.verify_manifest(self.lock)


if __name__ == "__main__":
    unittest.main()
