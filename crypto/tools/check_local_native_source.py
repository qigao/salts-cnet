#!/usr/bin/env python3
"""Verify pinned GmSSL vcpkg provider and exact extension blobs.

This is the existing source-admission gate, repurposed for the externally
installed GmSSL provider. It never downloads, builds or patches a provider.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "crypto/gmssl-extensions"
LOCK = NATIVE / "source-lock.json"
VCPKG_MANIFEST = ROOT / "vcpkg.json"
REGISTRY = ROOT / "vcpkg-configuration.json"
CRYPTO_CMAKE = ROOT / "crypto/CMakeLists.txt"
LOCAL_NATIVE = ROOT / "crypto/native/gmssl"
EXPECTED_SOURCE_SHA = "720abc55eca41cc7f676d0b5dbb38e8605d091b9"
EXPECTED_PORT_TREE = "9eee73ae12ad32e499425f8cc28b740c5f84d89e"
EXPECTED_REGISTRY = "05a10d73a5b1d01598e59d8cf34074513bd49df4"
EXPECTED_REGISTRY_VERSION = "v0.1.0"
EXPECTED_UPSTREAM = "7c9f02904ef33e59c87b4f16621cc8fd434e7579"


def git_blob(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def verify_lock(lock: dict) -> int:
    require = lambda condition, message: condition or (_fail(message))
    require(lock.get("schema") == 2 and lock.get("owner") == "Salts::Crypto"
            and lock.get("provider") == "GmSSL::GmSSL",
            "noncanonical GmSSL package owner")
    package = lock["package"]
    require((package.get("name"), package.get("version"), package.get("port_version")) ==
            ("gmssl", "3.2.0", 17), "wrong pinned GmSSL vcpkg version")
    require(package.get("port_tree") == EXPECTED_PORT_TREE
            and package.get("registry_commit") == EXPECTED_REGISTRY
            and package.get("registry_reference") == EXPECTED_REGISTRY_VERSION,
            "unreviewed GmSSL port revision or registry")
    require(lock["upstream"].get("commit") == EXPECTED_UPSTREAM,
            "unpinned GmSSL upstream source")
    require(lock["source_checkout"].get("commit") == EXPECTED_SOURCE_SHA
            and lock["source_checkout"].get("directory") == "crypto/gmssl-extensions",
            "unpinned extension checkout")
    files = lock["original_inputs"]
    require(len(files) == 15, "incomplete original extension inventory")
    paths = [entry["path"] for entry in files]
    require(len(set(paths)) == len(paths), "duplicate extension input")
    require(all(path.startswith(("src/", "include/gmssl/", "patches/"))
                and not Path(path).is_absolute() and ".." not in Path(path).parts
                and Path(path).suffix in (".c", ".h", ".cmake")
                for path in paths), "unsafe or unexpected extension path")
    require(sum(Path(p).suffix == ".c" for p in paths) == 6,
            "missing original extension C implementation")
    return len(files)


def _fail(message: str) -> bool:
    raise ValueError(message)


def verify_manifest(lock: dict) -> None:
    package = lock["package"]
    manifest = json.loads(VCPKG_MANIFEST.read_text(encoding="utf-8"))
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    if "gmssl" not in manifest.get("dependencies", []):
        raise ValueError("GmSSL must be declared in root vcpkg.json")
    matches = [item for item in registry.get("registries", [])
               if "gmssl" in item.get("packages", [])]
    if (len(matches) != 1
        or matches[0].get("repository") != package.get("registry_repository")
        or matches[0].get("reference") != EXPECTED_REGISTRY_VERSION
        or matches[0].get("baseline") != EXPECTED_REGISTRY):
        raise ValueError("GmSSL registry must be immutable and unique")
    cmake = CRYPTO_CMAKE.read_text(encoding="utf-8")
    if ("find_package(GmSSL CONFIG REQUIRED)" not in cmake
        or "GmSSL::GmSSL" not in cmake
        or "salts_crypto_native_objects" in cmake
        or "add_subdirectory(native/gmssl)" in cmake):
        raise ValueError("Crypto must import one vcpkg GmSSL target, not compile a mirror")
    if LOCAL_NATIVE.exists() and any(
        p.is_file() and p.suffix in (".c", ".h")
        for p in LOCAL_NATIVE.rglob("*")
    ):
        raise ValueError("mirrored native GmSSL C/H tree is still present")
    if package.get("port_tree") != EXPECTED_PORT_TREE:
        raise ValueError("unexpected GmSSL package tree")


def verify() -> int:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    count = verify_lock(lock)
    expected = set(item["path"] for item in lock["original_inputs"])
    actual = set(path.relative_to(NATIVE).as_posix()
                 for path in NATIVE.rglob("*") if path.is_file()
                 and path.name not in ("README.md", "source-lock.json"))
    if actual != expected:
        raise ValueError("extension files missing or added: " + str(sorted(actual ^ expected)))
    for entry in lock["original_inputs"]:
        p = NATIVE / entry["path"]
        if git_blob(p.read_bytes()) != entry["git_blob"]:
            raise ValueError("modified original extension bytes: " + entry["path"])
    verify_manifest(lock)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        count = verify()
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as error:
        print("FAIL pinned GmSSL vcpkg source: " + str(error), file=sys.stderr)
        return 1
    print(f"PASS: {count} immutable Crypto extension inputs; gmssl 3.2.0#17 from vcpkg registry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
