#!/usr/bin/env python3
"""Verify a vcpkg-cache GmSSL port and, optionally, its installed static SDK.

This is a local/manual source-owner check, not a CI runner or installer.
It never downloads source, modifies the vcpkg port or selects a fallback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

# qigao/vcpkg-cache PR #214, merged as d2ce09ebd3cf127338eea5c8d87a588aeb9d127c
# The complete port tree, not just a manifest/portfile hash.
EXPECTED_PORT_TREE = "9eee73ae12ad32e499425f8cc28b740c5f84d89e"
EXPECTED_FILES = {
    "portfile.cmake": "e9d5fa752330900fdfe0525744e14c35cc62633d",
    "vcpkg.json": "c5346f31c9c335c4b9923da95098cfa1654958fc",
    "GmSSLConfig.cmake": "6539349471a849b4d613cbb9b1f05cd6ece313d1",
}


def object_id(kind: str, data: bytes) -> str:
    return hashlib.sha1(
        f"{kind} {len(data)}\0".encode("ascii") + data
    ).hexdigest()


def tree_id(directory: Path) -> str:
    entries = []
    for path in directory.iterdir():
        if path.is_symlink():
            raise ValueError(f"symlink not permitted in pinned GmSSL port: {path}")
        if path.is_dir():
            mode, obj_id, suffix = b"40000", tree_id(path), b"/"
        elif path.is_file():
            mode, obj_id, suffix = b"100644", object_id("blob", path.read_bytes()), b""
        else:
            raise ValueError(f"unsupported GmSSL port filesystem entry: {path}")
        entries.append((path.name.encode("utf-8"), suffix, mode, obj_id))
    entries.sort(key=lambda part: part[0] + part[1])
    payload = b"".join(
        mode + b" " + name + b"\0" + bytes.fromhex(obj_id)
        for name, _, mode, obj_id in entries
    )
    return object_id("tree", payload)


def resolve_port(explicit: Path | None) -> Path:
    if explicit is not None:
        port = explicit.resolve(strict=True)
        if not port.is_dir() or port.name != "gmssl":
            raise ValueError("--port must point to the vcpkg-cache ports/gmssl directory")
        return port
    for entry in os.environ.get("VCPKG_OVERLAY_PORTS", "").split(os.pathsep):
        if entry and (Path(entry) / "gmssl").is_dir():
            return (Path(entry) / "gmssl").resolve(strict=True)
    raise ValueError("provide --port or VCPKG_OVERLAY_PORTS; no fallback registry")


def verify_port(port: Path) -> None:
    actual = tree_id(port)
    if actual != EXPECTED_PORT_TREE:
        raise ValueError(f"incorrect complete GmSSL port tree {actual}; expected {EXPECTED_PORT_TREE}")
    for name, expected in EXPECTED_FILES.items():
        actual_file = object_id("blob", (port / name).read_bytes())
        if actual_file != expected:
            raise ValueError(f"incorrect source-controlled GmSSL file: {name}")
    manifest = json.loads((port / "vcpkg.json").read_text(encoding="utf-8"))
    if (manifest.get("name"), manifest.get("version"), manifest.get("port-version")) != (
        "gmssl", "3.2.0", 17
    ):
        raise ValueError("require exact GmSSL 3.2.0#17 from qigao/vcpkg-cache")


def verify_installed(prefix: Path) -> None:
    name = "gmssl.lib" if os.name == "nt" else "libgmssl.a"
    for rel in ("share/gmssl/GmSSLConfig.cmake", "share/gmssl/copyright",
                "include/gmssl/sm3.h", "include/gmssl/tls.h", f"lib/{name}"):
        p = prefix / rel
        if not p.is_file() or p.stat().st_size == 0:
            raise ValueError(f"installed vcpkg GmSSL SDK incomplete: {p}")
    for rel in ("lib/gmssl.dll", "lib/libgmssl.so", "lib/libgmssl.dylib"):
        if (prefix / rel).exists():
            raise ValueError(f"dynamic GmSSL binary forbidden: {prefix / rel}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=Path, help="qigao/vcpkg-cache/ports/gmssl")
    parser.add_argument("--prefix", type=Path, help="optional installed target triplet prefix")
    args = parser.parse_args()
    try:
        port = resolve_port(args.port)
        verify_port(port)
        if args.prefix is not None:
            verify_installed(args.prefix.resolve(strict=True))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL GmSSL port source ownership: {error}", file=sys.stderr)
        return 1
    print(f"PASS GmSSL 3.2.0#17: immutable full port tree {EXPECTED_PORT_TREE}")
    if args.prefix is not None:
        print("PASS installed GmSSL static input " + str(args.prefix))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
