#!/usr/bin/env python3
"""Audit the real CNet link against two separately owned static archives.

GmSSL::GmSSL supplies native TLS/algorithm definitions from libgmssl.a;
Salts::Crypto supplies first-party facade definitions from libsalts_crypto.a.
CNet may extract both into the single production DSO. Neither plugin nor its
loader may extract either archive. Link maps remain mandatory on every OS.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


NATIVE_SYMBOLS = (
    "tls_ctx_init", "tls_ctx_cleanup", "tls_init", "tls_cleanup", "tls_set_io",
    "tls_do_handshake", "tls_send", "tls_recv", "tls_shutdown",
    "tls_get_peer_certificate", "tls_get_peer_certificate_sha256",
    "tls_export_keying_material",
)
FACADE_SYMBOLS = (
    "crypto_tls_session_handshake", "crypto_tls_session_create_auth_v1_3",
    "crypto_tls_cipher_bio_create", "salts_crypto_sha256",
    "salts_crypto_ed448_sign",
)
ARCHIVE_SYMBOLS = NATIVE_SYMBOLS + FACADE_SYMBOLS
CRYPTO_MEMBER = re.compile(
    r"(?:^|[/\\\s])(?:lib)?salts_crypto(?:[.](?:a|lib))?(?:\(|:)", re.I)
GMSSL_MEMBER = re.compile(
    r"(?:^|[/\\\s])(?:lib)?gmssl(?:[.](?:a|lib))?(?:\(|:)", re.I)
GMSSL_ARCHIVE = re.compile(
    r"(?:^|[/\\\s])(?:lib)?gmssl(?:[.](?:a|lib))?(?:\(|:|[\s]|$)", re.I)
CRYPTO_ARCHIVE = re.compile(
    r"(?:^|[/\\\s])(?:lib)?salts_crypto(?:[.](?:a|lib))?(?:\(|:|[\s]|$)", re.I)
EXTERNAL_CRYPTO = re.compile(
    r"^(?:lib)?(?:gmssl|ssl|crypto|salts_crypto)(?:[-.]|$)", re.I)
EXTERNAL_ARCHIVE = re.compile(
    r"(?:^|[/\\\s])(?:lib)?(?:ssl|crypto)[.](?:a|lib)(?:[\s(:]|$)",
    re.I | re.M)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(arguments):
    result = subprocess.run(arguments, text=True, capture_output=True)
    require(result.returncode == 0,
            f"symbol/dependency reader failed: {arguments[0]}: {result.stderr[-2000:]}")
    return result.stdout


def normalized(name, system):
    if system == "Darwin":
        name = name.removeprefix("_")
    return name.split("@@", 1)[0]


def coff_archive_definitions(output):
    """Count definitions using each COFF member's section-selection records.

    DUMPBIN /SYMBOLS marks both strong functions and mergeable CRT inline/data
    definitions External. The section's STATIC auxiliary record distinguishes
    them; its SECT index is local to one archive member, never the whole archive.
    See Microsoft's PE format, "COMDAT Sections (Object Only)", and /SYMBOLS:
    https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    https://learn.microsoft.com/en-us/cpp/build/reference/symbols
    """
    result = Counter()
    sections = {}
    symbols = []
    pending_section = None
    # ANY, SAME_SIZE, EXACT_MATCH and LARGEST permit linker coalescing. Ordinary
    # sections and NODUPLICATES (including /Gy functions) remain strong. Treat
    # associative sections conservatively as strong: their eligibility depends
    # on another section and cannot be inferred from this selection alone.
    coalescible = {2, 3, 4, 6}

    def finish_member():
        for name, section in symbols:
            selection = sections.get(section, 0)
            # Required native/facade entries must exist in exactly one physical
            # member even if a compiler puts them in a mergeable COMDAT section.
            if name in ARCHIVE_SYMBOLS or selection not in coalescible:
                result[name] += 1
        sections.clear()
        symbols.clear()

    for line in output.splitlines():
        if re.match(r"^\s*(?:COFF SYMBOL TABLE|Archive member name at\b|"
                    r"Dump of file\b|String Table Size\b)", line):
            finish_member()
            pending_section = None
            continue
        match = re.match(
            r"^\s*[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+"
            r"(SECT[0-9A-Fa-f]+|UNDEF|ABS|DEBUG)\s+.*?\b"
            r"(Static|External|WeakExternal)\s*\|\s*(\S+)", line)
        if match:
            section, storage, name = match.groups()
            pending_section = None
            if section.startswith("SECT"):
                section = section.upper()
                if storage == "Static":
                    pending_section = section
                elif storage == "External":
                    symbols.append((name, section))
            continue
        if line.lstrip().startswith("Section length"):
            require(pending_section is not None,
                    "COFF section auxiliary record has no section symbol")
            selection = 0
            if re.search(r"\bselection\b", line, re.I):
                match = re.search(r"\bselection\s+(\d+)\b", line, re.I)
                require(match is not None, "unrecognized COFF COMDAT selection")
                selection = int(match[1])
                require(selection in range(7), "unknown COFF COMDAT selection: " + str(selection))
            require(pending_section not in sections or sections[pending_section] == selection,
                    "conflicting COFF section-selection records")
            sections[pending_section] = selection
            pending_section = None
            continue
        require(not ("External" in line and re.search(r"\bSECT[0-9A-Fa-f]+\b", line)),
                "unrecognized COFF defined-symbol record")
        # Other symbol kinds (for example Filename) cannot lend their auxiliary
        # metadata to a preceding STATIC section record.
        if re.match(r"^\s*[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+", line):
            pending_section = None
    finish_member()
    return result


def archive_definitions(output, system):
    """Count strong definitions, retaining duplicate members in the archive."""
    looks_like_dumpbin = (
        "COFF SYMBOL TABLE" in output or
        re.search(r"\bSECT[0-9A-Fa-f]+\b.*\b(?:Static|External)\b", output) or
        "Section length" in output
    )
    if system == "Windows" and looks_like_dumpbin:
        return coff_archive_definitions(output)
    result = Counter()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[-2] not in ("T", "D", "B", "R", "S", "G", "C"):
            continue
        name = normalized(fields[-1], system)
        if name.startswith((".", "__", "$")):
            continue
        result[name] += 1
    return result


def nm_archive_members(output, system):
    """Map each definition to its physical member in llvm-nm archive output."""
    result = defaultdict(set)
    for line in output.splitlines():
        parts = line.rsplit(":", 2)
        if len(parts) != 3:
            continue
        member, record = parts[1].strip(), parts[2].split()
        if len(record) < 3 or record[-2] not in ("T", "D", "B", "R", "S", "G", "C"):
            continue
        name = normalized(record[-1], system)
        if name in ARCHIVE_SYMBOLS:
            result[name].add(member.replace("\\", "/").rsplit("/", 1)[-1])
    return result


def validate_archive(definitions, required, label):
    missing = {name: definitions[name] for name in required
               if definitions[name] != 1}
    require(not missing, label + " required definitions missing or duplicated: " + str(missing))
    duplicates = {name: count for name, count in definitions.items() if count > 1}
    require(not duplicates, "duplicate strong " + label + " archive definitions: " +
            str(duplicates))


def validate_archives(gmssl_definitions, crypto_definitions):
    validate_archive(gmssl_definitions, NATIVE_SYMBOLS, "GmSSL")
    validate_archive(crypto_definitions, FACADE_SYMBOLS, "Crypto")
    collisions = sorted(set(gmssl_definitions) & set(crypto_definitions))
    require(not collisions, "cross-archive duplicate strong definitions: " + str(collisions))
    # A local second TLS protocol engine is forbidden, even if a particular
    # symbol was not part of our mandatory native ABI sampling list.
    embedded_tls = sorted(name for name in crypto_definitions
                          if name.startswith(("tls_", "tlcp_")))
    require(not embedded_tls, "Crypto embeds native TLS/TLCP implementation: " +
            str(embedded_tls))
    foreign_facade = sorted(name for name in gmssl_definitions
                            if name.startswith(("crypto_tls_", "salts_crypto_")))
    require(not foreign_facade, "GmSSL embeds the first-party Crypto facade: " +
            str(foreign_facade))

def map_definitions(text, system):
    """Read the selected physical member for each required native TLS symbol."""
    result = defaultdict(list)
    if system == "Darwin":
        objects = {}
        for line in text.splitlines():
            match = re.match(r"^\[\s*(\d+)\]\s+(.+)$", line)
            if match:
                objects[match[1]] = match[2].strip()
            match = re.match(
                r"^\s*0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+\[\s*(\d+)\]\s+(\S+)",
                line)
            if match:
                name = normalized(match[2], system)
                if name in ARCHIVE_SYMBOLS:
                    result[name].append(objects.get(match[1], "unidentified object"))
    elif system == "Windows":
        if re.search(r"(?m)^Address\s+Size\s+Align\s+Out\s+In\s+Symbol\s*$", text):
            owner = ""
            for line in text.splitlines():
                object_match = re.match(
                    r"^\s*[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+\d+\s+(.+?[.]obj):\(", line)
                if object_match:
                    owner = object_match[1].replace("\\", "/").rsplit("/", 1)[-1]
                    continue
                symbol_match = re.match(
                    r"^\s*[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+\d+\s+"
                    r"([A-Za-z_][A-Za-z_0-9]*)\s*$", line)
                if (symbol_match and symbol_match[1] in ARCHIVE_SYMBOLS and owner and
                        owner not in result[symbol_match[1]]):
                    result[symbol_match[1]].append(owner)
        else:
            for line in text.splitlines():
                match = re.match(
                    r"^\s*[0-9a-fA-F]+:[0-9a-fA-F]+\s+(\S+)\s+[0-9a-fA-F]+"
                    r"(?:\s+[fi])*\s+(\S+)\s*$", line)
                if match and match[1] in ARCHIVE_SYMBOLS:
                    result[match[1]].append(match[2])
    else:
        owner = ""
        object_pattern = re.compile(r"(\S+[.](?:a|lib)\([^)]+\)|\S+[.](?:o|obj))")
        for line in text.splitlines():
            obj = object_pattern.search(line)
            if obj:
                owner = obj[1]
            match = re.match(
                r"^\s*(?:(?:0x)?[0-9a-fA-F]+\s+)+([A-Za-z_][A-Za-z_0-9]*)\s*$",
                line)
            if match and match[1] in ARCHIVE_SYMBOLS:
                result[match[1]].append(owner)
    return result


def validate_runtime_map(text, system, gmssl_members=None, crypto_members=None):
    require(not EXTERNAL_ARCHIVE.search(text),
            "production link selected another SSL/crypto archive")
    definitions = map_definitions(text, system)
    lld_mingw = system == "Windows" and re.search(
        r"(?m)^Address\s+Size\s+Align\s+Out\s+In\s+Symbol\s*$", text)
    invalid_native = {}
    for name in NATIVE_SYMBOLS:
        owners = definitions[name]
        valid = len(owners) == 1
        if valid and lld_mingw:
            valid = gmssl_members is not None and gmssl_members.get(name) == {owners[0]}
        elif valid:
            valid = GMSSL_MEMBER.search(owners[0]) is not None
        if not valid:
            invalid_native[name] = owners
    require(not invalid_native, "production native TLS is not supplied once by GmSSL: " +
            str(invalid_native))
    # A static linker can omit unused Crypto facade members from CNet; when
    # they ARE selected, every physical definition must come from Crypto only.
    invalid_facade = {}
    for name in FACADE_SYMBOLS:
        owners = definitions[name]
        if not owners:
            continue
        valid = len(owners) == 1
        if valid and lld_mingw:
            valid = crypto_members is not None and crypto_members.get(name) == {owners[0]}
        elif valid:
            valid = CRYPTO_MEMBER.search(owners[0]) is not None
        if not valid:
            invalid_facade[name] = owners
    require(not invalid_facade, "production facade is not supplied by Salts::Crypto: " +
            str(invalid_facade))
    return dict(definitions)

def validate_peer_map(text):
    require(not CRYPTO_ARCHIVE.search(text) and not GMSSL_ARCHIVE.search(text),
            "consumer/plugin link contains a copied static Crypto/GmSSL archive")
    require(not EXTERNAL_ARCHIVE.search(text),
            "consumer/plugin link contains another SSL/crypto archive")
    for symbol in NATIVE_SYMBOLS:
        require(re.search(r"(?<![A-Za-z_0-9])_?" + re.escape(symbol) +
                          r"(?![A-Za-z_0-9])", text) is None,
                "consumer/plugin defines or directly imports native TLS: " + symbol)


def dependencies(output, system):
    if system == "Windows":
        return re.findall(
            r"(?im)^(?:\s+|\s*Name:\s*)([^\s/\\]+[.]dll)\s*$", output)
    if system == "Darwin":
        return [line.strip().split(" ", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]
                for line in output.splitlines()[1:] if line.strip()]
    return re.findall(r"\(NEEDED\)[^\n]*\[([^\]]+)\]", output)


def validate_dependencies(names):
    forbidden = [name for name in names if EXTERNAL_CRYPTO.match(name)]
    require(not forbidden, "independent Crypto/GmSSL runtime dependency: " + str(forbidden))


def inspect(args):
    files = [args.archive, args.gmssl_archive, args.runtime, args.map,
             *args.peer, *args.peer_map]
    require(all(path.is_file() for path in files), "required native artifact/link map missing")
    require(len(args.peer) == 3 and len(args.peer_map) == 3,
            "require both actual production plugins and their loader")
    if args.system == "Windows":
        reader = args.nm
        require(reader, "COFF symbol reader required")
    else:
        reader = args.nm or shutil.which("nm")
        require(reader, "native nm required")
    dumpbin = args.system == "Windows" and "dumpbin" in Path(reader).name.lower()

    def read_symbols(path):
        if dumpbin:
            return command([reader, "/nologo", "/symbols", str(path)])
        if args.system == "Windows":
            return command([reader, "-g", "--defined-only", "--print-file-name",
                            str(path)])
        return command([reader, "-g", str(path)])

    crypto_symbols = read_symbols(args.archive)
    gmssl_symbols = read_symbols(args.gmssl_archive)
    crypto_table = archive_definitions(crypto_symbols, args.system)
    gmssl_table = archive_definitions(gmssl_symbols, args.system)
    validate_archives(gmssl_table, crypto_table)
    gmssl_members = (nm_archive_members(gmssl_symbols, args.system)
                     if args.system == "Windows" and not dumpbin else None)
    crypto_members = (nm_archive_members(crypto_symbols, args.system)
                      if args.system == "Windows" and not dumpbin else None)
    ownership = validate_runtime_map(
        args.map.read_text(errors="replace"), args.system,
        gmssl_members=gmssl_members, crypto_members=crypto_members)
    for path in args.peer_map:
        validate_peer_map(path.read_text(errors="replace"))
    imports = {}
    for path in [args.runtime, *args.peer]:
        if args.system == "Windows":
            if dumpbin:
                output = command([reader, "/nologo", "/dependents", str(path)])
            else:
                object_reader = args.readobj or shutil.which("llvm-readobj")
                require(object_reader, "llvm-readobj required for COFF imports")
                output = command([object_reader, "--coff-imports", str(path)])
        elif args.system == "Darwin":
            output = command(["otool", "-L", str(path)])
        else:
            readelf = args.readelf or shutil.which("readelf")
            require(readelf, "native readelf required")
            output = command([readelf, "-d", str(path)])
        names = dependencies(output, args.system)
        validate_dependencies(names)
        imports[str(path)] = names
    # Both modules must directly load the real CNet shared image. The loader
    # intentionally has no CNet import and opens those modules at runtime.
    for path in args.peer[:2]:
        require(any(re.search(r"(?:lib)?saltscore_cnet(?:[-.]|$)", name, re.I)
                    for name in imports[str(path)]),
                "production plugin does not import the real CNet owner: " + str(path))
    return {"ok": True, "crypto_archive": str(args.archive),
            "gmssl_archive": str(args.gmssl_archive), "runtime": str(args.runtime),
            "crypto_strong_definitions": len(crypto_table),
            "gmssl_strong_definitions": len(gmssl_table),
            "native_owners": ownership, "imports": imports,
            "scope": "production-two-archive-native-link-not-facade-parity"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--gmssl-archive", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--system", required=True)
    parser.add_argument("--nm", default="")
    parser.add_argument("--readelf", default="")
    parser.add_argument("--readobj", default="")
    parser.add_argument("--peer", action="append", type=Path, default=[])
    parser.add_argument("--peer-map", action="append", type=Path, default=[])
    try:
        print(json.dumps(inspect(parser.parse_args()), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print("CNet native Crypto owner: FAIL: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
