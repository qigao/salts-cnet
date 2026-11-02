#!/usr/bin/env python3
"""Fail-closed static SDK audit: Crypto, ASN1 and external vcpkg GmSSL.

Crypto and GmSSL are separate physical archives; callers must provide the
installed vcpkg prefix explicitly. This never builds an installer/consumer.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys

GMSSL_SYMBOLS = (
    "sm3_init", "sm3_update", "sm3_finish",
    "sha256_init", "sha256_update", "sha256_finish",
    "tls_init", "tls_set_io", "tls_do_handshake", "tls_send", "tls_recv",
)
CRYPTO_SYMBOLS = (
    "crypto_tls_session_handshake",
    "crypto_tls_auth_abi_version",
    "crypto_tls_session_create_auth_v1_3",
    "crypto_tls_session_client_authenticated_v1_3",
    "crypto_tls_session_export_v1_2",
    "crypto_tls_cipher_bio_create",
    "salts_crypto_sha256", "salts_crypto_ed448_sign",
    "salts_crypto_ed448_verify", "salts_crypto_random_bytes",
    "salts_crypto_libecc_get_random",
    "crypto_asn1_ecdsa_signature_encode",
    "crypto_asn1_ecdsa_signature_decode",
    "crypto_asn1_rfc8410_spki_encode",
    "crypto_asn1_rfc8410_pkcs8_encode",
    "crypto_x509_der_inspect", "crypto_x509_der_chain_next",
    "crypto_x509_der_common_name", "crypto_x509_der_get_public_key_kind",
)
ASN1_SYMBOLS = (
    "salts_asn1_reader_init", "salts_asn1_reader_next",
    "salts_asn1_validate", "salts_asn1_encode_tlv",
    "salts_asn1_value_create", "salts_asn1_value_encode",
    "salts_asn1_value_decode", "salts_asn1_value_free",
    "salts_asn1_value_get_oid",
)
OLD_SYMBOLS = (
    "get_unsafe_random",
    "salts_crypto_libecc_salts_crypto_libecc_get_random",
    "crypto_provider_sm3", "crypto_provider_runtime_abi",
    "crypto_provider_abi_0_1_required",
)

def _defined_symbols(archive: Path) -> Counter[str]:
    command = ["nm", "-gU" if sys.platform == "darwin" else "-g", str(archive)]
    p = subprocess.run(command, capture_output=True, text=True, check=False)
    if p.returncode != 0:
        raise ValueError("native archive symbol reader failed: " + p.stderr[-3000:])
    result: Counter[str] = Counter()
    for line in p.stdout.splitlines():
        # nm prefixes archive object boundaries; only count defined exports.
        m = re.match(r"^\s*(?:[0-9a-fA-F]+\s+)?([A-TV-Z])\s+(\S+)\s*$", line)
        if not m or m.group(1) not in ("T", "D", "B", "R", "S", "C"):
            continue
        symbol = m.group(2)
        if sys.platform == "darwin":
            symbol = symbol.removeprefix("_")
        result[symbol] += 1
    return result

def _check_archive_inventory(prefix: Path, allowed: list[Path]) -> None:
    archives = sorted(
        path for path in prefix.rglob("*")
        if path.is_file() and path.suffix.lower() in
        (".a", ".lib", ".dll", ".dylib", ".so")
    )
    if archives != sorted(allowed):
        raise ValueError(
            "unexpected native binary in installation: " +
            ", ".join(str(path.relative_to(prefix)) for path in archives)
        )
    for path in prefix.rglob("*"):
        if path.is_file() and re.search(r"\.so\.[0-9]+", path.name):
            raise ValueError("versioned shared library forbidden: " + str(path))

def inspect(prefix: Path, asn1_prefix: Path | None = None,
            gmssl_prefix: Path | None = None) -> dict:
    prefix = prefix.resolve(strict=True)
    asn1_prefix = (asn1_prefix or prefix).resolve(strict=True)
    if gmssl_prefix is None:
        raise ValueError("--gmssl-prefix is required for external vcpkg GmSSL")
    gmssl_prefix = gmssl_prefix.resolve(strict=True)
    ext = ".lib" if sys.platform == "win32" else ".a"
    crypto_name = "salts_crypto.lib" if ext == ".lib" else "libsalts_crypto.a"
    asn1_name = "salts_asn1.lib" if ext == ".lib" else "libsalts_asn1.a"
    gmssl_name = "gmssl.lib" if ext == ".lib" else "libgmssl.a"
    crypto_archive = prefix / "lib" / crypto_name
    asn1_archive = asn1_prefix / "lib" / asn1_name
    gmssl_archive = gmssl_prefix / "lib" / gmssl_name
    if not all(path.is_file() for path in
               (crypto_archive, asn1_archive, gmssl_archive)):
        raise ValueError("missing one of the required independent native static archives")
    _check_archive_inventory(prefix, [
        crypto_archive, *([asn1_archive] if asn1_prefix == prefix else [])
    ])
    if asn1_prefix != prefix:
        _check_archive_inventory(asn1_prefix, [asn1_archive])
    crypto_inc = prefix / "include" / "crypto"
    asn1_inc = asn1_prefix / "include" / "salts"
    for name in ("status.h", "sha256.h", "ed448.h", "asn1_crypto.h",
                 "tls_auth.h"):
        if not (crypto_inc / name).is_file():
            raise ValueError("missing canonical Crypto header: " + name)
    for name in ("asn1.h", "asn1_value.h"):
        if not (asn1_inc / name).is_file():
            raise ValueError("missing canonical ASN1 header: " + name)
        if (prefix / "include" / "crypto" / name).exists():
            raise ValueError("duplicated old Crypto-owned ASN1 header: " + name)
    if (prefix / "include" / "salts" / "crypto.h").exists():
        raise ValueError("legacy salts/crypto.h found")
    if (prefix / "include" / "crypto" / "provider.h").exists():
        raise ValueError("provider compatibility header found")
    if (prefix / "include" / "gmssl").exists():
        raise ValueError("Crypto SDK must not duplicate installed vcpkg GmSSL headers")
    for rel in ("include/gmssl/sm3.h", "include/gmssl/tls.h",
                "share/gmssl/GmSSLConfig.cmake", "share/gmssl/copyright"):
        if not (gmssl_prefix / rel).is_file():
            raise ValueError("canonical vcpkg GmSSL file missing: " + rel)
    for name in ("libgmssl.so", "libgmssl.dylib", "gmssl.dll"):
        if (gmssl_prefix / "lib" / name).exists():
            raise ValueError("GmSSL must remain a separate STATIC vcpkg provider: " + name)

    targets = prefix / "lib" / "cmake" / "Crypto" / "CryptoTargets.cmake"
    asn1targets = asn1_prefix / "lib" / "cmake" / "ASN1" / "ASN1Targets.cmake"
    cfg = prefix / "lib" / "cmake" / "Crypto" / "CryptoConfig.cmake"
    if not targets.is_file() or not asn1targets.is_file() or not cfg.is_file():
        raise ValueError("missing exported native module package")
    crypto_value = targets.read_text(encoding="utf-8")
    asn1_value = asn1targets.read_text(encoding="utf-8")
    if "add_library(Salts::Crypto STATIC IMPORTED)" not in crypto_value:
        raise ValueError("Crypto must export one imported static target")
    if "add_library(Salts::ASN1 STATIC IMPORTED)" not in asn1_value:
        raise ValueError("ASN1 must export one imported static target")
    if "Salts::ASN1" not in crypto_value or "find_dependency(ASN1" not in cfg.read_text(encoding="utf-8"):
        raise ValueError("Crypto must explicitly depend on exactly one ASN1 package")
    config_text = cfg.read_text(encoding="utf-8")
    if ("find_dependency(GmSSL CONFIG REQUIRED)" not in config_text or
            "GmSSL::GmSSL" not in crypto_value):
        raise ValueError("Crypto static package must transitively resolve vcpkg GmSSL")
    if "PrivateGmSSL" in crypto_value:
        raise ValueError("noncanonical private GmSSL provider exported")
    report = {
        "ok": True,
        "crypto_archive": str(crypto_archive),
        "asn1_archive": str(asn1_archive),
        "gmssl_archive": str(gmssl_archive),
        "native_modules": ["Salts::ASN1", "Salts::Crypto", "GmSSL::GmSSL"],
        "symbols_checked": False,
    }
    if sys.platform == "win32":
        # COFF uniqueness is checked by the real production CNet llvm-nm
        # and link-map auditor. This SDK metadata audit does not pretend
        # to have parsed COFF strong/COMDAT definitions.
        return report

    crypto_symbols = _defined_symbols(crypto_archive)
    asn1_symbols = _defined_symbols(asn1_archive)
    gmssl_symbols = _defined_symbols(gmssl_archive)
    for label, table, required in (
        ("Crypto", crypto_symbols, CRYPTO_SYMBOLS),
        ("ASN1", asn1_symbols, ASN1_SYMBOLS),
        ("GmSSL", gmssl_symbols, GMSSL_SYMBOLS),
    ):
        invalid = {s: table[s] for s in required if table[s] != 1}
        if invalid:
            raise ValueError(label + " missing or nonunique exported symbols: " + str(invalid))
    duplicates = sorted(
        (set(crypto_symbols) & set(asn1_symbols)) |
        (set(crypto_symbols) & set(gmssl_symbols)) |
        (set(asn1_symbols) & set(gmssl_symbols))
    )
    if duplicates:
        raise ValueError("cross-archive duplicate strong definitions: " + str(duplicates))
    for label, symbols in (("Crypto", crypto_symbols),
                           ("ASN1", asn1_symbols),
                           ("GmSSL", gmssl_symbols)):
        repeated = {name: count for name, count in symbols.items() if count > 1}
        if repeated:
            raise ValueError(label + " archive duplicate strong definitions: " +
                             str(repeated))
    embedded_tls = [name for name in crypto_symbols
                    if name.startswith(("tls_", "tlcp_"))]
    if embedded_tls:
        raise ValueError("Crypto contains a duplicate native TLS/TLCP engine: " +
                         str(embedded_tls))
    forbidden = [s for s in crypto_symbols if
                 s in OLD_SYMBOLS or
                 s.startswith(("salts_asn1_", "crypto_asn1_reader_", "crypto_asn1_value_")) or
                 s in ("crypto_asn1_validate", "crypto_asn1_encode_tlv")]
    if forbidden:
        raise ValueError("Crypto contains an obsolete or duplicate native owner: " + str(forbidden))
    report["symbols_checked"] = True
    report["crypto_symbol_count"] = len(crypto_symbols)
    report["asn1_symbol_count"] = len(asn1_symbols)
    report["gmssl_symbol_count"] = len(gmssl_symbols)
    return report

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--asn1-prefix", type=Path,
                        help="use only if ASN1 is installed at a separate prefix")
    parser.add_argument("--gmssl-prefix", type=Path, required=True,
                        help="installed vcpkg GmSSL target triplet prefix")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = inspect(args.prefix, args.asn1_prefix, args.gmssl_prefix)
    except (OSError, ValueError) as exc:
        result = {"ok": False, "reason": str(exc)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Independent Crypto/ASN1/GmSSL archive ownership: " + ("PASS" if result["ok"] else "FAIL " + result["reason"]))
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
