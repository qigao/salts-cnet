#!/usr/bin/env python3
"""Reject high-level dependencies and enforce canonical Salts:: targets in SaltsCore.

A historical `cmeta_` API spelling is *not* a CMeta runtime dependency; only
specific target, include and runtime reflection/actor types are forbidden.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re

SCANNED_EXTENSIONS = {".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".mm", ".cmake"}
IGNORED_DIRECTORIES = {".git", ".github", "vendor", "third_party", "build", "out", "tools", "docs", "_build", "_installed", "_sdk", "CMakeFiles"}
PATTERNS = {
    "forbidden high-level Salts target": re.compile(r"\bSalts::(?!Core\b|Platform\b|Concurrency\b|Coroutine\b|NativeIO\b|URI\b|CNet\b|Unicode\b|IDNA\b|CSerde\b|TinyTest\b|SCTP\b|SCTPWire\b|FS\b|Process\b|Crypto\b|ASN1\b|Playback\b|Serial\b|Capture\b)[A-Za-z_0-9]+"),
    "forbidden alternate target namespace": re.compile(r"\b(?:SaltsCore|SaltsCrypto|Crypto)::[A-Za-z_0-9]+"),
    "legacy package lookup": re.compile(r"\b(?:find_package|find_dependency)\s*\(\s*Salts(?:Utils)?(?:\s|\))", re.IGNORECASE),
    "CMeta/CFlow/CSTL include": re.compile(r'^\s*#\s*include\s*[<"](?:cmeta/|cflow/|cstl(?:/|\.h))'),
    "CMeta/CFlow runtime object": re.compile(r"\b(?:CMETA_STRUCT|CMETA_IMPLEMENTS|cmeta_type_desc|cflow_executor|cflow_io_actor|cflow_waker|cflow_publisher)\b"),
}

# Negative CMake checks are prohibitions, not dependencies. Only these
# exact source-contract locations can opt out, and only when the entire
# if(TARGET ...)/FATAL_ERROR or foreach(...)/if/FATAL/endif/endforeach
# structure remains intact. Active links elsewhere are never excluded.
NEGATIVE_ASSERTION_FILES = frozenset({
    Path("tests/cnet-crypto-static/CMakeLists.txt"),
    Path("crypto/tests/owner/CMakeLists.txt"),
})
_TARGET_NAME = r"[A-Za-z_][A-Za-z_0-9]*::[A-Za-z_][A-Za-z_0-9]*"
_LIST_GUARD = re.compile(
    rf"foreach\(\s*([A-Za-z_][A-Za-z_0-9]*)\s+IN\s+ITEMS\s+"
    rf"({_TARGET_NAME}(?:\s+{_TARGET_NAME})*)\s*\)"
)
_IF_DENY_GUARD = re.compile(
    rf"if\(\s*TARGET\s+{_TARGET_NAME}"
    rf"(?:\s+OR\s+TARGET\s+{_TARGET_NAME})*\s*\)"
)


def _negative_assertion_indices(relative: Path, lines: list[str]) -> set[int]:
    if relative not in NEGATIVE_ASSERTION_FILES:
        return set()
    allowed: set[int] = set()
    for index, line in enumerate(lines):
        # A literal if(TARGET Old::Target OR TARGET Other::Target)
        # followed immediately by FATAL_ERROR and endif is a denial.
        if (_IF_DENY_GUARD.fullmatch(line.strip())
                and index + 2 < len(lines)
                and lines[index + 1].strip().startswith("message(FATAL_ERROR ")
                and lines[index + 2].strip() == "endif()"):
            allowed.add(index)
        if not line.lstrip().startswith("foreach("):
            continue
        last = index
        while last < len(lines) and not lines[last].strip().endswith(")"):
            last += 1
        if last >= len(lines) or last + 4 >= len(lines):
            continue
        declaration = " ".join(part.strip() for part in lines[index:last + 1])
        match = _LIST_GUARD.fullmatch(declaration)
        if match is None:
            continue
        variable = match.group(1)
        if not re.fullmatch(
                rf'if\(\s*TARGET\s+"?\$\{{{re.escape(variable)}\}}"?\s*\)',
                lines[last + 1].strip()):
            continue
        if (not lines[last + 2].strip().startswith("message(FATAL_ERROR ")
                or lines[last + 3].strip() != "endif()"
                or lines[last + 4].strip() != "endforeach()"):
            continue
        allowed.update(range(index, last + 1))
    return allowed


def _is_comment_line(relative: Path, line: str) -> bool:
    stripped = line.lstrip()
    if relative.name == "CMakeLists.txt" or relative.suffix == ".cmake":
        return stripped.startswith("#")
    # C/C++ whole-line comments only. An active #include remains checked;
    # disabled #if branches are still scanned, and *ptr code is not ignored.
    return stripped.startswith(("/*", "*/", "//", "* "))


def check_repository(root: Path) -> list[str]:
    violations: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in IGNORED_DIRECTORIES or part.startswith(".build") for part in relative.parts[:-1]):
            continue
        if path.suffix not in SCANNED_EXTENSIONS and path.name != "CMakeLists.txt":
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        denied_guard_indices = _negative_assertion_indices(relative, lines)
        for index, line in enumerate(lines):
            if index in denied_guard_indices or _is_comment_line(relative, line):
                continue
            lineno = index + 1
            # Salts::UUID and other C++ types are not imported CMake targets.
            # Target-namespace checks apply to CMake, while real includes and
            # reflection/actor types remain forbidden in all C/C++ sources.
            is_cmake = relative.name == "CMakeLists.txt" or relative.suffix == ".cmake"
            for rule, regex in PATTERNS.items():
                if rule in ("forbidden high-level Salts target",
                            "forbidden alternate target namespace") and not is_cmake:
                    continue
                if regex.search(line):
                    violations.append(f"{relative}:{lineno}: {rule}: {line.strip()}")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    violations = check_repository(args.root)
    for violation in violations:
        print(violation)
    if violations:
        print(f"FAILED: {len(violations)} forbidden dependency reference(s)")
        return 1
    print("PASS: no legacy Salts/CMeta/CFlow/CSTL dependencies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
