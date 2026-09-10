"""Canonical Loki configuration archive membership and checksum contract."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

CANONICAL_FILES = frozenset({
    "codestra/api/service-contract.v1.json",
    "codestra/config/loki.yaml",
    "codestra/config/runtime-config.yaml",
    "codestra/deploy/compose.candidate.yaml",
    "codestra/deploy/runtime.env.example",
})
SHA256 = re.compile(r"[0-9a-f]{64}")


def verify_bundle_files(root: Path, files: object) -> list[Path]:
    """Reject substitutions, missing entries and filesystem indirection."""
    if not isinstance(files, dict) or set(files) != CANONICAL_FILES:
        raise SystemExit("configuration manifest must contain the exact canonical file set")
    paths = []
    for relative, expected in sorted(files.items()):
        path = root / relative
        if not SHA256.fullmatch(str(expected)) or not path.is_file():
            raise SystemExit(f"invalid configuration manifest entry: {relative}")
        if any(part.is_symlink() for part in (path, *path.parents) if part != root and root in part.parents):
            raise SystemExit(f"symbolic configuration manifest entry: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(f"configuration checksum mismatch: {relative}")
        paths.append(path)
    return paths
