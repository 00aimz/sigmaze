"""sigmaze: Simple malware signature scanner.

This module provides a CLI for recursively scanning directories and
comparing file SHA-256 hashes against a local signature list.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Set


def load_signatures(path: Path) -> Set[str]:
    """Load SHA-256 signatures from a text file.

    Lines that are empty or start with ``#`` are ignored. Signatures are
    normalized to lowercase.
    """

    if not path.is_file():
        raise FileNotFoundError(f"Signature file not found: {path}")

    signatures: Set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            token = line.strip().lower()
            if not token or token.startswith("#"):
                continue
            signatures.add(token)
    return signatures


def hash_file(path: Path, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hash of a file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def scan_directory(root: Path, signatures: Set[str]) -> List[Dict[str, str]]:
    """Recursively scan ``root`` for files matching ``signatures``.

    Returns a list of dictionaries containing ``path`` and ``hash`` keys
    for infected files.
    """

    infected: List[Dict[str, str]] = []
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            file_path = Path(dirpath, filename)
            try:
                file_hash = hash_file(file_path)
            except (OSError, PermissionError):
                # Skip files that cannot be read.
                continue
            if file_hash in signatures:
                infected.append({"path": str(file_path), "hash": file_hash})
    return infected


def export_json(results: Iterable[Dict[str, str]], output_path: Path) -> None:
    """Export scan ``results`` to ``output_path`` in JSON format."""

    data = list(results)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recursively scan directories for known malware signatures."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=Path("."),
        type=Path,
        help="Target directory to scan (defaults to current directory)",
    )
    parser.add_argument(
        "--signatures",
        default=Path(__file__).with_name("signatures.txt"),
        type=Path,
        help="Path to the signature list (default: signatures.txt next to the script)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        type=Path,
        help="Optional path to write JSON scan results.",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        signatures = load_signatures(args.signatures)
    except FileNotFoundError as exc:
        parser.error(str(exc))

    results = scan_directory(args.path, signatures)

    for entry in results:
        print(entry["path"])

    if args.json_output:
        export_json(results, args.json_output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
