import json
import os
import tempfile
from pathlib import Path
import unittest

import sigmaze


class SigmazeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)

    def create_file(self, name: str, content: bytes) -> Path:
        path = self.root / name
        path.write_bytes(content)
        return path

    def test_hash_file(self):
        file_path = self.create_file("sample.bin", b"hello world")
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        self.assertEqual(sigmaze.hash_file(file_path), expected)

    def test_scan_directory_detects_signature(self):
        malicious_file = self.create_file("bad.bin", b"danger")
        malicious_hash = sigmaze.hash_file(malicious_file)
        signatures = {malicious_hash}

        results = sigmaze.scan_directory(self.root, signatures)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["path"], str(malicious_file))
        self.assertEqual(results[0]["hash"], malicious_hash)

    def test_export_json_writes_results(self):
        data = [
            {
                "path": str(self.root / "infected.bin"),
                "hash": "deadbeef",  # not a real hash, just placeholder for test
            }
        ]
        output_path = self.root / "results.json"
        sigmaze.export_json(data, output_path)

        with output_path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        self.assertEqual(loaded, data)

    def test_load_signatures_ignores_comments_and_blank_lines(self):
        signatures_path = self.root / "signatures.txt"
        signatures_path.write_text("""
# comment line
ABCDEF

def
"""
        )
        signatures = sigmaze.load_signatures(signatures_path)
        self.assertEqual(signatures, {"abcdef", "def"})


if __name__ == "__main__":
    unittest.main()
