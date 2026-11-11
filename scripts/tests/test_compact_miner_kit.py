"""Adversarial input and signing checks for complete miner kits."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("kit", SCRIPTS / "package-compact-miner-kit.py")
kit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kit)


class MinerKitTests(unittest.TestCase):
    def test_archive_rejects_traversal_duplicates_and_multiple_roots(self):
        for names in [["root/../file"], ["/root/file"], ["root/file", "root/file"], ["one/file", "two/file"], ["root\\file"]]:
            with self.subTest(names=names), self.assertRaises(ValueError):
                kit.archive_files([(name, 1, lambda: b"x") for name in names])

    def test_archive_checks_size_and_inventory_limits(self):
        for rows in [[], [("root/file", 2, lambda: b"x")], [("root/file", 513 * 1024**2, lambda: b"x")]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                kit.archive_files(rows)
        self.assertEqual(kit.archive_files([("root/file", 1, lambda: b"x")]), {"file": b"x"})

    @staticmethod
    def signed_fixture():
        original = bytearray(1024)
        struct.pack_into("<I", original, 60, 128)
        original[128:134] = b"PE\0\0\x64\x86"
        original[152:154] = b"\x0b\x02"
        original[512:520] = b"program!"
        signed = bytearray(original)
        struct.pack_into("<I", signed, 152 + 64, 0x12345678)
        struct.pack_into("<II", signed, 152 + 112 + 4 * 8, 1024, 16)
        signed += b"certificate-data"
        return bytes(original), bytes(signed)

    def test_authenticode_copy_allows_only_signature_changes(self):
        original, signed = self.signed_fixture()
        kit.validate_signed_copy(original, signed)
        changed = bytearray(signed)
        changed[512] ^= 1
        with self.assertRaises(ValueError):
            kit.validate_signed_copy(original, changed)
        with self.assertRaises(ValueError):
            kit.validate_signed_copy(original, signed + b"appended-payload")

    def test_authenticode_copy_rejects_missing_certificate(self):
        original, _ = self.signed_fixture()
        with self.assertRaises(ValueError):
            kit.validate_signed_copy(original, original)


if __name__ == "__main__":
    unittest.main()
