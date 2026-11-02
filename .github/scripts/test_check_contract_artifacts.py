#!/usr/bin/env python3
"""Tests for check_contract_artifacts.py's metadata stripping.

Run: python3 .github/scripts/test_check_contract_artifacts.py (contracts.yml
does, before the artifact comparison).
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_contract_artifacts import code, metadata_length  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def solc_tail(ipfs_byte=0x11, version=(0, 8, 28)):
    """A metadata tail shaped like solc's: {ipfs: <34 bytes>, solc: <3 bytes>} + length."""
    blob = (
        bytes([0xA2])
        + bytes([0x64]) + b"ipfs" + bytes([0x58, 0x22]) + bytes([ipfs_byte]) * 34
        + bytes([0x64]) + b"solc" + bytes([0x43]) + bytes(version)
    )
    return blob + len(blob).to_bytes(2, "big")


EXECUTABLE = bytes.fromhex("6080604052348015600e575f5ffd5b50")


class MetadataStripping(unittest.TestCase):
    def test_strips_a_solc_shaped_tail(self):
        raw = EXECUTABLE + solc_tail()
        self.assertEqual(metadata_length(raw), len(solc_tail()))
        self.assertEqual(code(raw.hex()), EXECUTABLE.hex())

    def test_builds_differing_only_in_metadata_compare_equal(self):
        a = "0x" + (EXECUTABLE + solc_tail(ipfs_byte=0x11)).hex()
        b = "0x" + (EXECUTABLE + solc_tail(ipfs_byte=0x22)).hex()
        self.assertEqual(code(a), code(b))

    def test_different_code_with_the_same_tail_still_differs(self):
        tail = solc_tail()
        a = "0x" + (bytes.fromhex("600160005500") + tail).hex()
        b = "0x" + (bytes.fromhex("600260005500") + tail).hex()
        self.assertNotEqual(code(a), code(b))

    def test_metadata_free_code_is_compared_in_full(self):
        # Hermes's reproduction: the old parser read 0x5500 as a length and
        # stripped everything, so these compared equal.
        self.assertEqual(code("0x600160005500"), "600160005500")
        self.assertNotEqual(code("0x600160005500"), code("0x600260005500"))

    def test_oversized_footer_is_not_stripped(self):
        raw = EXECUTABLE + bytes([0xFF, 0xFF])
        self.assertEqual(metadata_length(raw), 0)
        self.assertEqual(code(raw.hex()), raw.hex())

    def test_truncated_tail_is_not_stripped(self):
        # Drop bytes from the front of a valid tail: the footer now claims more
        # CBOR than is left before it.
        raw = solc_tail()[10:]
        self.assertEqual(metadata_length(raw), 0)

    def test_footer_over_non_cbor_bytes_is_not_stripped(self):
        raw = EXECUTABLE + bytes([0x60, 0x01, 0x55]) + (3).to_bytes(2, "big")
        self.assertEqual(metadata_length(raw), 0)

    def test_map_shorter_than_the_footer_is_not_stripped(self):
        blob = bytes([0xA1, 0x64]) + b"solc" + bytes([0x43, 0, 8, 28])
        padded = blob + bytes([0x00])  # one byte of garbage inside the stated length
        raw = EXECUTABLE + padded + len(padded).to_bytes(2, "big")
        self.assertEqual(metadata_length(raw), 0)

    def test_unknown_keys_are_not_metadata(self):
        blob = bytes([0xA1, 0x63]) + b"foo" + bytes([0x01])
        raw = EXECUTABLE + blob + len(blob).to_bytes(2, "big")
        self.assertEqual(metadata_length(raw), 0)

    # Round 2: maps that are well-formed CBOR but not solc metadata.

    def test_reviewer_counterexample_is_compared_in_full(self):
        # {"solc": 1} plus its length. Valid CBOR with a whitelisted key, but solc
        # writes a 3-byte version, and these bytes also execute (LOG1/PUSH5/STOP).
        self.assertEqual(code("0x600060006000a164736f6c63010007"), "600060006000a164736f6c63010007")
        self.assertNotEqual(code("0x600060006000a164736f6c63010007"), code("0x600060006000"))

    def assert_not_metadata(self, blob, why):
        raw = EXECUTABLE + blob + len(blob).to_bytes(2, "big")
        self.assertEqual(metadata_length(raw), 0, why)

    def assert_metadata(self, blob, why):
        raw = EXECUTABLE + blob + len(blob).to_bytes(2, "big")
        self.assertEqual(metadata_length(raw), len(blob) + 2, why)
        self.assertEqual(code(raw.hex()), EXECUTABLE.hex(), why)

    SOLC = bytes([0x64]) + b"solc" + bytes([0x43, 0, 8, 28])
    IPFS = bytes([0x64]) + b"ipfs" + bytes([0x58, 0x22]) + bytes([0x11]) * 34

    def test_duplicate_keys_are_not_metadata(self):
        self.assert_not_metadata(bytes([0xA2]) + self.SOLC + self.SOLC, "duplicate solc")

    def test_byte_string_keys_are_not_metadata(self):
        key_as_bytes = bytes([0x44]) + b"solc" + bytes([0x43, 0, 8, 28])
        self.assert_not_metadata(bytes([0xA1]) + key_as_bytes, "byte-string key")

    def test_wrong_value_types_and_lengths_are_not_metadata(self):
        cases = {
            "solc as uint": bytes([0xA1, 0x64]) + b"solc" + bytes([0x01]),
            "solc 2 bytes": bytes([0xA1, 0x64]) + b"solc" + bytes([0x42, 0, 8]),
            "solc empty text": bytes([0xA1, 0x64]) + b"solc" + bytes([0x60]),
            "ipfs 33 bytes": bytes([0xA2, 0x64]) + b"ipfs" + bytes([0x58, 0x21]) + bytes(33) + self.SOLC,
            "ipfs as text": bytes([0xA2, 0x64]) + b"ipfs" + bytes([0x63]) + b"abc" + self.SOLC,
            "experimental false": bytes([0xA2, 0x6C]) + b"experimental" + bytes([0xF4]) + self.SOLC,
        }
        for why, blob in cases.items():
            self.assert_not_metadata(blob, why)

    def test_solc_is_required_and_one_hash_at_most(self):
        self.assert_not_metadata(bytes([0xA1]) + self.IPFS, "no solc")
        bzzr1 = bytes([0x65]) + b"bzzr1" + bytes([0x58, 0x20]) + bytes(32)
        self.assert_not_metadata(bytes([0xA3]) + self.IPFS + bzzr1 + self.SOLC, "two hashes")

    def test_shapes_solc_emits_are_metadata(self):
        self.assert_metadata(bytes([0xA2]) + self.IPFS + self.SOLC, "ipfs + release solc")
        self.assert_metadata(bytes([0xA1]) + self.SOLC, "bytecodeHash none")
        prerelease = bytes([0x64]) + b"solc" + bytes([0x78, 0x18]) + b"0.8.29-nightly.2025.1.1+"
        self.assert_metadata(bytes([0xA2]) + self.IPFS + prerelease, "prerelease solc")
        bzzr1 = bytes([0x65]) + b"bzzr1" + bytes([0x58, 0x20]) + bytes(32)
        experimental = bytes([0x6C]) + b"experimental" + bytes([0xF5])
        self.assert_metadata(bytes([0xA3]) + bzzr1 + experimental + self.SOLC, "bzzr1 + experimental")

    def test_empty_and_tiny_code(self):
        self.assertEqual(code("0x"), "")
        self.assertEqual(code("0x00"), "00")

    def test_committed_artifact_has_a_recognised_tail(self):
        artifact = json.loads((REPO / "artifacts" / "PaymentVaultV2.json").read_text())
        for key in ("bytecode", "deployedBytecode"):
            entry = artifact[key]
            hex_code = entry["object"] if isinstance(entry, dict) else entry
            raw = bytes.fromhex(hex_code.removeprefix("0x"))
            self.assertGreater(metadata_length(raw), 0, key)


if __name__ == "__main__":
    unittest.main()
