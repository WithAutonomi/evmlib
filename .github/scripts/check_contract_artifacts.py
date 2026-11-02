#!/usr/bin/env python3
"""Fail if the committed PaymentVaultV2 artifacts have drifted from contracts/.

Usage: check_contract_artifacts.py <forge-out-dir>

Run `forge build --out <forge-out-dir>` first (contracts.yml does). The
committed files feed `sol!` and the Anvil deploys in the tests, so if a
contract source changes without them being regenerated, the tests keep
exercising the old contract. Checked:

  artifacts/PaymentVaultV2.json  ABI, bytecode and deployedBytecode
  abi/IPaymentVault.json         ABI (it is PaymentVaultV2's ABI)

Bytecode is compared without the trailing CBOR metadata. That blob hashes the
compiler settings, including the remappings Foundry auto-detects from whatever
nested submodules happen to be checked out, so it differs between otherwise
identical builds. The code before it is deterministic for a pinned solc.

The tail is only stripped when it really is solc metadata: the last two bytes
give a length, and the bytes before them must be exactly one well-formed CBOR
map of that length whose keys are all known metadata keys. Anything else
(no metadata, a truncated or oversized footer, non-CBOR bytes) is compared as
full bytecode, so a check can never pass by stripping executable code.

artifacts/AutonomiNetworkToken.json is not checked: it is a Hardhat artifact
whose source (contracts/AutonomiNetworkToken.sol) is not in this repo.
"""

import json
import sys
from pathlib import Path

COMMITTED = Path("artifacts/PaymentVaultV2.json")
COMMITTED_ABI = Path("abi/IPaymentVault.json")


def canonical(value):
    return json.dumps(value, sort_keys=True)


# Keys solc writes into the metadata map (bytecodeHash ipfs/bzzr0/bzzr1, the
# compiler version, and the experimental flag).
METADATA_KEYS = {"ipfs", "bzzr0", "bzzr1", "solc", "experimental"}


def _cbor_item(data, pos):
    """Parse one CBOR item of the kinds solc metadata uses.

    Returns (value, next_pos), or None if `data` doesn't hold such an item at
    `pos`. Supports unsigned ints, byte and text strings, maps, and the
    simple values false/true. Strings are returned as bytes.
    """
    if pos >= len(data):
        return None
    major, info = data[pos] >> 5, data[pos] & 0x1F
    pos += 1
    if major == 7:
        return (info == 21, pos) if info in (20, 21) else None
    if info < 24:
        arg = info
    elif info in (24, 25):
        width = 1 if info == 24 else 2
        if pos + width > len(data):
            return None
        arg = int.from_bytes(data[pos:pos + width], "big")
        pos += width
    else:
        return None
    if major == 0:
        return arg, pos
    if major in (2, 3):
        if pos + arg > len(data):
            return None
        return bytes(data[pos:pos + arg]), pos + arg
    if major == 5:
        items = {}
        for _ in range(arg):
            key = _cbor_item(data, pos)
            if key is None or not isinstance(key[0], bytes):
                return None
            value = _cbor_item(data, key[1])
            if value is None:
                return None
            items[key[0]] = value[0]
            pos = value[1]
        return items, pos
    return None


def metadata_length(raw):
    """Length in bytes of solc's metadata tail (CBOR map + 2-byte length), or 0."""
    if len(raw) < 3:
        return 0
    cbor_len = int.from_bytes(raw[-2:], "big")
    if cbor_len == 0 or cbor_len + 2 > len(raw):
        return 0
    blob = raw[-2 - cbor_len:-2]
    if blob[0] >> 5 != 5:  # must be a CBOR map
        return 0
    parsed = _cbor_item(blob, 0)
    if parsed is None or parsed[1] != len(blob):
        return 0  # malformed, or doesn't fill exactly the stated length
    keys = {key.decode("utf-8", "replace") for key in parsed[0]}
    if not keys or not keys <= METADATA_KEYS:
        return 0
    return cbor_len + 2


def code(entry):
    """Hex code without 0x and without solc's metadata tail, when there is one."""
    hex_code = entry["object"] if isinstance(entry, dict) else entry
    raw = bytes.fromhex(hex_code.removeprefix("0x"))
    tail = metadata_length(raw)
    return (raw[:-tail] if tail else raw).hex()


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    built_path = Path(sys.argv[1]) / "PaymentVaultV2.sol" / "PaymentVaultV2.json"
    built = json.loads(built_path.read_text())
    committed = json.loads(COMMITTED.read_text())
    committed_abi = json.loads(COMMITTED_ABI.read_text())

    failures = []
    if canonical(built["abi"]) != canonical(committed["abi"]):
        failures.append(f"{COMMITTED}: ABI differs from contracts/")
    if canonical(built["abi"]) != canonical(committed_abi):
        failures.append(f"{COMMITTED_ABI}: ABI differs from contracts/")
    for key in ("bytecode", "deployedBytecode"):
        if code(built[key]) != code(committed[key]):
            failures.append(f"{COMMITTED}: {key} differs from contracts/")

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        print(
            "Regenerate with `forge build`, copy "
            "artifacts/PaymentVaultV2.sol/PaymentVaultV2.json over "
            f"{COMMITTED}, and write its `abi` array to {COMMITTED_ABI}."
        )
        sys.exit(1)
    print(f"{COMMITTED} and {COMMITTED_ABI} match contracts/")


if __name__ == "__main__":
    main()
