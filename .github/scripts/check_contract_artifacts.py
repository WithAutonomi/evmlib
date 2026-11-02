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
map of that length, shaped like solc's (unique text keys, `solc` present, and
each value of the type and length solc writes; see HASH_LENGTHS below).
Anything else (no metadata, a truncated or oversized footer, non-CBOR bytes, a
map that merely looks like metadata) is compared as full bytecode, so a check
can't pass by stripping executable code.

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


# What solc writes into the metadata map. Each key appears at most once, as a
# CBOR text string, with exactly this value shape:
#   ipfs          byte string, 34 bytes (sha2-256 multihash)
#   bzzr0, bzzr1  byte string, 32 bytes
#   solc          byte string, 3 bytes (release x.y.z), or a text string
#                 (prerelease version)
#   experimental  true
# `solc` is required: every build that appends a metadata map includes it.
HASH_LENGTHS = {"ipfs": 34, "bzzr0": 32, "bzzr1": 32}


def _cbor_item(data, pos):
    """Parse one CBOR item of the kinds solc metadata uses.

    Returns ((kind, value), next_pos), or None if `data` doesn't hold such an
    item at `pos`. Kinds: "uint", "bytes", "text", "bool", and "map", whose
    value is a list of (key, value) pairs in order (duplicates kept, so the
    caller can reject them).
    """
    if pos >= len(data):
        return None
    major, info = data[pos] >> 5, data[pos] & 0x1F
    pos += 1
    if major == 7:
        return (("bool", info == 21), pos) if info in (20, 21) else None
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
        return ("uint", arg), pos
    if major in (2, 3):
        if pos + arg > len(data):
            return None
        raw = bytes(data[pos:pos + arg])
        if major == 2:
            return ("bytes", raw), pos + arg
        try:
            return ("text", raw.decode("utf-8")), pos + arg
        except UnicodeDecodeError:
            return None
    if major == 5:
        pairs = []
        for _ in range(arg):
            key = _cbor_item(data, pos)
            if key is None:
                return None
            value = _cbor_item(data, key[1])
            if value is None:
                return None
            pairs.append((key[0], value[0]))
            pos = value[1]
        return ("map", pairs), pos
    return None


def _is_solc_metadata(pairs):
    """True only for a map shaped exactly like solc's metadata (see above)."""
    seen = set()
    for (key_kind, key), (kind, value) in pairs:
        if key_kind != "text" or key in seen:
            return False
        seen.add(key)
        if key in HASH_LENGTHS:
            ok = kind == "bytes" and len(value) == HASH_LENGTHS[key]
        elif key == "solc":
            ok = (kind == "bytes" and len(value) == 3) or (kind == "text" and value != "")
        elif key == "experimental":
            ok = kind == "bool" and value
        else:
            ok = False
        if not ok:
            return False
    return "solc" in seen and len(seen & HASH_LENGTHS.keys()) <= 1


def metadata_length(raw):
    """Length in bytes of solc's metadata tail (CBOR map + 2-byte length), or 0."""
    if len(raw) < 3:
        return 0
    cbor_len = int.from_bytes(raw[-2:], "big")
    if cbor_len == 0 or cbor_len + 2 > len(raw):
        return 0
    blob = raw[-2 - cbor_len:-2]
    parsed = _cbor_item(blob, 0)
    if parsed is None or parsed[1] != len(blob):
        return 0  # malformed, or doesn't fill exactly the stated length
    (kind, pairs), _ = parsed
    if kind != "map" or not _is_solc_metadata(pairs):
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
