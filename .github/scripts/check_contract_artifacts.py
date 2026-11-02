#!/usr/bin/env python3
"""Fail if the committed PaymentVaultV2 artifacts have drifted from contracts/.

Usage: check_contract_artifacts.py <forge-out-dir>

Run `forge build --out <forge-out-dir>` first (contracts.yml does). The
committed files feed `sol!` and the Anvil deploys in the tests, so if a
contract source changes without them being regenerated, the tests keep
exercising the old contract. Checked:

  artifacts/PaymentVaultV2.json  ABI, bytecode and deployedBytecode
  abi/IPaymentVault.json         ABI (it is PaymentVaultV2's ABI)

Bytecode is compared in full, including solc's trailing CBOR metadata. That
metadata hashes the sources and the compiler settings, so it also catches a
drift the code alone wouldn't show. One of those settings is the remappings
Foundry auto-detects from lib/, including OpenZeppelin's nested submodules,
so the build only reproduces the committed artifact byte for byte when the
submodules are checked out recursively (contracts.yml does). Nothing is
stripped before comparing, so no executable code can be mistaken for metadata.

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


def code(entry):
    """Lower-case hex code without 0x, from a Foundry bytecode entry or a hex string."""
    hex_code = entry["object"] if isinstance(entry, dict) else entry
    return hex_code.removeprefix("0x").lower()


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
            f"{COMMITTED}, and write its `abi` array to {COMMITTED_ABI}.\n"
            "If only the end of the bytecode (the metadata hash) differs, the "
            "build probably saw different remappings: check out the submodules "
            "recursively (`git submodule update --init --recursive`) and rebuild."
        )
        sys.exit(1)
    print(f"{COMMITTED} and {COMMITTED_ABI} match contracts/")


if __name__ == "__main__":
    main()
