// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test, Vm, stdError} from "forge-std/Test.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {PaymentVaultV2} from "../contracts/PaymentVaultV2.sol";
import {IPaymentVaultV2} from "../contracts/IPaymentVaultV2.sol";
import {
    CandidateNode,
    CompletedMerklePayment,
    MerkleTreePayment,
    PoolCommitment
} from "../contracts/Types.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock ANT", "ANT") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract PaymentVaultV2Test is Test {
    uint64 internal constant TS = 1_755_000_000;
    uint256 internal constant BATCH_LIMIT = 512;

    MockERC20 internal token;
    PaymentVaultV2 internal vault;
    address internal payer = makeAddr("payer");

    function setUp() public {
        token = new MockERC20();
        vault = new PaymentVaultV2(IERC20(address(token)), BATCH_LIMIT);

        token.mint(payer, type(uint128).max);
        vm.prank(payer);
        token.approve(address(vault), type(uint256).max);

        // Fixed entropy so tests can replicate the winner-pool seed.
        vm.warp(1_755_100_000);
        vm.prevrandao(bytes32(uint256(0x5eed)));
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Mirror of MerklePaymentLib.expectedRewardPools
    function expectedPools(uint8 depth) internal pure returns (uint256) {
        return 1 << ((depth + 1) / 2);
    }

    /// Mirror of MerklePaymentLib.selectWinnerPool — replicates the on-chain
    /// seed so tests can predict which pool wins for a given tree index.
    function predictWinnerIdx(
        uint256 poolCount,
        address sender,
        uint64 ts,
        uint256 treeIndex
    ) internal view returns (uint256) {
        bytes32 seed = keccak256(
            abi.encodePacked(block.prevrandao, block.timestamp, sender, ts, treeIndex)
        );
        return uint256(seed) % poolCount;
    }

    /// Pool with a fixed hash, uniform candidate price and distinct reward addresses
    function makePool(bytes32 poolHash, uint256 price, uint160 addrSalt)
        internal
        pure
        returns (PoolCommitment memory pool)
    {
        pool.poolHash = poolHash;
        for (uint256 i = 0; i < 16; i++) {
            pool.candidates[i] =
                CandidateNode({rewardsAddress: address(uint160(0x10000) + addrSalt + uint160(i)), amount: price});
        }
    }

    /// Well-formed tree: correct pool count for depth, uniform price, pool
    /// hashes derived from the salt (distinct per pool).
    function makeTree(uint8 depth, uint256 price, uint256 salt)
        internal
        pure
        returns (MerkleTreePayment memory tree)
    {
        uint256 pools = expectedPools(depth);
        tree.depth = depth;
        tree.merklePaymentTimestamp = TS;
        tree.poolCommitments = new PoolCommitment[](pools);
        for (uint256 j = 0; j < pools; j++) {
            tree.poolCommitments[j] =
                makePool(keccak256(abi.encode(salt, j)), price, uint160(salt * 1000 + j * 100));
        }
    }

    function poolHashesOf(MerkleTreePayment memory tree) internal pure returns (bytes32[] memory hashes) {
        hashes = new bytes32[](tree.poolCommitments.length);
        for (uint256 j = 0; j < tree.poolCommitments.length; j++) {
            hashes[j] = tree.poolCommitments[j].poolHash;
        }
    }

    function containsHash(bytes32[] memory hashes, bytes32 needle) internal pure returns (bool) {
        for (uint256 j = 0; j < hashes.length; j++) {
            if (hashes[j] == needle) return true;
        }
        return false;
    }

    // ── Happy path: event ordering + attribution ────────────────────────

    function test_paysMultipleTrees_eventsInInputOrder() public {
        // Distinct depths and prices so each tree's event is unambiguous.
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](3);
        trees[0] = makeTree(2, 100, 1);
        trees[1] = makeTree(4, 200, 2);
        trees[2] = makeTree(1, 300, 3);

        uint256 balanceBefore = token.balanceOf(payer);

        vm.recordLogs();
        vm.prank(payer);
        (bytes32[] memory winners, uint256 totalAmount) = vault.payForMerkleTrees(trees);

        // Per-tree cost with uniform prices: price * 2^depth
        uint256 expectedTotal = (100 << 2) + (200 << 4) + (300 << 1);
        assertEq(totalAmount, expectedTotal, "summed total");
        assertEq(winners.length, 3, "one winner hash per tree");

        // Exactly one MerklePaymentMade per tree, in input order, each
        // attributable to its tree by log order.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 seen = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(vault)) continue;
            if (logs[i].topics[0] != IPaymentVaultV2.MerklePaymentMade.selector) continue;

            bytes32 winnerPoolHash = logs[i].topics[1];
            (uint8 depth, uint256 amount, uint64 ts) = abi.decode(logs[i].data, (uint8, uint256, uint64));

            assertEq(winnerPoolHash, winners[seen], "event order matches returned winners");
            assertTrue(containsHash(poolHashesOf(trees[seen]), winnerPoolHash), "winner from this tree's pools");
            assertEq(depth, trees[seen].depth, "event depth matches tree");
            assertEq(amount, uint256(trees[seen].poolCommitments[0].candidates[0].amount) << depth, "event amount");
            assertEq(ts, TS, "event timestamp");
            seen++;
        }
        assertEq(seen, 3, "one event per tree");

        // Storage written for every tree
        for (uint256 i = 0; i < 3; i++) {
            CompletedMerklePayment memory info = vault.getCompletedMerklePayment(winners[i]);
            assertEq(info.depth, trees[i].depth, "stored depth");
            assertEq(info.merklePaymentTimestamp, TS, "stored timestamp");
            assertEq(info.paidNodeAddresses.length, trees[i].depth, "one paid node per level");
        }

        // Uniform prices and power-of-two depths: every per-node amount is
        // exact, so the payer's balance moves by exactly totalAmount.
        assertEq(balanceBefore - token.balanceOf(payer), expectedTotal, "payer debited by total");
    }

    // ── Revert atomicity ────────────────────────────────────────────────

    function test_revertsWholeBatch_whenMiddleTreeInvalid() public {
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](3);
        trees[0] = makeTree(2, 100, 10);
        trees[1] = makeTree(4, 100, 11);
        trees[2] = makeTree(2, 100, 12);

        // Corrupt the middle tree: depth 4 expects 4 pools, give it 2.
        PoolCommitment[] memory tooFew = new PoolCommitment[](2);
        tooFew[0] = trees[1].poolCommitments[0];
        tooFew[1] = trees[1].poolCommitments[1];
        trees[1].poolCommitments = tooFew;

        uint256 balanceBefore = token.balanceOf(payer);

        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IPaymentVaultV2.WrongPoolCount.selector, 4, 2));
        vault.payForMerkleTrees(trees);

        // Tree 0 was processed before the revert point — nothing may persist.
        assertEq(token.balanceOf(payer), balanceBefore, "no tokens moved");
        bytes32[] memory hashes = poolHashesOf(trees[0]);
        for (uint256 j = 0; j < hashes.length; j++) {
            assertEq(vault.getCompletedMerklePayment(hashes[j]).depth, 0, "no payment stored");
        }
    }

    function test_revertsWholeBatch_whenDepthTooLarge() public {
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](2);
        trees[0] = makeTree(2, 100, 20);
        trees[1] = makeTree(2, 100, 21);
        trees[1].depth = 13; // > MAX_MERKLE_DEPTH

        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IPaymentVaultV2.DepthTooLarge.selector, 13, 12));
        vault.payForMerkleTrees(trees);
    }

    function test_revertsWholeBatch_whenDepthZero() public {
        // Depth 0 hits the pre-existing division-by-zero panic in the
        // per-tree path; in a batch that panic must abort everything.
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](2);
        trees[0] = makeTree(2, 100, 25);
        trees[1] = makeTree(2, 100, 26);
        trees[1].depth = 0;
        trees[1].poolCommitments = new PoolCommitment[](1);
        trees[1].poolCommitments[0] = makePool(keccak256("d0"), 100, 9_999);

        uint256 balanceBefore = token.balanceOf(payer);

        vm.prank(payer);
        vm.expectRevert(stdError.divisionError);
        vault.payForMerkleTrees(trees);

        assertEq(token.balanceOf(payer), balanceBefore, "no tokens moved");
    }

    function test_revertsWholeBatch_whenAllowanceShortByOne() public {
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](2);
        trees[0] = makeTree(2, 100, 30);
        trees[1] = makeTree(2, 100, 31);
        uint256 total = (100 << 2) + (100 << 2);

        vm.prank(payer);
        token.approve(address(vault), total - 1);

        uint256 balanceBefore = token.balanceOf(payer);

        // The last node transfer of the last tree exceeds the allowance;
        // every earlier transfer must unwind.
        vm.prank(payer);
        vm.expectRevert();
        vault.payForMerkleTrees(trees);

        assertEq(token.balanceOf(payer), balanceBefore, "no tokens moved");
    }

    // ── Allowance consumption ───────────────────────────────────────────

    function test_exactAllowanceCoversBatch() public {
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](2);
        trees[0] = makeTree(2, 100, 40);
        trees[1] = makeTree(4, 50, 41);
        uint256 total = (100 << 2) + (50 << 4);

        vm.prank(payer);
        token.approve(address(vault), total);

        vm.prank(payer);
        (, uint256 totalAmount) = vault.payForMerkleTrees(trees);

        assertEq(totalAmount, total, "batch costs the sum of per-tree costs");
        assertEq(token.allowance(payer, address(vault)), 0, "exact allowance fully consumed");
    }

    // ── Duplicate / replay protection ───────────────────────────────────

    function test_revertsOnDuplicateWinnerWithinBatch() public {
        // Both pools of both trees share one hash, so both trees must
        // resolve to the same winner regardless of the seed.
        bytes32 dup = keccak256("duplicate-pool");
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](2);
        trees[0] = makeTree(2, 100, 50);
        trees[1] = makeTree(2, 100, 51);
        for (uint256 j = 0; j < 2; j++) {
            trees[0].poolCommitments[j].poolHash = dup;
            trees[1].poolCommitments[j].poolHash = dup;
        }

        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IPaymentVaultV2.PaymentAlreadyExists.selector, dup));
        vault.payForMerkleTrees(trees);
    }

    function test_revertsWhenTreeAlreadyPaidViaLegacyEntryPoint() public {
        MerkleTreePayment memory tree = makeTree(2, 100, 60);

        vm.prank(payer);
        (bytes32 winner,) = vault.payForMerkleTree(tree.depth, tree.poolCommitments, TS);

        // Pin the batch's tree 0 to the already-paid pool.
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](1);
        trees[0] = tree;
        for (uint256 j = 0; j < trees[0].poolCommitments.length; j++) {
            trees[0].poolCommitments[j].poolHash = winner;
        }

        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IPaymentVaultV2.PaymentAlreadyExists.selector, winner));
        vault.payForMerkleTrees(trees);
    }

    // ── Seed decorrelation ──────────────────────────────────────────────

    function test_treeIndexDecorrelatesIdenticalTrees() public {
        // Two structurally identical trees (same ts, same pool count,
        // distinct hashes). Find an entropy value under which the seed with
        // treeIndex 0 and treeIndex 1 select different pool indices — with
        // the old index-free seed they would always collide.
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](2);
        trees[0] = makeTree(2, 100, 70);
        trees[1] = makeTree(2, 100, 71);

        bool found = false;
        for (uint256 k = 1; k <= 64; k++) {
            vm.prevrandao(bytes32(k));
            if (predictWinnerIdx(2, payer, TS, 0) != predictWinnerIdx(2, payer, TS, 1)) {
                found = true;
                break;
            }
        }
        assertTrue(found, "some entropy separates tree indices");

        uint256 idx0 = predictWinnerIdx(2, payer, TS, 0);
        uint256 idx1 = predictWinnerIdx(2, payer, TS, 1);

        vm.prank(payer);
        (bytes32[] memory winners,) = vault.payForMerkleTrees(trees);

        assertEq(winners[0], trees[0].poolCommitments[idx0].poolHash, "tree 0 winner follows seed(0)");
        assertEq(winners[1], trees[1].poolCommitments[idx1].poolHash, "tree 1 winner follows seed(1)");
        assertTrue(idx0 != idx1, "identical trees pick different pool slots");
    }

    // ── Input bounds ────────────────────────────────────────────────────

    function test_revertsOnEmptyBatch() public {
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](0);
        vm.prank(payer);
        vm.expectRevert(IPaymentVaultV2.InvalidInputLength.selector);
        vault.payForMerkleTrees(trees);
    }

    function test_revertsAboveMaxTreesPerPayment() public {
        uint256 tooMany = uint256(vault.MAX_TREES_PER_PAYMENT()) + 1;
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](tooMany);

        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(IPaymentVaultV2.TooManyTrees.selector, tooMany, 16));
        vault.payForMerkleTrees(trees);
    }

    function test_acceptsMaxTreesPerPayment() public {
        uint256 max = vault.MAX_TREES_PER_PAYMENT();
        MerkleTreePayment[] memory trees = new MerkleTreePayment[](max);
        for (uint256 i = 0; i < max; i++) {
            trees[i] = makeTree(1, 100, 80 + i);
        }

        vm.prank(payer);
        (bytes32[] memory winners,) = vault.payForMerkleTrees(trees);
        assertEq(winners.length, max, "max-sized batch accepted");
    }

    // ── Legacy entry point + production alignment ───────────────────────

    function test_legacyPayForMerkleTreeStillWorks() public {
        MerkleTreePayment memory tree = makeTree(2, 100, 90);

        vm.prank(payer);
        (bytes32 winner, uint256 totalAmount) = vault.payForMerkleTree(tree.depth, tree.poolCommitments, TS);

        assertEq(totalAmount, 100 << 2, "legacy cost formula unchanged");
        assertTrue(containsHash(poolHashesOf(tree), winner), "winner from submitted pools");
        assertEq(vault.getCompletedMerklePayment(winner).depth, 2, "payment stored");
    }

    function test_maxTreesGetterIsFeatureProbe() public view {
        assertEq(vault.MAX_TREES_PER_PAYMENT(), 16, "probe constant");
    }

    function test_setBatchLimitOnlyOwner() public {
        vault.setBatchLimit(1024);
        assertEq(vault.batchLimit(), 1024, "owner can set");

        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, payer));
        vault.setBatchLimit(1);
    }
}
