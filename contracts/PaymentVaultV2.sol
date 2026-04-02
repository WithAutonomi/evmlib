// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {
    PaidNode,
    CompletedMerklePayment,
    CompletedPayment,
    CandidateNode,
    PoolCommitment,
    DataPayment,
    PaymentVerificationResult
} from "./Types.sol";

import {MerklePaymentLib} from "./MerklePaymentLib.sol";
import {IPaymentVaultV2} from "./IPaymentVaultV2.sol";

/// @title PaymentVaultV2
/// @notice Unified payment vault for both single-node and merkle batch payments.
///         No proxy, no Ownable — for local Anvil testing.
///         Nodes calculate their own prices as (chunks_stored / 6000)^2.
contract PaymentVaultV2 is IPaymentVaultV2 {
    using SafeERC20 for IERC20;

    IERC20 public antToken;

    uint256 public batchLimit;

    mapping(bytes32 => CompletedPayment) public completedPayments;

    // mapping from winner hash to payment
    mapping(bytes32 => CompletedMerklePayment) public completedMerklePayments;

    /// Maximum supported Merkle tree depth
    uint8 public constant MAX_MERKLE_DEPTH = 12;

    /// Number of candidates per pool (fixed)
    uint8 public constant CANDIDATES_PER_POOL = 16;

    constructor(IERC20 _antToken, uint256 _batchLimit) {
        if (address(_antToken) == address(0)) {
            revert AntTokenNull();
        }

        antToken = _antToken;
        batchLimit = _batchLimit;
    }

    function payForMerkleTree(
        uint8 depth,
        PoolCommitment[] calldata poolCommitments,
        uint64 merklePaymentTimestamp
    ) external returns (bytes32 winnerPoolHash, uint256 totalAmount) {
        // check that the depth is less than max allowed depth
        if (depth > MAX_MERKLE_DEPTH) {
            revert DepthTooLarge(depth, MAX_MERKLE_DEPTH);
        }

        // validate pool count: 2^ceil(depth/2)
        uint256 expectedPools = MerklePaymentLib.expectedRewardPools(depth);
        if (poolCommitments.length != expectedPools) {
            revert WrongPoolCount(expectedPools, poolCommitments.length);
        }

        // select winner
        uint256 winnerPoolIdx = MerklePaymentLib.selectWinnerPool(
            poolCommitments.length,
            msg.sender,
            merklePaymentTimestamp
        );
        PoolCommitment memory winnerPool = poolCommitments[winnerPoolIdx];
        winnerPoolHash = winnerPool.poolHash;

        // verify unique payment
        if (completedMerklePayments[winnerPoolHash].depth != 0) {
            revert PaymentAlreadyExists(winnerPoolHash);
        }

        uint256[CANDIDATES_PER_POOL] memory quotes;
        for (uint256 i = 0; i < CANDIDATES_PER_POOL; i++) {
            quotes[i] = winnerPool.candidates[i].amount;
        }

        totalAmount = MerklePaymentLib.median16(quotes) * (1 << depth);

        // select winner nodes
        uint8[] memory winnerIndices = MerklePaymentLib.selectWinnerNodes(
            depth,
            winnerPoolHash,
            merklePaymentTimestamp
        );

        CompletedMerklePayment storage info = completedMerklePayments[
            winnerPoolHash
        ];
        info.depth = depth;
        info.merklePaymentTimestamp = merklePaymentTimestamp;

        PaidNode[] memory result = new PaidNode[](depth);

        // transfer payments
        uint256 amountPerNode = totalAmount / depth;

        for (uint256 i = 0; i < depth; i++) {
            uint8 nodeIdx = winnerIndices[i];
            address rewardsAddress = winnerPool
                .candidates[nodeIdx]
                .rewardsAddress;

            antToken.safeTransferFrom(
                msg.sender,
                rewardsAddress,
                amountPerNode
            );

            result[i] = PaidNode({
                rewardsAddress: rewardsAddress,
                poolIndex: nodeIdx,
                amount: amountPerNode
            });
        }

        info.paidNodeAddresses = result;

        emit MerklePaymentMade(
            winnerPoolHash,
            depth,
            totalAmount,
            merklePaymentTimestamp
        );

        return (winnerPoolHash, totalAmount);
    }

    function payForQuotes(DataPayment[] calldata _payments) external {
        uint256 paymentsLen = _payments.length;

        if (paymentsLen > batchLimit) {
            revert BatchLimitExceeded();
        }

        for (uint256 i = 0; i < paymentsLen; i++) {
            DataPayment calldata dataPayment = _payments[i];

            if (dataPayment.quoteHash == bytes32(0)) {
                antToken.safeTransferFrom(
                    msg.sender,
                    dataPayment.rewardsAddress,
                    dataPayment.amount
                );
                continue;
            }

            antToken.safeTransferFrom(
                msg.sender,
                dataPayment.rewardsAddress,
                dataPayment.amount
            );

            completedPayments[dataPayment.quoteHash] = CompletedPayment({
                rewardsAddress: getFirst16Bytes(dataPayment.rewardsAddress),
                amount: uint128(dataPayment.amount)
            });

            emit DataPaymentMade(
                dataPayment.rewardsAddress,
                dataPayment.amount,
                dataPayment.quoteHash
            );
        }
    }

    function verifyPayment(
        DataPayment[] calldata _payments
    ) external view returns (PaymentVerificationResult[] memory) {
        PaymentVerificationResult[]
            memory verificationResults = new PaymentVerificationResult[](
                _payments.length
            );
        for (uint256 i = 0; i < _payments.length; i++) {
            DataPayment memory _payment = _payments[i];

            CompletedPayment memory dataPayment = completedPayments[
                _payment.quoteHash
            ];

            bool isAmountOk = (dataPayment.amount != 0) &&
                (dataPayment.amount == _payment.amount);

            bool isAddressOk = dataPayment.rewardsAddress ==
                getFirst16Bytes(_payment.rewardsAddress) &&
                (_payment.rewardsAddress != address(0));

            verificationResults[i] = PaymentVerificationResult({
                quoteHash: _payment.quoteHash,
                amountPaid: dataPayment.amount,
                isValid: isAmountOk && isAddressOk
            });
        }

        return verificationResults;
    }

    function getCompletedMerklePayment(
        bytes32 winnerHash
    ) external view returns (CompletedMerklePayment memory) {
        return completedMerklePayments[winnerHash];
    }

    function getFirst16Bytes(address addr) internal pure returns (bytes16) {
        return bytes16(uint128(uint160(addr) >> 32));
    }
}
