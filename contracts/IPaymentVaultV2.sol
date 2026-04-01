// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {
    PoolCommitment,
    DataPayment,
    PaymentVerificationResult
} from "./Types.sol";

interface IPaymentVaultV2 {
    error AntTokenNull();
    error BatchLimitExceeded();
    error InvalidInputLength();
    error DepthTooLarge(uint8 depth, uint8 maxDepth);
    error WrongPoolCount(uint256 expected, uint256 actual);
    error PaymentAlreadyExists(bytes32 winnerPoolHash);

    event DataPaymentMade(
        address indexed rewardsAddress,
        uint256 indexed amount,
        bytes32 indexed quoteHash
    );

    /// Emitted when a Merkle batch payment is made
    event MerklePaymentMade(
        bytes32 indexed winnerPoolHash,
        uint8 depth,
        uint256 totalAmount,
        uint64 merklePaymentTimestamp
    );

    function payForMerkleTree(
        uint8 depth,
        PoolCommitment[] calldata poolCommitments,
        uint64 merklePaymentTimestamp
    ) external returns (bytes32 winnerPoolHash, uint256 totalAmount);

    function payForQuotes(DataPayment[] calldata _payments) external;

    function verifyPayment(
        DataPayment[] calldata _payments
    ) external view returns (PaymentVerificationResult[] memory);
}
