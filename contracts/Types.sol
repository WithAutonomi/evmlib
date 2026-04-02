// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Individual paid node record
struct PaidNode {
    address rewardsAddress;
    uint8 poolIndex; // Index in winner pool (0-19)
    uint256 amount;
}

/// Payment information stored on-chain
struct CompletedMerklePayment {
    uint8 depth; // Merkle tree depth
    uint64 merklePaymentTimestamp; // Payment timestamp
    PaidNode[] paidNodeAddresses; // List of paid nodes
}

struct CompletedPayment {
    bytes16 rewardsAddress;
    uint128 amount;
}

struct CandidateNode {
    address rewardsAddress;
    uint256 amount;
}

struct PoolCommitment {
    bytes32 poolHash; // Cryptographic commitment to full pool data
    CandidateNode[16] candidates; // Fixed size: always 16
}

struct DataPayment {
    address rewardsAddress;
    uint256 amount;
    bytes32 quoteHash;
}

struct PaymentVerificationResult {
    bytes32 quoteHash;
    uint256 amountPaid;
    bool isValid;
}
