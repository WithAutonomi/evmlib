// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.

mod merkle_payment;
mod merkle_tree;

// Re-export types from the merkle_batch_payment module (already in evmlib)
pub use crate::merkle_batch_payment::{
    CANDIDATES_PER_POOL, MAX_MERKLE_DEPTH, OnChainPaymentInfo, PoolCommitment,
    expected_reward_pools,
};

// Export payment types (nodes, pools, proofs)
pub use merkle_payment::{
    MerklePaymentCandidateNode, MerklePaymentCandidatePool, MerklePaymentProof,
    MerklePaymentVerificationError,
};
pub use merkle_tree::{
    BadMerkleProof, MAX_LEAVES, MERKLE_PAYMENT_EXPIRATION, MerkleBranch, MerkleTree,
    MerkleTreeError, MidpointProof, verify_merkle_proof,
};
