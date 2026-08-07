// Copyright 2025 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

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
