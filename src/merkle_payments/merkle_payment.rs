// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.

use crate::common::{Address as RewardsAddress, Amount};
use crate::merkle_batch_payment::{CANDIDATES_PER_POOL, CandidateNode, PoolCommitment, PoolHash};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use tiny_keccak::{Hasher, Sha3};
use xor_name::XorName;

use super::merkle_tree::MerkleBranch;
use super::merkle_tree::MidpointProof;

/// Errors that can occur during merkle payment verification
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MerklePaymentVerificationError {
    #[error("Invalid signature for node with address {address}")]
    InvalidNodeSignature { address: RewardsAddress },
    #[error("Timestamp mismatch for node {address}: expected {expected}, got {got}")]
    TimestampMismatch {
        address: RewardsAddress,
        expected: u64,
        got: u64,
    },
    #[error("Data type mismatch for node {address}: expected {expected}, got {got}")]
    DataTypeMismatch {
        address: RewardsAddress,
        expected: u32,
        got: u32,
    },
    #[error("Commitment does not match pool")]
    CommitmentDoesNotMatchPool,
    #[error("Paid node index {index} out of bounds (pool size: {pool_size})")]
    PaidNodeIndexOutOfBounds { index: usize, pool_size: usize },
    #[error("Paid address mismatch at index {index}: expected {expected}, got {got}")]
    PaidAddressMismatch {
        index: usize,
        expected: RewardsAddress,
        got: RewardsAddress,
    },
    #[error("Winner pool hash not found in on-chain commitments")]
    WinnerPoolNotInCommitments,
    #[error(
        "Price mismatch at index {index}: on_chain={on_chain_price}, expected={expected_price}"
    )]
    PriceMismatch {
        index: usize,
        on_chain_price: String,
        expected_price: String,
    },
}

/// A node's signed quote for potential reward eligibility.
///
/// Nodes create this in response to a client's quote request. The `pub_key`
/// field stores the raw ML-DSA-65 public key bytes, and `signature` stores
/// the ML-DSA-65 signature over `bytes_to_sign()`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerklePaymentCandidateNode {
    /// Node's public key bytes (ML-DSA-65)
    pub pub_key: Vec<u8>,

    /// Node-calculated price for storing data
    pub price: Amount,

    /// Node's Ethereum address for payment
    pub reward_address: RewardsAddress,

    /// Quote timestamp (provided by the client)
    pub merkle_payment_timestamp: u64,

    /// Signature over hash(price || reward_address || timestamp)
    pub signature: Vec<u8>,
}

impl MerklePaymentCandidateNode {
    /// Get the bytes to sign.
    pub fn bytes_to_sign(
        price: &Amount,
        reward_address: &RewardsAddress,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&price.to_le_bytes::<32>());
        bytes.extend_from_slice(reward_address.as_slice());
        bytes.extend_from_slice(&timestamp.to_le_bytes());
        bytes
    }

    /// Convert to deterministic byte representation for hashing.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.pub_key);
        bytes.extend_from_slice(&self.price.to_le_bytes::<32>());
        bytes.extend_from_slice(self.reward_address.as_slice());
        bytes.extend_from_slice(&self.merkle_payment_timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }
}

/// One candidate pool: midpoint proof + nodes who could store addresses.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerklePaymentCandidatePool {
    /// The midpoint proof from the merkle tree
    pub midpoint_proof: MidpointProof,

    /// Candidate nodes for this pool (fixed size for determinism)
    pub candidate_nodes: [MerklePaymentCandidateNode; CANDIDATES_PER_POOL],
}

/// Compute SHA3-256 hash of input bytes.
pub(crate) fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    let mut output = [0u8; 32];
    sha3.update(input);
    sha3.finalize(&mut output);
    output
}

impl MerklePaymentCandidatePool {
    /// Compute deterministic hash for on-chain storage key.
    pub fn hash(&self) -> PoolHash {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.midpoint_proof.hash());
        bytes.extend_from_slice(&(self.candidate_nodes.len() as u32).to_le_bytes());
        for node in &self.candidate_nodes {
            bytes.extend_from_slice(&node.to_bytes());
        }
        sha3_256(&bytes)
    }

    /// Convert to minimal commitment for smart contract submission.
    pub fn to_commitment(&self) -> PoolCommitment {
        let candidates: [CandidateNode; CANDIDATES_PER_POOL] =
            self.candidate_nodes.clone().map(|node| CandidateNode {
                rewards_address: node.reward_address,
                price: node.price,
            });

        PoolCommitment {
            pool_hash: self.hash(),
            candidates,
        }
    }

    /// Verify that on-chain prices match what the signed nodes report.
    pub fn verify_prices(
        &self,
        on_chain_commitments: &[PoolCommitment],
        winner_pool_hash: &PoolHash,
    ) -> Result<(), MerklePaymentVerificationError> {
        let on_chain_winner = on_chain_commitments
            .iter()
            .find(|pc| pc.pool_hash == *winner_pool_hash)
            .ok_or(MerklePaymentVerificationError::WinnerPoolNotInCommitments)?;

        for (i, (on_chain_candidate, signed_node)) in on_chain_winner
            .candidates
            .iter()
            .zip(self.candidate_nodes.iter())
            .enumerate()
        {
            if on_chain_candidate.price != signed_node.price {
                return Err(MerklePaymentVerificationError::PriceMismatch {
                    index: i,
                    on_chain_price: on_chain_candidate.price.to_string(),
                    expected_price: signed_node.price.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Get the reward addresses of all candidate nodes.
    pub fn candidate_nodes_addresses(&self) -> HashSet<RewardsAddress> {
        self.candidate_nodes
            .iter()
            .map(|node| node.reward_address)
            .collect()
    }
}

/// Data package for merkle payment verification.
///
/// Contains everything a node needs to verify a merkle batch payment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerklePaymentProof {
    /// The data's XorName
    pub address: XorName,

    /// Merkle proof that this data belongs to the paid tree
    pub data_proof: MerkleBranch,

    /// The winner pool selected by the smart contract
    pub winner_pool: MerklePaymentCandidatePool,
}

impl MerklePaymentProof {
    /// Create a new Merkle payment proof.
    pub fn new(
        address: XorName,
        data_proof: MerkleBranch,
        winner_pool: MerklePaymentCandidatePool,
    ) -> Self {
        Self {
            address,
            data_proof,
            winner_pool,
        }
    }

    /// Get the hash of the winner pool (used to query smart contract for payment info).
    pub fn winner_pool_hash(&self) -> PoolHash {
        self.winner_pool.hash()
    }
}
