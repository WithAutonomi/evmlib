// Copyright 2025 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

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

    /// Signature over `bytes_to_sign`
    pub signature: Vec<u8>,

    /// ADR-0004: the number of keys in the storage commitment this price was
    /// derived from. `0` for a baseline (no-commitment) quote. Tail-placed with
    /// `#[serde(default)]` so an old-format candidate (lacking these fields)
    /// decodes as `0`/`None` rather than misaligning onto `signature`.
    #[serde(default)]
    pub committed_key_count: u32,

    /// ADR-0004: the pin (commitment hash) of the storage commitment this price
    /// was derived from. `None` for a baseline quote.
    #[serde(default)]
    pub commitment_pin: Option<[u8; 32]>,
}

impl MerklePaymentCandidateNode {
    /// Get the bytes to sign.
    ///
    /// ADR-0004: the commitment binding (`committed_key_count`, `commitment_pin`)
    /// is appended to the signed payload so the per-node ML-DSA-65 signature
    /// covers it — making a count/pin mismatch genuine "two artifacts signed by
    /// the same key" evidence. The pin is tagged (`0` = none, `1` = present) so a
    /// baseline candidate can never collide with one pinning an all-zero hash.
    /// This is a coordinated breaking change: `ant-protocol` must verify the same
    /// 5-field message (its `verify_merkle_candidate_signature` reconstructs this
    /// exact payload).
    pub fn bytes_to_sign(
        price: &Amount,
        reward_address: &RewardsAddress,
        timestamp: u64,
        committed_key_count: u32,
        commitment_pin: &Option<[u8; 32]>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&price.to_le_bytes::<32>());
        bytes.extend_from_slice(reward_address.as_slice());
        bytes.extend_from_slice(&timestamp.to_le_bytes());
        bytes.extend_from_slice(&committed_key_count.to_le_bytes());
        match commitment_pin {
            Some(pin) => {
                bytes.push(1u8);
                bytes.extend_from_slice(pin);
            }
            None => bytes.push(0u8),
        }
        bytes
    }

    /// Convert to deterministic byte representation for hashing.
    ///
    /// ADR-0004 fields are included so the commitment binding is covered by the
    /// pool hash (and therefore the on-chain commitment), not only the
    /// per-node signature.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.pub_key);
        bytes.extend_from_slice(&self.price.to_le_bytes::<32>());
        bytes.extend_from_slice(self.reward_address.as_slice());
        bytes.extend_from_slice(&self.merkle_payment_timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.committed_key_count.to_le_bytes());
        match &self.commitment_pin {
            Some(pin) => {
                bytes.push(1u8);
                bytes.extend_from_slice(pin);
            }
            None => bytes.push(0u8),
        }
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

    /// ADR-0004 commitment sidecars: the signed storage commitment each winner
    /// candidate pinned, as opaque serialized blobs, so a storer can cross-check
    /// a candidate's claimed count against the original commitment synchronously
    /// ("the commitment arrived with the quote"). `evmlib` stays agnostic of the
    /// commitment type; the node deserializes and validates each. Tail-placed,
    /// `serde(default)`: an old proof simply carries none and the node falls
    /// back to gossip/fetch.
    #[serde(default)]
    pub commitment_sidecars: Vec<Vec<u8>>,
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
            commitment_sidecars: Vec::new(),
        }
    }

    /// Get the hash of the winner pool (used to query smart contract for payment info).
    pub fn winner_pool_hash(&self) -> PoolHash {
        self.winner_pool.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_payments::MerkleTree;

    const TIMESTAMP: u64 = 1_700_000_000;

    /// A pool whose candidate `i` quotes `100 + i`, so every index has a
    /// distinct price and a mismatch report names the right candidate.
    fn make_pool() -> MerklePaymentCandidatePool {
        let leaves = (0..4u8).map(|i| XorName([i; 32])).collect();
        let tree = MerkleTree::from_xornames(leaves).expect("tree");
        let midpoint_proof = tree
            .reward_candidates(TIMESTAMP)
            .expect("reward candidates")
            .remove(0);
        let candidate_nodes = std::array::from_fn(|i| MerklePaymentCandidateNode {
            pub_key: vec![i as u8; 4],
            price: Amount::from(100 + i as u64),
            reward_address: RewardsAddress::new([i as u8; 20]),
            merkle_payment_timestamp: TIMESTAMP,
            signature: vec![],
            committed_key_count: 0,
            commitment_pin: None,
        });
        MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes,
        }
    }

    #[test]
    fn verify_prices_accepts_matching_on_chain_prices() {
        let pool = make_pool();
        let on_chain = [pool.to_commitment()];
        assert_eq!(pool.verify_prices(&on_chain, &pool.hash()), Ok(()));
    }

    #[test]
    fn verify_prices_checks_the_winner_not_the_first_commitment() {
        let pool = make_pool();
        // A decoy pool listed first, with a different hash and every price off.
        let mut decoy = pool.to_commitment();
        decoy.pool_hash = [0xAA; 32];
        for candidate in &mut decoy.candidates {
            candidate.price += Amount::from(1u64);
        }
        let on_chain = [decoy, pool.to_commitment()];
        assert_eq!(pool.verify_prices(&on_chain, &pool.hash()), Ok(()));
    }

    #[test]
    fn verify_prices_rejects_a_mismatch_at_the_first_candidate() {
        let pool = make_pool();
        let mut commitment = pool.to_commitment();
        commitment.candidates[0].price = Amount::from(999u64);
        assert_eq!(
            pool.verify_prices(&[commitment], &pool.hash()),
            Err(MerklePaymentVerificationError::PriceMismatch {
                index: 0,
                on_chain_price: "999".to_string(),
                expected_price: "100".to_string(),
            })
        );
    }

    #[test]
    fn verify_prices_rejects_a_mismatch_at_the_last_candidate() {
        let pool = make_pool();
        let last = CANDIDATES_PER_POOL - 1;
        let mut commitment = pool.to_commitment();
        commitment.candidates[last].price = Amount::from(999u64);
        assert_eq!(
            pool.verify_prices(&[commitment], &pool.hash()),
            Err(MerklePaymentVerificationError::PriceMismatch {
                index: last,
                on_chain_price: "999".to_string(),
                expected_price: (100 + last).to_string(),
            })
        );
    }

    #[test]
    fn verify_prices_reports_the_first_of_several_mismatches() {
        let pool = make_pool();
        let mut commitment = pool.to_commitment();
        commitment.candidates[3].price = Amount::ZERO;
        commitment.candidates[7].price = Amount::ZERO;
        assert!(matches!(
            pool.verify_prices(&[commitment], &pool.hash()),
            Err(MerklePaymentVerificationError::PriceMismatch { index: 3, .. })
        ));
    }

    #[test]
    fn verify_prices_rejects_a_winner_hash_missing_from_the_commitments() {
        let pool = make_pool();
        let on_chain = [pool.to_commitment()];
        assert_eq!(
            pool.verify_prices(&on_chain, &[0xBB; 32]),
            Err(MerklePaymentVerificationError::WinnerPoolNotInCommitments)
        );
        assert_eq!(
            pool.verify_prices(&[], &pool.hash()),
            Err(MerklePaymentVerificationError::WinnerPoolNotInCommitments)
        );
    }
}
