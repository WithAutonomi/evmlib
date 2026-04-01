// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Merkle batch payment types and disk-based mock smart contract
//!
//! This module contains the minimal types needed for Merkle batch payments and a disk-based
//! mock implementation of the smart contract. When the real smart contract is ready, the
//! disk contract will be replaced with actual on-chain calls.

use crate::common::{Address as RewardsAddress, Amount};

#[cfg(test)]
use crate::common::U256;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
use thiserror::Error;

/// Pool hash type (32 bytes) - compatible with XorName without the dependency
pub type PoolHash = [u8; 32];

/// Number of candidate nodes per pool (provides redundancy)
pub const CANDIDATES_PER_POOL: usize = 16;

/// Maximum supported Merkle tree depth
pub const MAX_MERKLE_DEPTH: u8 = 8;

/// Calculate expected number of reward pools for a given tree depth
///
/// Formula: 2^floor(depth/2)
pub fn expected_reward_pools(depth: u8) -> usize {
    let half_depth = depth / 2;
    1 << half_depth
}

/// Minimal pool commitment for smart contract submission
///
/// Contains only what's needed on-chain, with cryptographic commitment to full off-chain data.
/// This is sent to the smart contract as part of the batch payment transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoolCommitment {
    /// Hash of the full MerklePaymentCandidatePool (cryptographic commitment)
    /// This commits to the midpoint proof and all node signatures
    pub pool_hash: PoolHash,

    /// Candidate nodes with prices
    pub candidates: [CandidateNode; CANDIDATES_PER_POOL],
}

/// Candidate node with price for pool commitment
///
/// Nodes calculate their own price as `(chunks_stored / 6000)^2`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateNode {
    /// Rewards address of the candidate node
    pub rewards_address: RewardsAddress,

    /// Node-calculated price
    pub price: Amount,
}

/// What's stored on-chain (or disk) - indexed by winner_pool_hash
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnChainPaymentInfo {
    /// Tree depth
    pub depth: u8,

    /// Merkle payment timestamp provided by client (unix seconds)
    /// This is the timestamp that all nodes in the pool used for their quotes
    pub merkle_payment_timestamp: u64,

    /// Addresses of the 'depth' nodes that were paid, with their pool index and paid amount
    pub paid_node_addresses: Vec<(RewardsAddress, usize, Amount)>,
}

#[cfg(test)]
/// Errors that can occur during smart contract operations
#[derive(Debug, Error)]
pub enum SmartContractError {
    #[error("Wrong number of candidate nodes: expected {expected}, got {got}")]
    WrongCandidateCount { expected: usize, got: usize },

    #[error("Wrong number of candidate pools: expected {expected}, got {got}")]
    WrongPoolCount { expected: usize, got: usize },

    #[error("Depth {depth} exceeds maximum supported depth {max}")]
    DepthTooLarge { depth: u8, max: u8 },

    #[error("Payment not found for winner pool hash: {0}")]
    PaymentNotFound(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

#[cfg(test)]
/// Disk-based Merkle payment contract (mock for testing)
///
/// This simulates smart contract behavior by storing payment data to disk.
/// Only available for testing.
pub struct DiskMerklePaymentContract {
    storage_path: PathBuf, // ~/.autonomi/merkle_payments/
}

#[cfg(test)]
impl DiskMerklePaymentContract {
    /// Create a new contract with a specific storage path
    pub fn new_with_path(storage_path: PathBuf) -> Result<Self, SmartContractError> {
        std::fs::create_dir_all(&storage_path)?;
        Ok(Self { storage_path })
    }

    /// Create a new contract with the default storage path
    /// Uses: DATA_DIR/autonomi/merkle_payments/
    pub fn new() -> Result<Self, SmartContractError> {
        let storage_path = if let Some(data_dir) = dirs_next::data_dir() {
            data_dir.join("autonomi").join("merkle_payments")
        } else {
            // Fallback to current directory if data_dir is not available
            PathBuf::from(".autonomi").join("merkle_payments")
        };
        Self::new_with_path(storage_path)
    }

    /// Submit batch payment (simulates smart contract logic)
    ///
    /// # Arguments
    /// * `depth` - Tree depth
    /// * `pool_commitments` - Minimal pool commitments (2^ceil(depth/2) pools with hashes + addresses)
    /// * `merkle_payment_timestamp` - Client-defined timestamp committed to by all nodes in their quotes
    ///
    /// # Returns
    /// * `winner_pool_hash` - Hash of winner pool (storage key for verification)
    /// * `amount` - Amount paid for the Merkle tree
    pub fn pay_for_merkle_tree(
        &self,
        depth: u8,
        pool_commitments: Vec<PoolCommitment>,
        merkle_payment_timestamp: u64,
    ) -> Result<(PoolHash, Amount), SmartContractError> {
        // Validate: depth is within supported range
        if depth > MAX_MERKLE_DEPTH {
            return Err(SmartContractError::DepthTooLarge {
                depth,
                max: MAX_MERKLE_DEPTH,
            });
        }

        // Validate: correct number of pools (2^ceil(depth/2))
        let expected_pools = expected_reward_pools(depth);
        if pool_commitments.len() != expected_pools {
            return Err(SmartContractError::WrongPoolCount {
                expected: expected_pools,
                got: pool_commitments.len(),
            });
        }

        // Validate: each pool has exactly CANDIDATES_PER_POOL candidates
        for pool in &pool_commitments {
            if pool.candidates.len() != CANDIDATES_PER_POOL {
                return Err(SmartContractError::WrongCandidateCount {
                    expected: CANDIDATES_PER_POOL,
                    got: pool.candidates.len(),
                });
            }
        }

        // Select winner pool using random selection
        let winner_pool_idx = rand::random::<usize>() % pool_commitments.len();

        let winner_pool = &pool_commitments[winner_pool_idx];
        let winner_pool_hash = winner_pool.pool_hash;

        println!("\n=== MERKLE BATCH PAYMENT ===");
        println!("Depth: {depth}");
        println!("Total pools: {}", pool_commitments.len());
        println!("Nodes per pool: {CANDIDATES_PER_POOL}");
        println!("Winner pool index: {winner_pool_idx}");
        println!("Winner pool hash: {}", hex::encode(winner_pool_hash));

        // Select 'depth' unique winner nodes within the winner pool
        use std::collections::HashSet;
        let mut winner_node_indices = HashSet::new();
        while winner_node_indices.len() < depth as usize {
            let idx = rand::random::<usize>() % winner_pool.candidates.len();
            winner_node_indices.insert(idx);
        }
        let winner_node_indices: Vec<usize> = winner_node_indices.into_iter().collect();

        println!(
            "\nSelected {} winner nodes from pool:",
            winner_node_indices.len()
        );

        // Calculate total amount from winner node prices
        let mut total_amount = Amount::ZERO;

        // Extract paid node addresses, along with their indices
        let mut paid_node_addresses = Vec::new();
        for (i, &node_idx) in winner_node_indices.iter().enumerate() {
            let candidate = &winner_pool.candidates[node_idx];
            let addr = candidate.rewards_address;
            paid_node_addresses.push((addr, node_idx, candidate.price));
            total_amount += candidate.price;
            println!("  Node {}: {addr} (price: {})", i + 1, candidate.price);
        }

        println!(
            "\nSimulating payment to {} nodes, total: {total_amount}...",
            paid_node_addresses.len()
        );
        println!("=========================\n");

        // Store payment info on 'blockchain' (indexed by winner_pool_hash)
        let info = OnChainPaymentInfo {
            depth,
            merkle_payment_timestamp,
            paid_node_addresses,
        };

        let file_path = self
            .storage_path
            .join(format!("{}.json", hex::encode(winner_pool_hash)));
        let json = serde_json::to_string_pretty(&info)?;
        std::fs::write(&file_path, json)?;

        println!("✓ Stored payment info to: {}", file_path.display());

        Ok((winner_pool_hash, total_amount))
    }

    /// Get payment info by winner pool hash
    pub fn get_payment_info(
        &self,
        winner_pool_hash: PoolHash,
    ) -> Result<OnChainPaymentInfo, SmartContractError> {
        let file_path = self
            .storage_path
            .join(format!("{}.json", hex::encode(winner_pool_hash)));
        let json = std::fs::read_to_string(&file_path)
            .map_err(|_| SmartContractError::PaymentNotFound(hex::encode(winner_pool_hash)))?;
        let info = serde_json::from_str(&json)?;
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_reward_pools() {
        assert_eq!(expected_reward_pools(1), 1);
        assert_eq!(expected_reward_pools(2), 2);
        assert_eq!(expected_reward_pools(3), 2);
        assert_eq!(expected_reward_pools(4), 4);
        assert_eq!(expected_reward_pools(8), 16);
    }

    #[test]
    fn test_candidate_node_price() {
        let candidate = CandidateNode {
            rewards_address: RewardsAddress::from([0x42; 20]),
            price: U256::from(1000u64),
        };
        assert_eq!(candidate.price, U256::from(1000u64));
        assert_eq!(candidate.rewards_address, RewardsAddress::from([0x42; 20]));
    }

    #[test]
    fn test_pool_commitment_structure() {
        let candidates: [CandidateNode; CANDIDATES_PER_POOL] =
            std::array::from_fn(|i| CandidateNode {
                rewards_address: RewardsAddress::from([i as u8; 20]),
                price: U256::from((i as u64 + 1) * 100),
            });

        let pool = PoolCommitment {
            pool_hash: [0x42; 32],
            candidates,
        };

        assert_eq!(pool.pool_hash, [0x42; 32]);
        assert_eq!(pool.candidates.len(), CANDIDATES_PER_POOL);
        assert_eq!(pool.candidates[0].price, U256::from(100u64));
        assert_eq!(pool.candidates[15].price, U256::from(1600u64));
    }
}
