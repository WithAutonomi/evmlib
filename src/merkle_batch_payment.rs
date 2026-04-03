// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Merkle batch payment types
//!
//! This module contains the minimal types needed for Merkle batch payments.

use crate::common::{Address as RewardsAddress, Amount};

#[cfg(test)]
use crate::common::U256;
use serde::{Deserialize, Serialize};

/// Pool hash type (32 bytes) - compatible with XorName without the dependency
pub type PoolHash = [u8; 32];

/// Number of candidate nodes per pool (provides redundancy)
pub const CANDIDATES_PER_POOL: usize = 16;

/// Maximum supported Merkle tree depth
pub const MAX_MERKLE_DEPTH: u8 = 8;

/// Calculate expected number of reward pools for a given tree depth
///
/// Formula: 2^ceil(depth/2) — must match `MerklePaymentLib.expectedRewardPools` in Solidity
pub fn expected_reward_pools(depth: u8) -> usize {
    let half_depth = depth.div_ceil(2);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_reward_pools() {
        assert_eq!(expected_reward_pools(1), 2);
        assert_eq!(expected_reward_pools(2), 2);
        assert_eq!(expected_reward_pools(3), 4);
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
