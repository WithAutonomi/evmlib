use evmlib::common::Amount;
use evmlib::merkle_batch_payment::{
    CANDIDATES_PER_POOL, CandidateNode, MerkleTreePayment, PoolCommitment, expected_reward_pools,
};

/// Deterministic pool commitment: pool hash and reward addresses derived from
/// `seed`, uniform candidate price. Deterministic hashes avoid the (rare)
/// collision flakes of randomly generated pool hashes.
#[allow(dead_code)]
pub fn deterministic_pool_commitment(price: u64, seed: u16) -> PoolCommitment {
    let candidates: [CandidateNode; CANDIDATES_PER_POOL] = std::array::from_fn(|i| CandidateNode {
        rewards_address: {
            let mut addr = [0u8; 20];
            addr[0..2].copy_from_slice(&seed.to_be_bytes());
            addr[2] = (i + 1) as u8;
            alloy::primitives::Address::new(addr)
        },
        price: Amount::from(price),
    });

    let mut pool_hash = [0u8; 32];
    pool_hash[0..2].copy_from_slice(&seed.to_be_bytes());
    pool_hash[2] = 0xAB;

    PoolCommitment {
        pool_hash,
        candidates,
    }
}

/// Well-formed tree for the given depth: correct pool count, uniform price,
/// pool hashes derived from `salt` (distinct per pool). Space salts of
/// different trees by at least the pool count to keep hashes globally unique.
#[allow(dead_code)]
pub fn deterministic_tree(depth: u8, price: u64, salt: u16, timestamp: u64) -> MerkleTreePayment {
    let pools = expected_reward_pools(depth);
    MerkleTreePayment {
        depth,
        merkle_payment_timestamp: timestamp,
        pool_commitments: (0..pools)
            .map(|j| deterministic_pool_commitment(price, salt + j as u16))
            .collect(),
    }
}
