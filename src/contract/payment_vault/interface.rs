use crate::common::{Address, Amount, QuoteHash};
use crate::merkle_batch_payment::CANDIDATES_PER_POOL;
use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[derive(Debug)]
    #[sol(rpc)]
    IPaymentVault,
    "abi/IPaymentVault.json"
);

// Re-export PoolHash
pub use crate::merkle_batch_payment::PoolHash;

impl From<(QuoteHash, Address, Amount)> for IPaymentVault::DataPayment {
    fn from(value: (QuoteHash, Address, Amount)) -> Self {
        Self {
            rewardsAddress: value.1,
            amount: value.2,
            quoteHash: value.0,
        }
    }
}

impl From<crate::merkle_batch_payment::PoolCommitment> for IPaymentVault::PoolCommitment {
    fn from(pool: crate::merkle_batch_payment::PoolCommitment) -> Self {
        let candidates_array: [IPaymentVault::CandidateNode; CANDIDATES_PER_POOL] =
            pool.candidates.map(|c| c.into());
        Self {
            poolHash: pool.pool_hash.into(),
            candidates: candidates_array,
        }
    }
}

impl From<crate::merkle_batch_payment::CandidateNode> for IPaymentVault::CandidateNode {
    fn from(node: crate::merkle_batch_payment::CandidateNode) -> Self {
        Self {
            rewardsAddress: node.rewards_address,
            amount: node.price, // our internal "price" maps to contract's "amount"
        }
    }
}
