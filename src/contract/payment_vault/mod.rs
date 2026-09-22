use crate::contract::payment_vault::error::Error;
use crate::contract::payment_vault::handler::PaymentVaultHandler;
use crate::merkle_batch_payment::PoolHash;
use crate::utils::http_provider;

pub mod error;
pub mod handler;
pub mod implementation;
pub mod interface;

pub const MAX_TRANSFERS_PER_TRANSACTION: usize = 256;

/// Helper function to get completed merkle payment info for verification.
/// Returns the payment info if the payment exists on-chain.
pub async fn get_completed_merkle_payment(
    network: &crate::Network,
    winner_pool_hash: PoolHash,
) -> Result<interface::IPaymentVault::CompletedMerklePayment, Error> {
    let vault_address = *network.payment_vault_address();

    debug!(
        "get_completed_merkle_payment: contract={:?}, pool_hash={}",
        vault_address,
        hex::encode(winner_pool_hash)
    );

    let provider = http_provider(network.rpc_url().clone());
    let handler = PaymentVaultHandler::new(vault_address, provider);

    handler.get_completed_merkle_payment(winner_pool_hash).await
}

/// Encode the native vault call for an external signer without constructing an RPC provider.
pub fn encode_merkle_payment<T: Into<interface::IPaymentVault::PoolCommitment>>(
    depth: u8,
    pools: Vec<T>,
    timestamp: u64,
) -> Vec<u8> {
    use alloy::sol_types::SolCall;
    interface::IPaymentVault::payForMerkleTreeCall {
        depth,
        poolCommitments: pools.into_iter().map(Into::into).collect(),
        merklePaymentTimestamp: timestamp,
    }
    .abi_encode()
}

/// Decode a vault Merkle settlement event using the same ABI as the native wallet.
pub fn decode_merkle_payment_event(
    topics: &[[u8; 32]],
    data: &[u8],
) -> Result<interface::IPaymentVault::MerklePaymentMade, alloy::sol_types::Error> {
    use alloy::sol_types::SolEvent;
    interface::IPaymentVault::MerklePaymentMade::decode_raw_log(
        topics.iter().copied().map(alloy::primitives::B256::from),
        data,
    )
}
