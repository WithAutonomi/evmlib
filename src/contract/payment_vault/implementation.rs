use crate::common::Address;
use alloy::network::Network;
use alloy::primitives::U256;
use alloy::providers::Provider;
use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    PaymentVaultImplementation,
    "artifacts/PaymentVaultV2.json"
);

/// Default batch limit for local deployments.
const DEFAULT_BATCH_LIMIT: U256 = U256::from_limbs([512, 0, 0, 0]);

/// Deploys the unified payment vault contract and returns the contract address.
///
/// Uses a default batch limit of 512 for local testing.
pub async fn deploy<P, N>(provider: &P, network_token_address: Address) -> Address
where
    P: Provider<N>,
    N: Network,
{
    let contract =
        PaymentVaultImplementation::deploy(provider, network_token_address, DEFAULT_BATCH_LIMIT)
            .await
            .expect("Could not deploy payment vault implementation contract");

    *contract.address()
}
