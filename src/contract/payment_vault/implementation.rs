use crate::common::Address;
use alloy::network::Network;
use alloy::providers::Provider;
use alloy::sol;
use alloy::transports::Transport;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    PaymentVaultImplementation,
    "artifacts/PaymentVaultNoProxyV2.json"
);

/// Deploys the payment vault contract and returns the contract address
pub async fn deploy<T, P, N>(provider: &P, network_token_address: Address) -> Address
where
    T: Transport + Clone,
    P: Provider<T, N>,
    N: Network,
{
    let contract = PaymentVaultImplementation::deploy(provider, network_token_address)
        .await
        .expect("Could not deploy payment vault implementation contract");

    *contract.address()
}
