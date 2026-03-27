// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::env;
use std::num::ParseIntError;

use crate::common::Address;
use crate::contract::merkle_payment_vault::handler::MerklePaymentVaultHandler;
use crate::contract::payment_vault::handler::PaymentVaultHandler;
use crate::contract::{merkle_payment_vault, network_token::NetworkToken, payment_vault};
use crate::reqwest::Url;
use crate::{CustomNetwork, Network};
use alloy::hex::ToHexExt;
use alloy::network::{Ethereum, EthereumWallet};
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
    SimpleNonceManager, WalletFiller,
};
use alloy::providers::{Identity, ProviderBuilder, RootProvider};
use alloy::signers::local::PrivateKeySigner;

#[derive(Debug, thiserror::Error)]
pub enum TestnetError {
    #[error("ANVIL_PORT must be a valid u16: {0}")]
    InvalidPort(#[from] ParseIntError),
    #[error("Could not spawn Anvil node: {0}")]
    SpawnFailed(String),
    #[error("Failed to parse Anvil RPC URL: {0}")]
    InvalidUrl(String),
    #[error("Anvil key at index {0} not available")]
    MissingKey(usize),
}

pub struct Testnet {
    anvil: AnvilInstance,
    rpc_url: Url,
    network_token_address: Address,
    data_payments_address: Address,
    merkle_payments_address: Address,
}

impl Testnet {
    /// Starts an Anvil node and automatically deploys the network token and chunk payments smart contracts.
    pub async fn new() -> Result<Self, TestnetError> {
        let (node, rpc_url) = start_node()?;

        let network_token = deploy_network_token_contract(&rpc_url, &node).await?;
        let data_payments =
            deploy_data_payments_contract(&rpc_url, &node, *network_token.contract.address())
                .await?;
        let merkle_payments =
            deploy_merkle_payments_contract(&rpc_url, &node, *network_token.contract.address())
                .await?;

        Ok(Testnet {
            anvil: node,
            rpc_url,
            network_token_address: *network_token.contract.address(),
            data_payments_address: *data_payments.contract.address(),
            merkle_payments_address: *merkle_payments.contract.address(),
        })
    }

    pub fn to_network(&self) -> Network {
        Network::Custom(CustomNetwork {
            rpc_url_http: self.rpc_url.clone(),
            payment_token_address: self.network_token_address,
            data_payments_address: self.data_payments_address,
            merkle_payments_address: Some(self.merkle_payments_address),
        })
    }

    pub fn default_wallet_private_key(&self) -> Result<String, TestnetError> {
        // Fetches private key from the first default Anvil account (Alice).
        let key = self
            .anvil
            .keys()
            .first()
            .ok_or(TestnetError::MissingKey(0))?;
        let signer: PrivateKeySigner = key.clone().into();
        Ok(signer.to_bytes().encode_hex_with_prefix())
    }

    pub fn merkle_payments_address(&self) -> Address {
        self.merkle_payments_address
    }
}

/// Runs a local Anvil node bound to a specified IP address.
///
/// The `AnvilInstance` `endpoint` function is hardcoded to return "localhost", so we must also
/// return the RPC URL if we want to listen on a different address.
///
/// The `anvil` binary respects the `ANVIL_IP_ADDR` environment variable, but defaults to "localhost".
pub fn start_node() -> Result<(AnvilInstance, Url), TestnetError> {
    let host = env::var("ANVIL_IP_ADDR").unwrap_or_else(|_| "localhost".to_string());

    let mut builder = Anvil::new();

    // Only bind to a fixed port if explicitly requested via ANVIL_PORT.
    // By default, let the OS assign a random available port (port 0) so that
    // multiple Anvil instances (parallel tests, sequential tests with TIME_WAIT)
    // never collide on the same port.
    if let Ok(port_str) = env::var("ANVIL_PORT") {
        let port = port_str.parse::<u16>()?;
        builder = builder.port(port);
    }

    let anvil = builder
        .try_spawn()
        .map_err(|e| TestnetError::SpawnFailed(e.to_string()))?;

    // We have to manually return the RPC URL because the `anvil::endpoint_url()` always returns `localhost`
    let port = anvil.port();
    let url = Url::parse(&format!("http://{host}:{port}"))
        .map_err(|e| TestnetError::InvalidUrl(e.to_string()))?;

    Ok((anvil, url))
}

pub async fn deploy_network_token_contract(
    rpc_url: &Url,
    anvil: &AnvilInstance,
) -> Result<
    NetworkToken<
        FillProvider<
            JoinFill<
                JoinFill<
                    JoinFill<
                        Identity,
                        JoinFill<
                            GasFiller,
                            JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>,
                        >,
                    >,
                    NonceFiller<SimpleNonceManager>,
                >,
                WalletFiller<EthereumWallet>,
            >,
            RootProvider,
            Ethereum,
        >,
        Ethereum,
    >,
    TestnetError,
> {
    // Set up signer from the first default Anvil account (Alice).
    let key = anvil.keys().first().ok_or(TestnetError::MissingKey(0))?;
    let signer: PrivateKeySigner = key.clone().into();
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .wallet(wallet)
        .connect_http(rpc_url.clone());

    // Deploy the contract.
    Ok(NetworkToken::deploy(provider).await)
}

pub async fn deploy_data_payments_contract(
    rpc_url: &Url,
    anvil: &AnvilInstance,
    token_address: Address,
) -> Result<
    PaymentVaultHandler<
        FillProvider<
            JoinFill<
                JoinFill<
                    JoinFill<
                        Identity,
                        JoinFill<
                            GasFiller,
                            JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>,
                        >,
                    >,
                    NonceFiller<SimpleNonceManager>,
                >,
                WalletFiller<EthereumWallet>,
            >,
            RootProvider,
            Ethereum,
        >,
        Ethereum,
    >,
    TestnetError,
> {
    // Set up signer from the second default Anvil account (Bob).
    let key = anvil.keys().get(1).ok_or(TestnetError::MissingKey(1))?;
    let signer: PrivateKeySigner = key.clone().into();
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .wallet(wallet)
        .connect_http(rpc_url.clone());

    // Deploy the contract.
    let payment_vault_contract_address =
        payment_vault::implementation::deploy(&provider, token_address).await;

    // Create a handler for the deployed contract
    Ok(PaymentVaultHandler::new(
        payment_vault_contract_address,
        provider,
    ))
}

pub async fn deploy_merkle_payments_contract(
    rpc_url: &Url,
    anvil: &AnvilInstance,
    token_address: Address,
) -> Result<
    MerklePaymentVaultHandler<
        FillProvider<
            JoinFill<
                JoinFill<
                    JoinFill<
                        Identity,
                        JoinFill<
                            GasFiller,
                            JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>,
                        >,
                    >,
                    NonceFiller<SimpleNonceManager>,
                >,
                WalletFiller<EthereumWallet>,
            >,
            RootProvider,
            Ethereum,
        >,
        Ethereum,
    >,
    TestnetError,
> {
    // Set up signer from the third default Anvil account (Charlie).
    let key = anvil.keys().get(2).ok_or(TestnetError::MissingKey(2))?;
    let signer: PrivateKeySigner = key.clone().into();
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .wallet(wallet)
        .connect_http(rpc_url.clone());

    // Deploy the contract.
    let merkle_payment_vault_contract_address =
        merkle_payment_vault::implementation::deploy(&provider, token_address).await;

    // Create a handler for the deployed contract
    Ok(MerklePaymentVaultHandler::new(
        merkle_payment_vault_contract_address,
        provider,
    ))
}

#[cfg(test)]
mod tests {
    use crate::testnet::Testnet;

    #[tokio::test]
    async fn test_run_multiple_testnets_in_parallel() {
        let (_t1, _t2, _t3, _t4) = tokio::join!(
            Testnet::new(),
            Testnet::new(),
            Testnet::new(),
            Testnet::new(),
        );
        _t1.unwrap();
        _t2.unwrap();
        _t3.unwrap();
        _t4.unwrap();
    }
}
