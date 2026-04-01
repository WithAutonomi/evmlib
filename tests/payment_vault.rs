#![allow(clippy::expect_used)]

mod common;

use crate::common::quote::random_quote_payment;
use alloy::network::{Ethereum, EthereumWallet};
use alloy::node_bindings::AnvilInstance;
use alloy::primitives::utils::parse_ether;
use alloy::providers::ext::AnvilApi;
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
    SimpleNonceManager, WalletFiller,
};
use alloy::providers::{Identity, ProviderBuilder, RootProvider, WalletProvider};
use alloy::signers::local::{LocalSigner, PrivateKeySigner};
use evmlib::common::U256;
use evmlib::contract::network_token::NetworkToken;
use evmlib::contract::payment_vault::MAX_TRANSFERS_PER_TRANSACTION;
use evmlib::contract::payment_vault::handler::PaymentVaultHandler;
use evmlib::testnet::{deploy_network_token_contract, deploy_payment_vault_contract, start_node};
use evmlib::transaction_config::TransactionConfig;
use evmlib::wallet::wallet_address;

async fn setup() -> (
    AnvilInstance,
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
) {
    let (node, rpc_url) = start_node().unwrap();

    let network_token = deploy_network_token_contract(&rpc_url, &node)
        .await
        .unwrap();

    let payment_vault =
        deploy_payment_vault_contract(&rpc_url, &node, *network_token.contract.address())
            .await
            .unwrap();

    (node, network_token, payment_vault)
}

#[allow(clippy::unwrap_used)]
#[allow(clippy::type_complexity)]
#[allow(dead_code)]
async fn provider_with_gas_funded_wallet(
    anvil: &AnvilInstance,
) -> FillProvider<
    JoinFill<
        JoinFill<
            JoinFill<
                Identity,
                JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
            >,
            NonceFiller<SimpleNonceManager>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
    Ethereum,
> {
    let signer: PrivateKeySigner = LocalSigner::random();
    let wallet = EthereumWallet::from(signer);

    let rpc_url = anvil.endpoint().parse().unwrap();

    let provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .wallet(wallet)
        .connect_http(rpc_url);

    let account = wallet_address(provider.wallet());

    // Fund the wallet with plenty of gas tokens
    provider
        .anvil_set_balance(account, parse_ether("1000").expect(""))
        .await
        .unwrap();

    provider
}

#[tokio::test]
async fn test_deploy() {
    setup().await;
}

#[tokio::test]
async fn test_pay_for_quotes_on_local() {
    let (_anvil, network_token, mut payment_vault) = setup().await;

    let transaction_config = TransactionConfig::default();

    let mut quote_payments = vec![];

    for _ in 0..MAX_TRANSFERS_PER_TRANSACTION {
        let quote_payment = random_quote_payment();
        quote_payments.push(quote_payment);
    }

    let _ = network_token
        .approve(
            *payment_vault.contract.address(),
            U256::MAX,
            &transaction_config,
        )
        .await
        .unwrap();

    // Contract provider has a different account coupled to it,
    // so we set it to the same as the network token contract
    payment_vault.set_provider(network_token.contract.provider().clone());

    let result = payment_vault
        .pay_for_quotes(quote_payments, &transaction_config)
        .await;

    assert!(result.is_ok(), "Failed with error: {:?}", result.err());
}
