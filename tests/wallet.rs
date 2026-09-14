#![allow(clippy::expect_used)]

mod common;

use crate::common::quote::random_quote_payment;
use alloy::network::EthereumWallet;
use alloy::node_bindings::AnvilInstance;
use alloy::primitives::utils::parse_ether;
use alloy::providers::ext::AnvilApi;
use alloy::providers::{ProviderBuilder, WalletProvider};
use alloy::signers::local::{LocalSigner, PrivateKeySigner};
use evmlib::common::{Amount, TxHash};
use evmlib::contract::payment_vault::MAX_TRANSFERS_PER_TRANSACTION;
use evmlib::testnet::{deploy_network_token_contract, deploy_payment_vault_contract, start_node};
use evmlib::transaction_config::TransactionConfig;
use evmlib::wallet::{Wallet, transfer_tokens, wallet_address};
use evmlib::{CustomNetwork, Network};
use std::collections::HashSet;
use std::ops::Mul;

#[allow(clippy::unwrap_used)]
async fn local_testnet() -> (AnvilInstance, Network, EthereumWallet) {
    let (node, rpc_url) = start_node().unwrap();
    let network_token = deploy_network_token_contract(&rpc_url, &node)
        .await
        .unwrap();
    let payment_token_address = *network_token.contract.address();
    let payment_vault = deploy_payment_vault_contract(&rpc_url, &node, payment_token_address)
        .await
        .unwrap();

    (
        node,
        Network::Custom(CustomNetwork {
            rpc_url_http: rpc_url,
            payment_token_address,
            payment_vault_address: *payment_vault.contract.address(),
        }),
        network_token.contract.provider().wallet().clone(),
    )
}

#[allow(clippy::unwrap_used)]
async fn funded_wallet(network: &Network, genesis_wallet: EthereumWallet) -> Wallet {
    let signer: PrivateKeySigner = LocalSigner::random();
    let wallet = EthereumWallet::from(signer);
    let account = wallet_address(&wallet);

    let provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .wallet(genesis_wallet.clone())
        .connect_http(network.rpc_url().clone());

    // Fund the wallet with plenty of gas tokens
    provider
        .anvil_set_balance(account, parse_ether("1000").expect(""))
        .await
        .unwrap();

    let transaction_config = TransactionConfig::default();

    // Fund the wallet with plenty of ERC20 tokens
    transfer_tokens(
        genesis_wallet,
        network,
        account,
        Amount::from(9999999999_u64),
        &transaction_config,
    )
    .await
    .unwrap();

    Wallet::new(network.clone(), wallet)
}

#[tokio::test]
async fn test_pay_for_quotes() {
    const CHUNK_PAYMENTS: usize = 600;
    const QUOTES_PER_CHUNK: usize = 5;

    let (_anvil, network, genesis_wallet) = local_testnet().await;
    let wallet = funded_wallet(&network, genesis_wallet).await;

    let mut quote_payments = vec![];

    for _ in 0..CHUNK_PAYMENTS {
        let mut quotes = vec![];

        for _ in 0..QUOTES_PER_CHUNK {
            quotes.push(random_quote_payment());
        }

        quote_payments.push(quotes);
    }

    // Would normally only pay the three highest quotes per chunk, but for testing we pay all five.
    let (tx_hashes, _gas_info) = wallet
        .pay_for_quotes(quote_payments.iter().flatten().cloned())
        .await
        .unwrap();

    let unique_tx_hashes: HashSet<TxHash> = tx_hashes.values().cloned().collect();

    assert_eq!(
        unique_tx_hashes.len(),
        CHUNK_PAYMENTS
            .mul(QUOTES_PER_CHUNK)
            .div_ceil(MAX_TRANSFERS_PER_TRANSACTION)
    );
}

#[tokio::test]
async fn journaled_payment_survives_restart_without_double_payment() {
    use evmlib::wallet::journal::{PaymentRequest, PaymentStatus, SignedPayment};
    let (_anvil, network, genesis_wallet) = local_testnet().await;
    let wallet = funded_wallet(&network, genesis_wallet).await;
    let quote = random_quote_payment();
    let amount = quote.2;
    let request = PaymentRequest::Quotes(vec![quote]);
    let before = wallet.balance_of_tokens().await.unwrap();
    let signed = wallet.prepare_payment(&request).await.unwrap();
    assert_eq!(wallet.balance_of_tokens().await.unwrap(), before);
    assert!(matches!(
        wallet.observe_payment(&signed, &request).await.unwrap(),
        PaymentStatus::Pending
    ));
    let restored: SignedPayment =
        serde_json::from_slice(&serde_json::to_vec(&signed).unwrap()).unwrap();
    let wrong_request = PaymentRequest::Quotes(vec![random_quote_payment()]);
    assert!(
        wallet
            .broadcast_payment(&restored, &wrong_request)
            .await
            .is_err()
    );
    let hash = wallet.broadcast_payment(&restored, &request).await.unwrap();
    let receipt = loop {
        if let PaymentStatus::Confirmed(receipt) =
            wallet.observe_payment(&restored, &request).await.unwrap()
        {
            break receipt;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!(receipt.transaction_hash, hash);
    assert_eq!(receipt.amount, amount);
    assert_eq!(wallet.balance_of_tokens().await.unwrap(), before - amount);
    // RPC may reject a mined duplicate; either outcome must not spend twice.
    let _ = wallet.broadcast_payment(&restored, &request).await;
    assert_eq!(wallet.balance_of_tokens().await.unwrap(), before - amount);
    assert!(matches!(
        wallet.observe_payment(&restored, &request).await.unwrap(),
        PaymentStatus::Confirmed(_)
    ));
}

#[tokio::test]
async fn journaled_merkle_payment_restores_the_confirmed_winner() {
    use evmlib::merkle_batch_payment::{CandidateNode, PoolCommitment};
    use evmlib::wallet::journal::{PaymentRequest, PaymentStatus};
    let (_anvil, network, genesis_wallet) = local_testnet().await;
    let wallet = funded_wallet(&network, genesis_wallet).await;
    let pools = (1..=2)
        .map(|n| PoolCommitment {
            pool_hash: [n; 32],
            candidates: std::array::from_fn(|i| CandidateNode {
                rewards_address: [(i + 1) as u8; 20].into(),
                price: Amount::from(100),
            }),
        })
        .collect::<Vec<_>>();
    let request = PaymentRequest::Merkle {
        depth: 2,
        pools: pools.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let before = wallet.balance_of_tokens().await.unwrap();
    let signed = wallet.prepare_payment(&request).await.unwrap();
    wallet.broadcast_payment(&signed, &request).await.unwrap();
    let receipt = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let PaymentStatus::Confirmed(receipt) =
                wallet.observe_payment(&signed, &request).await.unwrap()
            {
                break receipt;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        pools
            .iter()
            .any(|p| Some(p.pool_hash) == receipt.winner_pool)
    );
    assert_eq!(
        wallet.balance_of_tokens().await.unwrap(),
        before - receipt.amount
    );
    let PaymentStatus::Confirmed(recovered) =
        wallet.observe_payment(&signed, &request).await.unwrap()
    else {
        panic!("confirmed receipt missing")
    };
    assert_eq!(recovered.winner_pool, receipt.winner_pool);
    assert_eq!(recovered.transaction_hash, receipt.transaction_hash);
}
