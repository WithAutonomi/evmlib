#![allow(clippy::expect_used)]

mod common;

use crate::common::merkle::deterministic_tree;
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
use evmlib::common::{Amount, U256};
use evmlib::contract::network_token::NetworkToken;
use evmlib::contract::payment_vault::MAX_TRANSFERS_PER_TRANSACTION;
use evmlib::contract::payment_vault::handler::PaymentVaultHandler;
use evmlib::merkle_batch_payment::{
    CANDIDATES_PER_POOL, CandidateNode, PoolCommitment, expected_reward_pools,
};
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

fn make_pool_commitment(price: u64) -> PoolCommitment {
    let candidates: [CandidateNode; CANDIDATES_PER_POOL] = std::array::from_fn(|i| CandidateNode {
        rewards_address: alloy::primitives::Address::new([(i + 1) as u8; 20]),
        price: Amount::from(price),
    });
    PoolCommitment {
        pool_hash: {
            let mut hash = [0u8; 32];
            hash[0] = rand::random();
            hash[1] = rand::random();
            hash
        },
        candidates,
    }
}

#[tokio::test]
async fn test_pay_for_merkle_tree_on_local() {
    let (_anvil, network_token, mut payment_vault) = setup().await;

    let transaction_config = TransactionConfig::default();

    // Use depth=2 → expected pools = 2^ceil(2/2) = 2
    let depth: u8 = 2;
    let num_pools = expected_reward_pools(depth);
    assert_eq!(num_pools, 2);

    let pool_commitments: Vec<PoolCommitment> =
        (0..num_pools).map(|_| make_pool_commitment(100)).collect();

    let merkle_payment_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Approve the payment vault to spend tokens
    let _ = network_token
        .approve(
            *payment_vault.contract.address(),
            U256::MAX,
            &transaction_config,
        )
        .await
        .unwrap();

    // Use the same provider as the network token (funded account)
    payment_vault.set_provider(network_token.contract.provider().clone());

    let (winner_pool_hash, total_amount, _gas_info) = payment_vault
        .pay_for_merkle_tree(
            depth,
            pool_commitments.clone(),
            merkle_payment_timestamp,
            &transaction_config,
        )
        .await
        .expect("pay_for_merkle_tree should succeed");

    // Verify winner pool hash is one of the submitted pools
    assert!(
        pool_commitments
            .iter()
            .any(|pc| pc.pool_hash == winner_pool_hash),
        "Winner pool hash should match one of the submitted pools"
    );

    // Verify total amount: median(100) * 2^2 = 400
    assert_eq!(total_amount, Amount::from(400u64));

    // Query on-chain payment info and verify
    let completed = payment_vault
        .get_completed_merkle_payment(winner_pool_hash)
        .await
        .expect("get_completed_merkle_payment should succeed");

    assert_eq!(completed.depth, depth);
    assert_eq!(completed.merklePaymentTimestamp, merkle_payment_timestamp);
    assert_eq!(
        completed.paidNodeAddresses.len(),
        depth as usize,
        "Should have paid exactly {depth} nodes"
    );

    // Each node should receive totalAmount / depth
    let expected_per_node = total_amount / Amount::from(depth as u64);
    for paid_node in &completed.paidNodeAddresses {
        assert_eq!(paid_node.amount, expected_per_node);
    }
}

#[tokio::test]
async fn test_pay_for_merkle_tree_depth_4() {
    let (_anvil, network_token, mut payment_vault) = setup().await;

    let transaction_config = TransactionConfig::default();

    // Use depth=4 → expected pools = 2^ceil(4/2) = 4
    let depth: u8 = 4;
    let num_pools = expected_reward_pools(depth);
    assert_eq!(num_pools, 4);

    let pool_commitments: Vec<PoolCommitment> =
        (0..num_pools).map(|_| make_pool_commitment(50)).collect();

    let merkle_payment_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let _ = network_token
        .approve(
            *payment_vault.contract.address(),
            U256::MAX,
            &transaction_config,
        )
        .await
        .unwrap();

    payment_vault.set_provider(network_token.contract.provider().clone());

    let (winner_pool_hash, total_amount, _gas_info) = payment_vault
        .pay_for_merkle_tree(
            depth,
            pool_commitments,
            merkle_payment_timestamp,
            &transaction_config,
        )
        .await
        .expect("pay_for_merkle_tree depth=4 should succeed");

    // median(50) * 2^4 = 800
    assert_eq!(total_amount, Amount::from(800u64));

    let completed = payment_vault
        .get_completed_merkle_payment(winner_pool_hash)
        .await
        .expect("get_completed_merkle_payment should succeed");

    assert_eq!(completed.depth, depth);
    assert_eq!(completed.paidNodeAddresses.len(), 4);

    // Verify all paid node indices are unique and within bounds
    let paid_indices: Vec<u8> = completed
        .paidNodeAddresses
        .iter()
        .map(|n| n.poolIndex)
        .collect();
    let unique_indices: std::collections::HashSet<u8> = paid_indices.iter().copied().collect();
    assert_eq!(
        unique_indices.len(),
        depth as usize,
        "All paid node indices should be unique"
    );
    for idx in &paid_indices {
        assert!(
            (*idx as usize) < CANDIDATES_PER_POOL,
            "Paid node index {idx} should be < {CANDIDATES_PER_POOL}"
        );
    }
}

#[tokio::test]
async fn test_pay_for_merkle_tree_duplicate_rejected() {
    let (_anvil, network_token, mut payment_vault) = setup().await;

    let transaction_config = TransactionConfig::default();

    let depth: u8 = 2;
    let num_pools = expected_reward_pools(depth);
    let pool_commitments: Vec<PoolCommitment> =
        (0..num_pools).map(|_| make_pool_commitment(100)).collect();

    let merkle_payment_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let _ = network_token
        .approve(
            *payment_vault.contract.address(),
            U256::MAX,
            &transaction_config,
        )
        .await
        .unwrap();

    payment_vault.set_provider(network_token.contract.provider().clone());

    // With 2 pools, each payment randomly picks a winner pool via on-chain entropy
    // (block.prevrandao, block.timestamp). By pigeonhole, 3 payments guarantee at least
    // one duplicate winner pool hash, which the contract rejects.
    let max_attempts = num_pools + 1;
    let mut saw_duplicate_rejection = false;

    for i in 0..max_attempts {
        let result = payment_vault
            .pay_for_merkle_tree(
                depth,
                pool_commitments.clone(),
                merkle_payment_timestamp,
                &transaction_config,
            )
            .await;

        if result.is_err() {
            saw_duplicate_rejection = true;
            break;
        }
        assert!(
            i < num_pools,
            "Payment {i} succeeded but all {num_pools} pool slots should be filled"
        );
    }

    assert!(
        saw_duplicate_rejection,
        "Expected at least one duplicate rejection in {max_attempts} attempts"
    );
}

#[tokio::test]
async fn test_pay_for_merkle_trees_on_local() {
    let (_anvil, network_token, mut payment_vault) = setup().await;

    let transaction_config = TransactionConfig::default();

    let merkle_payment_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Three trees with distinct depths and prices, paid in one transaction
    let trees = vec![
        deterministic_tree(2, 100, 100, merkle_payment_timestamp),
        deterministic_tree(4, 50, 200, merkle_payment_timestamp),
        deterministic_tree(2, 200, 300, merkle_payment_timestamp),
    ];

    let _ = network_token
        .approve(
            *payment_vault.contract.address(),
            U256::MAX,
            &transaction_config,
        )
        .await
        .unwrap();

    payment_vault.set_provider(network_token.contract.provider().clone());

    let (payments, _gas_info) = payment_vault
        .pay_for_merkle_trees(trees.clone(), &transaction_config)
        .await
        .expect("pay_for_merkle_trees should succeed");

    assert_eq!(payments.len(), 3, "one (winner, amount) per tree");

    for (i, (winner_pool_hash, amount)) in payments.iter().enumerate() {
        let tree = &trees[i];

        assert!(
            tree.pool_commitments
                .iter()
                .any(|pc| pc.pool_hash == *winner_pool_hash),
            "winner of tree {i} should come from that tree's pools"
        );

        // Uniform prices per tree: cost = price * 2^depth
        let price = tree.pool_commitments[0].candidates[0].price;
        assert_eq!(
            *amount,
            price * Amount::from(1u64 << tree.depth),
            "tree {i} amount"
        );

        let completed = payment_vault
            .get_completed_merkle_payment(*winner_pool_hash)
            .await
            .expect("payment should be stored on-chain");
        assert_eq!(completed.depth, tree.depth);
        assert_eq!(completed.merklePaymentTimestamp, merkle_payment_timestamp);
        assert_eq!(completed.paidNodeAddresses.len(), tree.depth as usize);
    }
}

#[tokio::test]
async fn test_pay_for_merkle_trees_duplicate_rejected() {
    let (_anvil, network_token, mut payment_vault) = setup().await;

    let transaction_config = TransactionConfig::default();

    let merkle_payment_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Every pool of both trees shares one hash, so both trees resolve to the
    // same winner regardless of on-chain entropy — the second tree must
    // revert the whole transaction.
    let mut tree_a = deterministic_tree(2, 100, 400, merkle_payment_timestamp);
    let dup_hash = tree_a.pool_commitments[0].pool_hash;
    for pc in &mut tree_a.pool_commitments {
        pc.pool_hash = dup_hash;
    }
    let tree_b = tree_a.clone();

    let _ = network_token
        .approve(
            *payment_vault.contract.address(),
            U256::MAX,
            &transaction_config,
        )
        .await
        .unwrap();

    payment_vault.set_provider(network_token.contract.provider().clone());

    let err = payment_vault
        .pay_for_merkle_trees(vec![tree_a, tree_b], &transaction_config)
        .await
        .expect_err("duplicate winner within one batch should fail");

    match err {
        evmlib::contract::payment_vault::error::Error::PaymentAlreadyExists(hash) => {
            assert_eq!(hash, hex::encode(dup_hash));
        }
        other => panic!("expected PaymentAlreadyExists, got {other:?}"),
    }

    // All-or-nothing: the first tree's payment must not persist either
    assert!(
        payment_vault
            .get_completed_merkle_payment(dup_hash)
            .await
            .is_err(),
        "no payment should be stored after the revert"
    );
}

#[cfg(feature = "external-signer")]
#[tokio::test]
async fn test_pay_for_merkle_trees_external_signer_calldata() {
    use alloy::network::TransactionBuilder;
    use alloy::providers::Provider;
    use alloy::rpc::types::TransactionRequest;
    use evmlib::Network;

    let (anvil, network_token, mut payment_vault) = setup().await;

    let transaction_config = TransactionConfig::default();

    let network = Network::new_custom(
        &anvil.endpoint(),
        &network_token.contract.address().to_string(),
        &payment_vault.contract.address().to_string(),
    );

    let merkle_payment_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let trees = vec![
        deterministic_tree(2, 100, 500, merkle_payment_timestamp),
        deterministic_tree(2, 150, 600, merkle_payment_timestamp),
    ];

    let calldata_return =
        evmlib::external_signer::pay_for_merkle_trees_calldata(&network, trees.clone())
            .expect("calldata generation should succeed");

    assert_eq!(calldata_return.tree_count, 2);
    assert_eq!(calldata_return.to, *payment_vault.contract.address());
    assert_eq!(
        calldata_return.approve_spender,
        *payment_vault.contract.address()
    );

    // Approve, then submit the raw calldata from the funded genesis account —
    // exactly what an external wallet does with this return value.
    let _ = network_token
        .approve(
            *payment_vault.contract.address(),
            U256::MAX,
            &transaction_config,
        )
        .await
        .unwrap();

    payment_vault.set_provider(network_token.contract.provider().clone());

    let provider = network_token.contract.provider();
    let tx = TransactionRequest::default()
        .with_to(calldata_return.to)
        .with_input(calldata_return.calldata.clone());

    let receipt = provider
        .send_transaction(tx)
        .await
        .expect("raw calldata transaction should send")
        .get_receipt()
        .await
        .expect("receipt should be available");
    assert!(receipt.status(), "batched payment tx should succeed");

    // Exactly one pool per tree must be stored on-chain, with that tree's depth
    for (i, tree) in trees.iter().enumerate() {
        let mut stored = 0;
        for pc in &tree.pool_commitments {
            if let Ok(info) = payment_vault
                .get_completed_merkle_payment(pc.pool_hash)
                .await
            {
                assert_eq!(info.depth, tree.depth, "tree {i} stored depth");
                stored += 1;
            }
        }
        assert_eq!(stored, 1, "tree {i} should have exactly one paid pool");
    }
}
