// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// Allow expect usage in this crate as it's used for compile-time constants
#![allow(clippy::expect_used)]
// Allow enum variant names that end with Error as they come from external derives
#![allow(clippy::enum_variant_names)]

use crate::common::{Address, Amount};
use crate::merkle_batch_payment::PoolCommitment;
use crate::utils::get_evm_network;
use alloy::primitives::address;
use alloy::transports::http::reqwest;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::str::FromStr;
use std::sync::LazyLock;

#[macro_use]
extern crate tracing;

pub mod common;
pub mod contract;
pub mod cryptography;
pub mod data_payments;
#[cfg(feature = "external-signer")]
pub mod external_signer;
pub mod merkle_batch_payment;
pub mod merkle_payments;
pub mod quoting_metrics;
mod retry;
pub mod testnet;
pub mod transaction_config;
pub mod utils;
pub mod wallet;

// Re-export GasInfo for use by other crates
pub use retry::GasInfo;

// Re-export payment types for convenience (replaces ant-evm)
pub use common::Address as RewardsAddress;
pub use data_payments::{EncodedPeerId, PaymentQuote, ProofOfPayment};

/// Timeout for transactions
const TX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(24); // Should differ per chain

static PUBLIC_ARBITRUM_ONE_HTTP_RPC_URL: LazyLock<reqwest::Url> = LazyLock::new(|| {
    "https://arb1.arbitrum.io/rpc"
        .parse()
        .expect("Invalid RPC URL")
});

static PUBLIC_ARBITRUM_SEPOLIA_HTTP_RPC_URL: LazyLock<reqwest::Url> = LazyLock::new(|| {
    "https://sepolia-rollup.arbitrum.io/rpc"
        .parse()
        .expect("Invalid RPC URL")
});

const ARBITRUM_ONE_PAYMENT_TOKEN_ADDRESS: Address =
    address!("a78d8321B20c4Ef90eCd72f2588AA985A4BDb684");

const ARBITRUM_SEPOLIA_TEST_PAYMENT_TOKEN_ADDRESS: Address =
    address!("4bc1aCE0E66170375462cB4E6Af42Ad4D5EC689C");

/// Unified payment vault address (handles both single-node and merkle payments).
const ARBITRUM_ONE_PAYMENT_VAULT_ADDRESS: Address =
    address!("B1b5219f8Aaa18037A2506626Dd0406a46f70BcC");

/// Unified payment vault address on Arbitrum Sepolia (proxy contract).
const ARBITRUM_SEPOLIA_TEST_PAYMENT_VAULT_ADDRESS: Address =
    address!("d742E8CFEf27A9a884F3EFfA239Ee2F39c276522");

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomNetwork {
    #[serde_as(as = "DisplayFromStr")]
    pub rpc_url_http: reqwest::Url,
    pub payment_token_address: Address,
    /// Unified payment vault handling both single-node and merkle payments.
    pub payment_vault_address: Address,
}

impl CustomNetwork {
    pub fn new(rpc_url: &str, payment_token_addr: &str, payment_vault_addr: &str) -> Self {
        Self {
            rpc_url_http: reqwest::Url::parse(rpc_url).expect("Invalid RPC URL"),
            payment_token_address: Address::from_str(payment_token_addr)
                .expect("Invalid payment token address"),
            payment_vault_address: Address::from_str(payment_vault_addr)
                .expect("Invalid payment vault address"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum Network {
    #[default]
    ArbitrumOne,
    ArbitrumSepoliaTest,
    Custom(CustomNetwork),
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::ArbitrumOne => write!(f, "evm-arbitrum-one"),
            Network::ArbitrumSepoliaTest => write!(f, "evm-arbitrum-sepolia-test"),
            Network::Custom(_) => write!(f, "evm-custom"),
        }
    }
}

impl std::str::FromStr for Network {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "evm-arbitrum-one" => Ok(Network::ArbitrumOne),
            "evm-arbitrum-sepolia-test" => Ok(Network::ArbitrumSepoliaTest),
            _ => Err(()),
        }
    }
}

impl Network {
    pub fn new(local: bool) -> Result<Self, utils::Error> {
        get_evm_network(local, None).inspect_err(|err| {
            warn!("Failed to select EVM network from ENV: {err}");
        })
    }

    pub fn new_custom(rpc_url: &str, payment_token_addr: &str, payment_vault_addr: &str) -> Self {
        Self::Custom(CustomNetwork::new(
            rpc_url,
            payment_token_addr,
            payment_vault_addr,
        ))
    }

    pub fn identifier(&self) -> &str {
        match self {
            Network::ArbitrumOne => "arbitrum-one",
            Network::ArbitrumSepoliaTest => "arbitrum-sepolia-test",
            Network::Custom(_) => "custom",
        }
    }

    pub fn rpc_url(&self) -> &reqwest::Url {
        match self {
            Network::ArbitrumOne => &PUBLIC_ARBITRUM_ONE_HTTP_RPC_URL,
            Network::ArbitrumSepoliaTest => &PUBLIC_ARBITRUM_SEPOLIA_HTTP_RPC_URL,
            Network::Custom(custom) => &custom.rpc_url_http,
        }
    }

    pub fn payment_token_address(&self) -> &Address {
        match self {
            Network::ArbitrumOne => &ARBITRUM_ONE_PAYMENT_TOKEN_ADDRESS,
            Network::ArbitrumSepoliaTest => &ARBITRUM_SEPOLIA_TEST_PAYMENT_TOKEN_ADDRESS,
            Network::Custom(custom) => &custom.payment_token_address,
        }
    }

    /// Unified payment vault address (handles both single-node and merkle payments).
    pub fn payment_vault_address(&self) -> &Address {
        match self {
            Network::ArbitrumOne => &ARBITRUM_ONE_PAYMENT_VAULT_ADDRESS,
            Network::ArbitrumSepoliaTest => &ARBITRUM_SEPOLIA_TEST_PAYMENT_VAULT_ADDRESS,
            Network::Custom(custom) => &custom.payment_vault_address,
        }
    }

    /// Estimate the cost of a Merkle tree batch locally.
    ///
    /// Computes a conservative upper-bound by summing the top `depth` candidate
    /// prices from each pool and returning the maximum. No on-chain call is made.
    ///
    /// # Arguments
    /// * `depth` - The Merkle tree depth
    /// * `pool_commitments` - Vector of pool commitments with prices (one per reward pool)
    ///
    /// # Returns
    /// * Estimated total cost in AttoTokens
    pub fn estimate_merkle_payment_cost(
        &self,
        depth: u8,
        pool_commitments: &[PoolCommitment],
    ) -> Amount {
        if pool_commitments.is_empty() {
            return Amount::ZERO;
        }

        let depth_usize = usize::from(depth);
        pool_commitments
            .iter()
            .map(|pool| {
                let mut prices: Vec<Amount> = pool.candidates.iter().map(|c| c.price).collect();
                prices.sort_unstable_by(|a, b| b.cmp(a)); // descending
                prices
                    .iter()
                    .take(depth_usize)
                    .fold(Amount::ZERO, |acc, p| acc + p)
            })
            .max()
            .unwrap_or(Amount::ZERO)
    }
}
