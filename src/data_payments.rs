// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Payment proof types for the Saorsa network.
//!
//! Defines [`EncodedPeerId`], [`PaymentQuote`], and [`ProofOfPayment`] used
//! in the EVM payment verification flow.

use crate::common::{Address as RewardsAddress, Amount, QuoteHash};
use crate::cryptography::hash as crypto_hash;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::SystemTime;
use xor_name::XorName;

/// A peer's identity encoded as raw 32 bytes (BLAKE3 hash of ML-DSA-65 public key).
///
/// This is the native Saorsa peer identity — no libp2p multihash encoding.
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct EncodedPeerId(#[serde(with = "serde_byte_array")] [u8; 32]);

impl EncodedPeerId {
    /// Create from raw 32-byte peer ID.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for EncodedPeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = hex::encode(self.0);
        write!(f, "EncodedPeerId({hex})")
    }
}

impl From<[u8; 32]> for EncodedPeerId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The proof of payment for a data payment
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ProofOfPayment {
    pub peer_quotes: Vec<(EncodedPeerId, PaymentQuote)>,
}

impl ProofOfPayment {
    /// Returns a short digest of the proof of payment to use for on-chain verification.
    pub fn digest(&self) -> Vec<(QuoteHash, Amount, RewardsAddress)> {
        self.peer_quotes
            .clone()
            .into_iter()
            .map(|(_, quote)| (quote.hash(), quote.price, quote.rewards_address))
            .collect()
    }
}

/// A payment quote to store data given by a node to a client.
///
/// The PaymentQuote is a contract between the node and itself to make sure
/// the clients aren't mispaying. It is NOT a contract between the client
/// and the node.
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PaymentQuote {
    /// The content paid for
    pub content: XorName,
    /// The local node time when the quote was created
    pub timestamp: SystemTime,
    /// The node-calculated price for storing this content
    pub price: Amount,
    /// The node's wallet address
    pub rewards_address: RewardsAddress,
    /// The node's public key in bytes (ML-DSA-65)
    pub pub_key: Vec<u8>,
    /// The node's signature for the quote (ML-DSA-65)
    pub signature: Vec<u8>,
}

impl fmt::Debug for PaymentQuote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymentQuote")
            .field("content", &self.content)
            .field("timestamp", &self.timestamp)
            .field("price", &self.price)
            .field("rewards_address", &self.rewards_address)
            .finish_non_exhaustive()
    }
}

impl PaymentQuote {
    /// Compute the hash of this quote.
    pub fn hash(&self) -> QuoteHash {
        let mut bytes = self.bytes_for_sig();
        bytes.extend_from_slice(self.pub_key.as_slice());
        bytes.extend_from_slice(self.signature.as_slice());
        crypto_hash(bytes)
    }

    /// Returns the bytes to be signed from the given parameters.
    pub fn bytes_for_signing(
        xorname: XorName,
        timestamp: SystemTime,
        price: &Amount,
        rewards_address: &RewardsAddress,
    ) -> Vec<u8> {
        let mut bytes = xorname.to_vec();
        let secs = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        bytes.extend_from_slice(&secs.to_le_bytes());
        bytes.extend_from_slice(&price.to_le_bytes::<32>());
        bytes.extend_from_slice(rewards_address.as_slice());
        bytes
    }

    /// Returns the bytes to be signed from self.
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        Self::bytes_for_signing(
            self.content,
            self.timestamp,
            &self.price,
            &self.rewards_address,
        )
    }
}

/// Serde helper for fixed-size byte arrays as raw bytes.
mod serde_byte_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&bytes[..], serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            let len = v.len();
            serde::de::Error::custom(format!("Expected 32 bytes, got {len}"))
        })
    }
}
