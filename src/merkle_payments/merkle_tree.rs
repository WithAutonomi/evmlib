// Copyright 2025 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.

use ant_merkle::Hasher;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use xor_name::XorName;

use super::merkle_payment::sha3_256;
use crate::merkle_batch_payment::expected_reward_pools;

/// Maximum tree depth
pub use crate::merkle_batch_payment::MAX_MERKLE_DEPTH;

/// Minimum number of leaves (addresses) for a Merkle tree
pub const MIN_LEAVES: usize = 2;

/// Maximum number of leaves (2^MAX_MERKLE_DEPTH)
pub const MAX_LEAVES: usize = 1 << MAX_MERKLE_DEPTH;

/// Maximum age of a Merkle payment (one week in seconds)
pub const MERKLE_PAYMENT_EXPIRATION: u64 = 7 * 24 * 60 * 60;

/// Errors that can occur when working with Merkle trees
#[derive(Debug, Error)]
pub enum MerkleTreeError {
    #[error("Too few leaves: got {got}, minimum is {MIN_LEAVES}")]
    TooFewLeaves { got: usize },
    #[error("Too many leaves: got {got}, maximum is {MAX_LEAVES}")]
    TooManyLeaves { got: usize },
    #[error("Invalid leaf index: {index} (tree has {leaf_count} leaves)")]
    InvalidLeafIndex { index: usize, leaf_count: usize },
    #[error("Invalid midpoint index: {index} (tree has {midpoint_count} midpoints)")]
    InvalidMidpointIndex { index: usize, midpoint_count: usize },
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, MerkleTreeError>;

/// A Merkle tree built from XorNames (content addresses).
pub struct MerkleTree {
    inner: ant_merkle::MerkleTree<Sha3Hasher>,
    leaf_count: usize,
    depth: u8,
    root: XorName,
    salts: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Create a new Merkle tree from XorNames.
    pub fn from_xornames(leaves: Vec<XorName>) -> Result<Self> {
        let leaf_count = leaves.len();

        if leaf_count < MIN_LEAVES {
            return Err(MerkleTreeError::TooFewLeaves { got: leaf_count });
        }
        if leaf_count > MAX_LEAVES {
            return Err(MerkleTreeError::TooManyLeaves { got: leaf_count });
        }

        let mut rng = rand::thread_rng();
        let salts: Vec<[u8; 32]> = (0..leaf_count)
            .map(|_| {
                let mut salt = [0u8; 32];
                rand::Rng::fill(&mut rng, &mut salt);
                salt
            })
            .collect();

        let depth = tree_depth(leaf_count);
        let padded_size = 1 << depth;

        let mut salted_leaves: Vec<[u8; 32]> = leaves
            .iter()
            .zip(&salts)
            .map(|(address, salt)| {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(address.as_ref());
                data.extend_from_slice(salt);
                Sha3Hasher::hash(&data)
            })
            .collect();

        if leaf_count < padded_size {
            for _ in leaf_count..padded_size {
                let mut dummy = [0u8; 32];
                rand::Rng::fill(&mut rng, &mut dummy);
                salted_leaves.push(dummy);
            }
        }

        let inner = ant_merkle::MerkleTree::<Sha3Hasher>::from_leaves(&salted_leaves);

        let root = inner.root().ok_or(MerkleTreeError::Internal(
            "Tree must have root after construction".to_string(),
        ))?;

        Ok(Self {
            inner,
            root: XorName(root),
            leaf_count,
            depth,
            salts,
        })
    }

    /// Get the root hash of the tree.
    pub fn root(&self) -> XorName {
        self.root
    }

    /// Get the depth of the tree.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Get the original leaf count (before padding).
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Get midpoint nodes at depth/2.
    fn midpoints(&self) -> Result<Vec<MerkleMidpoint>> {
        let level = midpoint_level(self.depth);

        let nodes = self
            .inner
            .get_nodes_at_level(level)
            .ok_or(MerkleTreeError::Internal(
                "Midpoint level must exist".to_string(),
            ))?;

        let midpoints: Vec<MerkleMidpoint> = nodes
            .into_iter()
            .map(|(index, hash)| MerkleMidpoint {
                hash: XorName(hash),
                index,
            })
            .collect();

        Ok(midpoints)
    }

    /// Get reward candidates for batch payment.
    pub fn reward_candidates(&self, merkle_payment_timestamp: u64) -> Result<Vec<MidpointProof>> {
        let midpoints = self.midpoints()?;

        midpoints
            .into_iter()
            .map(|midpoint| {
                let branch = self.generate_midpoint_proof(midpoint.index, midpoint.hash)?;
                Ok(MidpointProof {
                    branch,
                    merkle_payment_timestamp,
                })
            })
            .collect()
    }

    /// Generate a proof that an address belongs to this tree.
    pub fn generate_address_proof(
        &self,
        address_index: usize,
        address_hash: XorName,
    ) -> Result<MerkleBranch> {
        if address_index >= self.leaf_count {
            return Err(MerkleTreeError::InvalidLeafIndex {
                index: address_index,
                leaf_count: self.leaf_count,
            });
        }

        let indices = vec![address_index];
        let proof = self.inner.proof(&indices);
        let padded_size = 1 << self.depth;
        let root = self.root();
        let salt = self.salts[address_index];

        Ok(MerkleBranch::from_rs_merkle_proof(
            proof,
            address_index,
            padded_size,
            address_hash,
            root,
            Some(salt),
        ))
    }

    /// Generate a proof that a midpoint exists at the midpoint level.
    fn generate_midpoint_proof(
        &self,
        midpoint_index: usize,
        midpoint_hash: XorName,
    ) -> Result<MerkleBranch> {
        let level = midpoint_level(self.depth);
        let midpoint_count = expected_reward_pools(self.depth);

        if midpoint_index >= midpoint_count {
            return Err(MerkleTreeError::InvalidMidpointIndex {
                index: midpoint_index,
                midpoint_count,
            });
        }

        let proof = self
            .inner
            .proof_from_node(level, midpoint_index)
            .ok_or_else(|| {
                MerkleTreeError::Internal("Failed to generate midpoint proof".to_string())
            })?;

        let effective_leaf_count = midpoint_count;
        let root = self.root();

        Ok(MerkleBranch::from_rs_merkle_proof(
            proof,
            midpoint_index,
            effective_leaf_count,
            midpoint_hash,
            root,
            None,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct MerkleMidpoint {
    hash: XorName,
    index: usize,
}

/// A reward candidate derived from a midpoint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MidpointProof {
    /// Proof that the midpoint belongs to the Merkle tree
    pub branch: MerkleBranch,
    /// Merkle payment timestamp provided by client
    pub merkle_payment_timestamp: u64,
}

impl MidpointProof {
    /// Get the Merkle root from the proof's branch.
    pub fn root(&self) -> &XorName {
        self.branch.root()
    }

    /// Get the candidate address for this pool.
    pub fn address(&self) -> XorName {
        let mut data = Vec::with_capacity(32 + 32 + 8);
        data.extend_from_slice(self.branch.leaf_hash().as_ref());
        data.extend_from_slice(self.branch.root().as_ref());
        data.extend_from_slice(&self.merkle_payment_timestamp.to_le_bytes());
        XorName::from_content(&data)
    }

    /// Compute deterministic hash for storage/verification.
    pub fn hash(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        for proof_hash in &self.branch.proof_hashes {
            bytes.extend_from_slice(proof_hash);
        }
        bytes.extend_from_slice(&(self.branch.leaf_index as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.branch.total_leaves_count as u64).to_le_bytes());
        bytes.extend_from_slice(self.branch.unsalted_leaf_hash.as_ref());
        bytes.extend_from_slice(self.branch.root.as_ref());
        if let Some(salt) = &self.branch.salt {
            bytes.push(1);
            bytes.extend_from_slice(salt);
        } else {
            bytes.push(0);
        }
        bytes.extend_from_slice(&self.merkle_payment_timestamp.to_le_bytes());
        sha3_256(&bytes)
    }
}

/// A Merkle branch (proof) from a leaf or midpoint to the root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MerkleBranch {
    pub(crate) proof_hashes: Vec<[u8; 32]>,
    pub(crate) leaf_index: usize,
    pub(crate) total_leaves_count: usize,
    pub(crate) unsalted_leaf_hash: XorName,
    pub(crate) root: XorName,
    pub(crate) salt: Option<[u8; 32]>,
}

impl MerkleBranch {
    fn from_rs_merkle_proof(
        proof: ant_merkle::MerkleProof<Sha3Hasher>,
        leaf_index: usize,
        total_leaves_count: usize,
        unsalted_leaf_hash: XorName,
        root: XorName,
        salt: Option<[u8; 32]>,
    ) -> Self {
        let proof_hashes = proof.proof_hashes().to_vec();
        Self {
            proof_hashes,
            leaf_index,
            total_leaves_count,
            unsalted_leaf_hash,
            root,
            salt,
        }
    }

    /// Get the unsalted leaf hash being proven.
    pub fn leaf_hash(&self) -> &XorName {
        &self.unsalted_leaf_hash
    }

    /// Get the expected Merkle root.
    pub fn root(&self) -> &XorName {
        &self.root
    }

    /// Verify this proof.
    pub fn verify(&self) -> bool {
        let hash = if let Some(salt) = &self.salt {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(self.unsalted_leaf_hash.as_ref());
            data.extend_from_slice(salt);
            Sha3Hasher::hash(&data)
        } else {
            let leaf_bytes = self.unsalted_leaf_hash.as_ref();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(leaf_bytes);
            hash
        };

        let root_bytes = self.root.as_ref();
        let mut expected_root = [0u8; 32];
        expected_root.copy_from_slice(root_bytes);

        let proof = ant_merkle::MerkleProof::<Sha3Hasher>::new(self.proof_hashes.clone());
        proof.verify(
            expected_root,
            &[self.leaf_index],
            &[hash],
            self.total_leaves_count,
        )
    }

    /// Get the depth (number of hashing steps) of this proof.
    pub fn depth(&self) -> usize {
        self.proof_hashes.len()
    }
}

/// Calculate tree depth from leaf count.
pub fn tree_depth(leaf_count: usize) -> u8 {
    if leaf_count <= 1 {
        return 0;
    }
    let mut depth = 0;
    let mut n = leaf_count - 1;
    while n > 0 {
        depth += 1;
        n >>= 1;
    }
    depth
}

/// Calculate the proof depth from midpoint to root.
pub fn midpoint_proof_depth(depth: u8) -> u8 {
    depth.div_ceil(2)
}

/// Level at which reward-pool midpoints sit, in `ant_merkle`'s level numbering.
///
/// `ant_merkle::MerkleTree::get_nodes_at_level(L)` numbers levels from the
/// leaves up — `L = 0` is the leaf layer, `L = depth` is the root — so a
/// padded tree of `2^depth` leaves contains `2^(depth - L)` nodes at level `L`.
///
/// We need exactly `expected_reward_pools(depth) = 2^ceil(depth/2)` midpoints
/// to match the on-chain `MerklePaymentLib.expectedRewardPools`. Picking
/// `L = floor(depth/2)` yields `2^(depth - floor(depth/2)) = 2^ceil(depth/2)`
/// nodes, matching the contract for both even and odd depths.
///
/// Do NOT change this to `depth.div_ceil(2)` to "match" `expected_reward_pools`:
/// because the level is counted from the leaves, `ceil(depth/2)` halves the
/// pool count on odd depths and triggers a `WrongPoolCount` revert at the
/// payment vault.
fn midpoint_level(depth: u8) -> usize {
    (depth / 2) as usize
}

/// Errors for Merkle proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BadMerkleProof {
    #[error("Address branch proof failed Merkle verification")]
    InvalidAddressBranchProof,
    #[error("Winner/intersection branch proof failed Merkle verification")]
    InvalidWinnerBranchProof,
    #[error("Address proof depth mismatch: expected {expected}, got {got}")]
    AddressProofDepthMismatch { expected: usize, got: usize },
    #[error("Winner proof depth mismatch: expected {expected}, got {got}")]
    WinnerProofDepthMismatch { expected: usize, got: usize },
    #[error(
        "Address branch root doesn't match smart contract root: smart_contract={smart_contract_root}, branch={branch_root}"
    )]
    AddressBranchRootMismatch {
        smart_contract_root: XorName,
        branch_root: XorName,
    },
    #[error(
        "Winner branch root doesn't match smart contract root: smart_contract={smart_contract_root}, branch={branch_root}"
    )]
    WinnerBranchRootMismatch {
        smart_contract_root: XorName,
        branch_root: XorName,
    },
    #[error(
        "Payment timestamp {payment_timestamp} is in the future (current time: {current_time})"
    )]
    TimestampInFuture {
        payment_timestamp: u64,
        current_time: u64,
    },
    #[error(
        "Payment expired: timestamp {payment_timestamp} is {age_seconds}s old (max: {MERKLE_PAYMENT_EXPIRATION}s)"
    )]
    PaymentExpired {
        payment_timestamp: u64,
        current_time: u64,
        age_seconds: u64,
    },
    #[error("Failed to get current system time: {0}")]
    SystemTimeError(String),
    #[error(
        "Winner pool timestamp {pool_timestamp} doesn't match smart contract timestamp {contract_timestamp}"
    )]
    TimestampMismatch {
        pool_timestamp: u64,
        contract_timestamp: u64,
    },
    #[error("Address hash not matching branch leaf: leaf={leaf}, address={address}")]
    AddressHashNotBranchLeaf { leaf: XorName, address: XorName },
}

fn validate_payment_timestamp(
    payment_timestamp: u64,
    pool_timestamp: u64,
) -> std::result::Result<(), BadMerkleProof> {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| BadMerkleProof::SystemTimeError(e.to_string()))?
        .as_secs();

    if payment_timestamp > current_time {
        return Err(BadMerkleProof::TimestampInFuture {
            payment_timestamp,
            current_time,
        });
    }

    let age = current_time - payment_timestamp;
    if age > MERKLE_PAYMENT_EXPIRATION {
        return Err(BadMerkleProof::PaymentExpired {
            payment_timestamp,
            current_time,
            age_seconds: age,
        });
    }

    if pool_timestamp != payment_timestamp {
        return Err(BadMerkleProof::TimestampMismatch {
            pool_timestamp,
            contract_timestamp: payment_timestamp,
        });
    }

    Ok(())
}

/// Verify a Merkle proof against smart contract payment data.
pub fn verify_merkle_proof(
    address_hash: &XorName,
    address_branch: &MerkleBranch,
    winner_pool_midpoint_proof: &MidpointProof,
    smart_contract_depth: u8,
    smart_contract_root: &XorName,
    smart_contract_timestamp: u64,
) -> std::result::Result<(), BadMerkleProof> {
    validate_payment_timestamp(
        smart_contract_timestamp,
        winner_pool_midpoint_proof.merkle_payment_timestamp,
    )?;

    let address_depth = address_branch.depth();
    let expected_address_depth = smart_contract_depth as usize;
    if address_depth != expected_address_depth {
        return Err(BadMerkleProof::AddressProofDepthMismatch {
            expected: expected_address_depth,
            got: address_depth,
        });
    }

    let winner_depth = winner_pool_midpoint_proof.branch.depth();
    let expected_winner_depth = midpoint_proof_depth(smart_contract_depth) as usize;
    if winner_depth != expected_winner_depth {
        return Err(BadMerkleProof::WinnerProofDepthMismatch {
            expected: expected_winner_depth,
            got: winner_depth,
        });
    }

    if !address_branch.verify() {
        return Err(BadMerkleProof::InvalidAddressBranchProof);
    }

    if !winner_pool_midpoint_proof.branch.verify() {
        return Err(BadMerkleProof::InvalidWinnerBranchProof);
    }

    if address_hash != address_branch.leaf_hash() {
        return Err(BadMerkleProof::AddressHashNotBranchLeaf {
            leaf: *address_branch.leaf_hash(),
            address: *address_hash,
        });
    }

    if address_branch.root() != smart_contract_root {
        return Err(BadMerkleProof::AddressBranchRootMismatch {
            smart_contract_root: *smart_contract_root,
            branch_root: *address_branch.root(),
        });
    }

    if winner_pool_midpoint_proof.branch.root() != smart_contract_root {
        return Err(BadMerkleProof::WinnerBranchRootMismatch {
            smart_contract_root: *smart_contract_root,
            branch_root: *winner_pool_midpoint_proof.branch.root(),
        });
    }

    Ok(())
}

/// SHA3-256 hasher for Merkle tree.
#[derive(Clone)]
pub(crate) struct Sha3Hasher;

impl ant_merkle::Hasher for Sha3Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        sha3_256(data)
    }

    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        match right {
            Some(r) => {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(left);
                combined.extend_from_slice(r);
                sha3_256(&combined)
            }
            None => sha3_256(left),
        }
    }

    fn hash_size() -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaves(count: usize) -> Vec<XorName> {
        (0..count)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
                XorName(bytes)
            })
            .collect()
    }

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    /// Regression: client-produced midpoint count must equal the on-chain
    /// `expected_reward_pools(depth)`. Pre-fix this only held for even depths;
    /// odd depths produced 2^floor(d/2) instead of 2^ceil(d/2), causing
    /// `WrongPoolCount` reverts at the payment vault for files in the chunk
    /// bands 5-8 (depth 3), 17-32 (depth 5) and 65-128 (depth 7).
    #[test]
    fn reward_candidate_count_matches_contract_for_all_depths() -> TestResult {
        for leaf_count in MIN_LEAVES..=MAX_LEAVES {
            let tree = MerkleTree::from_xornames(make_leaves(leaf_count))?;
            let candidates = tree.reward_candidates(0)?;
            let expected = expected_reward_pools(tree.depth());
            assert_eq!(
                candidates.len(),
                expected,
                "leaf_count={leaf_count} depth={} produced {} pools, contract expects {expected}",
                tree.depth(),
                candidates.len(),
            );
        }
        Ok(())
    }

    /// The exact failure observed in production: `WrongPoolCount(16, 8)`.
    /// 65-128 chunks → depth 7 → contract expects 16 pools; client must send 16.
    #[test]
    fn depth_seven_produces_sixteen_pools_not_eight() -> TestResult {
        for leaf_count in [65usize, 100, 128] {
            let tree = MerkleTree::from_xornames(make_leaves(leaf_count))?;
            assert_eq!(tree.depth(), 7, "leaf_count={leaf_count}");
            let candidates = tree.reward_candidates(0)?;
            assert_eq!(
                candidates.len(),
                16,
                "leaf_count={leaf_count} should produce 16 pools, got {}",
                candidates.len(),
            );
        }
        Ok(())
    }

    /// Smallest odd-depth case: depth=1 (2 leaves) must produce 2 midpoint pools.
    /// Pre-fix this produced only 1 pool (the root), which would have triggered
    /// `WrongPoolCount(2, 1)` for any 2-chunk upload.
    #[test]
    fn depth_one_produces_two_pools_not_one() -> TestResult {
        let tree = MerkleTree::from_xornames(make_leaves(2))?;
        assert_eq!(tree.depth(), 1);
        let candidates = tree.reward_candidates(0)?;
        assert_eq!(candidates.len(), 2);
        Ok(())
    }

    /// Each midpoint proof must verify against the tree root using the same
    /// `total_leaves_count` the contract uses (= number of midpoints).
    #[test]
    fn every_midpoint_proof_verifies_for_all_depths() -> TestResult {
        for leaf_count in MIN_LEAVES..=MAX_LEAVES {
            let tree = MerkleTree::from_xornames(make_leaves(leaf_count))?;
            let tree_root = tree.root();
            let candidates = tree.reward_candidates(0)?;
            for (i, mp) in candidates.iter().enumerate() {
                assert!(
                    mp.branch.verify(),
                    "midpoint {i}/{} failed branch.verify() (leaf_count={leaf_count}, depth={}, branch_root={:?}, tree_root={:?})",
                    candidates.len(),
                    tree.depth(),
                    mp.branch.root(),
                    tree_root,
                );
                assert_eq!(
                    mp.branch.depth(),
                    midpoint_proof_depth(tree.depth()) as usize,
                    "midpoint {i} proof depth mismatch (leaf_count={leaf_count}, depth={})",
                    tree.depth(),
                );
                assert_eq!(
                    mp.branch.root(),
                    &tree_root,
                    "midpoint {i} root divergence (leaf_count={leaf_count})",
                );
            }
        }
        Ok(())
    }

    /// End-to-end: the production verifier `verify_merkle_proof` must accept
    /// proofs produced by the fixed client across every supported depth.
    /// `branch.verify()` alone only checks Merkle hashing — this exercises
    /// the full set of checks (proof depth, root match, leaf identity, timestamp).
    #[test]
    fn verify_merkle_proof_accepts_all_depths() -> TestResult {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        for leaf_count in MIN_LEAVES..=MAX_LEAVES {
            let leaves = make_leaves(leaf_count);
            let first_leaf = match leaves.first() {
                Some(leaf) => *leaf,
                None => return Err(format!("make_leaves({leaf_count}) returned empty").into()),
            };
            let tree = MerkleTree::from_xornames(leaves)?;
            let address_branch = tree.generate_address_proof(0, first_leaf)?;
            let candidates = tree.reward_candidates(now)?;
            let winner = match candidates.first() {
                Some(c) => c.clone(),
                None => {
                    return Err(format!(
                        "no reward candidates for leaf_count={leaf_count} depth={}",
                        tree.depth()
                    )
                    .into());
                }
            };
            let root = tree.root();

            verify_merkle_proof(
                &first_leaf,
                &address_branch,
                &winner,
                tree.depth(),
                &root,
                now,
            )?;
        }
        Ok(())
    }
}
