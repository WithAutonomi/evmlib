// Copyright 2026 MaidSafe.net limited.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sign before broadcasting so callers can durably journal and recover payments.

use super::{ProviderWithWallet, Wallet};
use crate::common::{Amount, Calldata, QuotePayment, TxHash, U256};
use crate::contract::payment_vault::{MAX_TRANSFERS_PER_TRANSACTION, handler::PaymentVaultHandler};
use crate::merkle_batch_payment::{PoolCommitment, PoolHash};
use alloy::consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy::eips::eip2718::{Decodable2718, Encodable2718};
use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::network::TransactionBuilder;
use alloy::providers::Provider;
use alloy::rpc::types::{Block, Header, TransactionReceipt};
use serde::{Deserialize, Serialize};

/// An ordinary single transaction payment, using the existing vault encoders.
pub enum PaymentRequest {
    /// At most one vault transaction of nonzero quote payments.
    Quotes(Vec<QuotePayment>),
    /// One Merkle sub-batch.
    Merkle {
        depth: u8,
        pools: Vec<PoolCommitment>,
        timestamp: u64,
    },
}

/// Signed transaction bytes, safe to persist before the first broadcast.
/// Contains no private key. Re-sending these bytes cannot create another payment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPayment {
    raw: Vec<u8>,
}

/// A payment included in the canonical chain. Inclusion is not finality.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Settlement transaction hash, including a same-intent fee replacement.
    pub transaction_hash: TxHash,
    /// Storage tokens charged.
    pub amount: Amount,
    /// Merkle winner, absent for quote payments.
    pub winner_pool: Option<PoolHash>,
    /// Actual gas spend.
    pub gas_cost_wei: u128,
}

/// Observation never assumes a missing receipt means the transaction failed.
#[derive(Debug)]
pub enum PaymentStatus {
    /// No mined payment found; retain the journal.
    Pending,
    /// A mined failure or consumed nonce is not finalized yet. Retain the journal without
    /// broadcasting or preparing another payment.
    Finalizing,
    /// The payment reverted in a finalized block. The original transaction
    /// cannot subsequently charge storage tokens, including after a fee replacement.
    Reverted,
    /// A different transaction consumed the nonce in a finalized block.
    /// Its calldata differs from this payment; the original cannot execute.
    Replaced { transaction_hash: TxHash },
    /// Successful canonical inclusion, suitable for optimistic proof construction.
    /// This retains the existing wallet's inclusion-level success semantics;
    /// callers requiring irreversible settlement must also wait for finality.
    Confirmed(PaymentReceipt),
}

impl PaymentRequest {
    fn calldata(&self, wallet: &Wallet) -> Result<(Calldata, Amount), String> {
        let handler = PaymentVaultHandler::new(
            *wallet.network.payment_vault_address(),
            wallet.to_provider(),
        );
        match self {
            Self::Quotes(quotes) => {
                let quotes = quotes
                    .iter()
                    .filter(|(_, _, amount)| *amount != Amount::ZERO)
                    .copied()
                    .collect::<Vec<_>>();
                if quotes.is_empty() || quotes.len() > MAX_TRANSFERS_PER_TRANSACTION {
                    return Err(
                        "journaled quote payment must fit one nonempty vault transaction".into(),
                    );
                }
                let amount = quotes.iter().try_fold(Amount::ZERO, |sum, (_, _, value)| {
                    sum.checked_add(*value).ok_or("payment total overflow")
                })?;
                Ok((
                    handler
                        .pay_for_quotes_calldata(quotes)
                        .map_err(|e| e.to_string())?
                        .0,
                    amount,
                ))
            }
            Self::Merkle {
                depth,
                pools,
                timestamp,
            } => Ok((
                handler
                    .pay_for_merkle_tree_calldata(*depth, pools.clone(), *timestamp)
                    .map_err(|e| e.to_string())?
                    .0,
                wallet.network.estimate_merkle_payment_cost(*depth, pools),
            )),
        }
    }
}

impl Wallet {
    /// Prepare and sign without broadcasting the storage payment. Persist the
    /// result before calling `broadcast_payment`. Hold `Wallet::lock` across
    /// preparation and submission when sharing a wallet between operations.
    pub async fn prepare_payment(&self, request: &PaymentRequest) -> Result<SignedPayment, String> {
        let (calldata, amount) = request.calldata(self)?;
        let balance = self.balance_of_tokens().await.map_err(|e| e.to_string())?;
        if balance < amount {
            return Err(super::Error::InsufficientTokensForQuotes(balance, amount).to_string());
        }
        let vault = *self.network.payment_vault_address();
        if self
            .token_allowance(vault)
            .await
            .map_err(|e| e.to_string())?
            < amount
        {
            self.approve_to_spend_tokens(vault, U256::MAX)
                .await
                .map_err(|e| e.to_string())?;
        }
        let provider = self.to_provider();
        let mut tx = provider
            .transaction_request()
            .with_from(self.address())
            .with_to(vault)
            .with_input(calldata);
        if let Some(fees) = crate::retry::get_eip1559_fees(&provider, &self.transaction_config)
            .await
            .map_err(|e| e.to_string())?
        {
            tx.set_max_fee_per_gas(fees.max_fee_per_gas);
            tx.set_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
        }
        let gas = provider
            .estimate_gas(tx.clone())
            .await
            .map_err(|e| e.to_string())?;
        tx.set_gas_limit(gas.saturating_mul(120) / 100);
        tx.set_nonce(
            provider
                .get_transaction_count(self.address())
                .pending()
                .await
                .map_err(|e| e.to_string())?,
        );
        let envelope = provider
            .fill(tx)
            .await
            .map_err(|e| e.to_string())?
            .try_into_envelope()
            .map_err(|_| "wallet did not sign transaction")?;
        Ok(SignedPayment {
            raw: envelope.encoded_2718(),
        })
    }

    async fn validate_payment(
        &self,
        signed: &SignedPayment,
        request: &PaymentRequest,
    ) -> Result<TxEnvelope, String> {
        let mut bytes = signed.raw.as_slice();
        let tx = TxEnvelope::decode_2718(&mut bytes).map_err(|e| e.to_string())?;
        let (calldata, _) = request.calldata(self)?;
        let chain = self
            .to_provider()
            .get_chain_id()
            .await
            .map_err(|e| e.to_string())?;
        if !bytes.is_empty()
            || tx.to() != Some(*self.network.payment_vault_address())
            || tx.input() != &calldata
            || tx.value() != U256::ZERO
            || tx.chain_id() != Some(chain)
            || tx.recover_signer().map_err(|e| e.to_string())? != self.address()
        {
            return Err(
                "journaled transaction does not match this wallet, chain, or payment intent".into(),
            );
        }
        Ok(tx)
    }

    /// Broadcast exactly the journaled bytes. No re-signing, nonce change, or
    /// fee replacement occurs, including after an ambiguous RPC failure.
    pub async fn broadcast_payment(
        &self,
        signed: &SignedPayment,
        request: &PaymentRequest,
    ) -> Result<TxHash, String> {
        let tx = self.validate_payment(signed, request).await?;
        let provider = self.to_provider();
        let pending = provider
            .send_raw_transaction(&signed.raw)
            .await
            .map_err(|e| e.to_string())?;
        if pending.tx_hash() != tx.tx_hash() {
            return Err("RPC returned a different transaction hash".into());
        }
        Ok(*tx.tx_hash())
    }

    /// Observe the journaled payment without broadcasting. Reverted and replaced
    /// outcomes require finalized, canonical evidence before another payment is safe.
    /// A successful fee replacement with identical calldata recovers its own receipt.
    pub async fn observe_payment(
        &self,
        signed: &SignedPayment,
        request: &PaymentRequest,
    ) -> Result<PaymentStatus, String> {
        let tx = self.validate_payment(signed, request).await?;
        let provider = self.to_provider();
        if let Some(receipt) = provider
            .get_transaction_receipt(*tx.tx_hash())
            .await
            .map_err(|e| e.to_string())?
        {
            if receipt.transaction_hash != *tx.tx_hash() {
                return Err("RPC returned a different receipt transaction hash".into());
            }
            if receipt.status() {
                if !receipt_is_canonical(&provider, &receipt).await? {
                    return Ok(PaymentStatus::Pending);
                }
                return self
                    .payment_receipt(request, receipt)
                    .map(PaymentStatus::Confirmed);
            }
            let finalized = finalized_header(&provider).await?;
            // Read finality before checking canonicality: a reorg between the
            // two queries must not bless a receipt from the discarded fork.
            if !receipt_is_canonical(&provider, &receipt).await? {
                return Ok(PaymentStatus::Pending);
            }
            return Ok(
                if receipt.block_number.is_some_and(|n| n <= finalized.number) {
                    PaymentStatus::Reverted
                } else {
                    PaymentStatus::Finalizing
                },
            );
        }

        // A missing receipt alone is never evidence of failure. Check whether
        // this nonce has been mined before asking for historical/finality data.
        let latest_nonce = provider
            .get_transaction_count(self.address())
            .await
            .map_err(|e| e.to_string())?;
        if latest_nonce <= tx.nonce() {
            return Ok(PaymentStatus::Pending);
        }
        let finalized = finalized_header(&provider).await?;
        let finalized_nonce = nonce_at(&provider, self.address(), &finalized).await?;
        if finalized_nonce <= tx.nonce() {
            return Ok(PaymentStatus::Finalizing);
        }

        // Find what actually consumed the nonce. It could be the original
        // transaction with a temporarily unavailable receipt, or a fee bump
        // that already paid. Neither permits assuming the payment failed.
        let (replacement_hash, block) =
            find_nonce_transaction(&provider, self.address(), tx.nonce(), &finalized).await?;
        let replacement = provider
            .get_transaction_by_hash(replacement_hash)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("finalized nonce transaction unavailable; retain the journal")?;
        let receipt = provider
            .get_transaction_receipt(replacement_hash)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("finalized nonce receipt unavailable; retain the journal")?;
        if replacement.inner.tx_hash() != &replacement_hash
            || replacement.block_hash != Some(block.hash)
            || receipt.transaction_hash != replacement_hash
            || receipt.block_hash != Some(block.hash)
            || receipt.block_number != Some(block.number)
            || !receipt_is_canonical(&provider, &receipt).await?
        {
            return Err("inconsistent finalized transaction evidence; retain the journal".into());
        }
        if replacement.to() != tx.to()
            || replacement.value() != tx.value()
            || replacement.input() != tx.input()
        {
            return Ok(PaymentStatus::Replaced {
                transaction_hash: replacement_hash,
            });
        }
        if !receipt.status() {
            return Ok(PaymentStatus::Reverted);
        }
        self.payment_receipt(request, receipt)
            .map(PaymentStatus::Confirmed)
    }

    fn payment_receipt(
        &self,
        request: &PaymentRequest,
        receipt: TransactionReceipt,
    ) -> Result<PaymentReceipt, String> {
        let (amount, winner_pool) = match request {
            PaymentRequest::Quotes(_) => (request.calldata(self)?.1, None),
            PaymentRequest::Merkle { .. } => {
                // Decode the logs from this receipt so block-number queries
                // cannot mix a settlement event from another fork into it.
                use crate::contract::payment_vault::interface::IPaymentVault;
                let event = receipt
                    .inner
                    .logs()
                    .iter()
                    .filter(|log| log.address() == *self.network.payment_vault_address())
                    .find_map(|log| log.log_decode::<IPaymentVault::MerklePaymentMade>().ok())
                    .ok_or("MerklePaymentMade event missing from payment receipt")?;
                (
                    event.inner.data.totalAmount,
                    Some(event.inner.data.winnerPoolHash.0),
                )
            }
        };
        Ok(PaymentReceipt {
            transaction_hash: receipt.transaction_hash,
            amount,
            winner_pool,
            gas_cost_wei: (receipt.gas_used as u128).saturating_mul(receipt.effective_gas_price),
        })
    }
}

async fn finalized_header(provider: &ProviderWithWallet) -> Result<Header, String> {
    provider
        .get_block_by_number(BlockNumberOrTag::Finalized)
        .await
        .map_err(|e| e.to_string())?
        .map(|block| block.header)
        .ok_or_else(|| "finalized block unavailable; retain the journal".into())
}

async fn receipt_is_canonical(
    provider: &ProviderWithWallet,
    receipt: &TransactionReceipt,
) -> Result<bool, String> {
    let (Some(number), Some(hash)) = (receipt.block_number, receipt.block_hash) else {
        return Ok(false);
    };
    Ok(provider
        .get_block_by_number(number.into())
        .await
        .map_err(|e| e.to_string())?
        .is_some_and(|block| block.header.number == number && block.header.hash == hash))
}

async fn nonce_at(
    provider: &ProviderWithWallet,
    address: crate::common::Address,
    block: &Header,
) -> Result<u64, String> {
    provider
        .get_transaction_count(address)
        .block_id(BlockId::hash_canonical(block.hash))
        .await
        .map_err(|e| e.to_string())
}

// Decode only transaction identity when scanning a block. Arbitrum blocks also
// contain system transaction types that Ethereum's TxEnvelope cannot decode.
#[derive(Debug, Deserialize)]
struct NonceTransaction {
    hash: TxHash,
    from: Option<crate::common::Address>,
    #[serde(default, with = "alloy::serde::quantity::opt")]
    nonce: Option<u64>,
}

async fn find_nonce_transaction(
    provider: &ProviderWithWallet,
    address: crate::common::Address,
    nonce: u64,
    finalized: &Header,
) -> Result<(TxHash, Header), String> {
    // Search backwards from finality first: recent replacements should not
    // require state from halfway back to genesis on a pruned RPC endpoint.
    // Exponential bracketing then binary search takes O(log age) queries and
    // supports existing journals without adding preparation-block metadata.
    let (mut low, mut high) = (finalized.number, finalized.number);
    let mut step = 1u64;
    while low > 0 {
        let probe = low.saturating_sub(step);
        let block = provider
            .get_block_by_number(probe.into())
            .await
            .map_err(|e| e.to_string())?
            .ok_or("nonce history unavailable; retain the journal")?;
        low = probe;
        if nonce_at(provider, address, &block.header).await? <= nonce {
            break;
        }
        high = probe;
        step = step.saturating_mul(2);
    }
    while low < high {
        let mid = low + (high - low) / 2;
        let block = provider
            .get_block_by_number(mid.into())
            .await
            .map_err(|e| e.to_string())?
            .ok_or("nonce history unavailable; retain the journal")?;
        if nonce_at(provider, address, &block.header).await? > nonce {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    let header = provider
        .get_block_by_number(low.into())
        .await
        .map_err(|e| e.to_string())?
        .ok_or("nonce block unavailable; retain the journal")?
        .header;
    let block: Option<Block<NonceTransaction>> = provider
        .client()
        .request("eth_getBlockByHash", (header.hash, true))
        .await
        .map_err(|e| e.to_string())?;
    let block = block.ok_or("nonce transactions unavailable; retain the journal")?;
    if block.header.hash != header.hash || block.header.number != header.number {
        return Err("inconsistent nonce block; retain the journal".into());
    }
    for candidate in block.transactions.txns() {
        if candidate.from == Some(address) && candidate.nonce == Some(nonce) {
            return Ok((candidate.hash, header));
        }
    }
    // EIP-7702 authorizations can also advance a nonce. Do not classify an
    // unexplained nonce advance or incomplete RPC history as a safe retry.
    Err("finalized nonce consumer not found; retain the journal for reconciliation".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_scan_accepts_arbitrum_system_transactions() {
        // Scanning an entire Arbitrum block must not require decoding every
        // transaction as an Ethereum envelope. Unknown system types are skipped.
        let system: NonceTransaction = serde_json::from_value(serde_json::json!({
            "type": "0x6a",
            "hash": TxHash::ZERO,
            "from": crate::common::Address::ZERO,
            "nonce": "0x0",
            "input": "0x1234"
        }))
        .unwrap();
        assert_eq!(system.nonce, Some(0));
        let without_nonce: NonceTransaction = serde_json::from_value(serde_json::json!({
            "type": "0x7e",
            "hash": TxHash::ZERO
        }))
        .unwrap();
        assert_eq!(without_nonce.nonce, None);
    }
}
