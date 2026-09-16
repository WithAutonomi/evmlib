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
use alloy::transports::{RpcError, TransportErrorKind};
use serde::{Deserialize, Serialize};

/// Retry base for reads made while a caller is polling for an outcome. The
/// native client observes inside a 30s window, so the default 4s base (4/16/36s)
/// would turn one throttled read into a timed-out payment.
const OBSERVE_RETRY_INTERVAL_MS: u64 = 500;

/// Run a read-only RPC call with the crate's standard backoff.
///
/// Every read in the journal path used to be single-shot, so one `429` from a
/// public endpoint failed the upload — the legacy `send_transaction_with_retries`
/// path wrapped the same reads in three retries.
async fn rpc<T, E, F, Fut>(
    operation: &str,
    interval_ms: Option<u64>,
    action: F,
) -> Result<T, String>
where
    F: FnMut() -> Fut + Send,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Debug + std::fmt::Display,
{
    crate::retry::retry(action, operation, interval_ms)
        .await
        .map_err(|e| e.to_string())
}

/// A failure the endpoint may not give again: HTTP-level errors (429, 5xx),
/// connection loss, timeouts, and the backend-timeout error responses public
/// load balancers emit. Definitive RPC rejections (bad nonce, underpriced,
/// insufficient funds) are never transient.
fn is_transient(err: &RpcError<TransportErrorKind>) -> bool {
    match err {
        RpcError::Transport(_) => true,
        RpcError::ErrorResp(payload) => {
            let message = payload.message.to_ascii_lowercase();
            [
                "deadline exceeded",
                "timeout",
                "timed out",
                "too many requests",
                "rate limit",
            ]
            .iter()
            .any(|needle| message.contains(needle))
        }
        _ => false,
    }
}

/// The endpoint already holds these exact bytes: a retried broadcast after an
/// ambiguous failure, or a replica that saw the first send.
fn is_already_known(err: &RpcError<TransportErrorKind>) -> bool {
    match err {
        RpcError::ErrorResp(payload) => {
            let message = payload.message.to_ascii_lowercase();
            [
                "already known",
                "already imported",
                "already exists",
                "alreadyexists",
            ]
            .iter()
            .any(|needle| message.contains(needle))
        }
        _ => false,
    }
}

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
    /// A mined failure is not finalized yet. Retain the journal without
    /// broadcasting or preparing another payment. (A consumed nonce with no
    /// receipt reports `Pending`, not this: see `observe_payment`.)
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
        let address = self.address();
        // Set the chain id here so `fill` below needs no RPC call of its own.
        let chain = rpc("chain id", None, || async { provider.get_chain_id().await }).await?;
        let mut tx = provider
            .transaction_request()
            .with_from(address)
            .with_to(vault)
            .with_input(calldata)
            .with_chain_id(chain);
        if let Some(fees) = crate::retry::get_eip1559_fees(&provider, &self.transaction_config)
            .await
            .map_err(|e| e.to_string())?
        {
            tx.set_max_fee_per_gas(fees.max_fee_per_gas);
            tx.set_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
        }
        let gas = rpc("gas estimate", None, || {
            let (provider, tx) = (&provider, tx.clone());
            async move { provider.estimate_gas(tx).await }
        })
        .await?;
        tx.set_gas_limit(gas.saturating_mul(120) / 100);
        // Two independent reads, highest wins. A public endpoint is a pool of
        // replicas that can lag each other by a block or more; a single stale
        // `pending` read signs a nonce the chain has already consumed, and those
        // bytes can then never be mined. Measured on sepolia-rollup.arbitrum.io
        // (2026-09-16): `pending=98` followed by `latest=99`, 1 pair in 150.
        let pending_nonce = rpc("pending nonce", None, || async {
            provider.get_transaction_count(address).pending().await
        })
        .await?;
        let latest_nonce = rpc("latest nonce", None, || async {
            provider.get_transaction_count(address).await
        })
        .await?;
        tx.set_nonce(pending_nonce.max(latest_nonce));
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
        let provider = self.to_provider();
        let chain = rpc("chain id", Some(OBSERVE_RETRY_INTERVAL_MS), || async {
            provider.get_chain_id().await
        })
        .await?;
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
    ///
    /// Transport-level failures (HTTP 429/5xx, timeouts, backend deadline
    /// responses) are retried with the same bytes: re-sending a signed
    /// transaction cannot create a second payment, and an endpoint that already
    /// holds it answers "already known", which is treated as success. A
    /// definitive rejection (bad nonce, underpriced, insufficient funds) is
    /// returned at once.
    pub async fn broadcast_payment(
        &self,
        signed: &SignedPayment,
        request: &PaymentRequest,
    ) -> Result<TxHash, String> {
        let tx = self.validate_payment(signed, request).await?;
        let provider = self.to_provider();
        let mut retries: u8 = 0;
        loop {
            match provider.send_raw_transaction(&signed.raw).await {
                Ok(pending) => {
                    if pending.tx_hash() != tx.tx_hash() {
                        return Err("RPC returned a different transaction hash".into());
                    }
                    return Ok(*tx.tx_hash());
                }
                Err(err) if is_already_known(&err) => return Ok(*tx.tx_hash()),
                Err(err) if is_transient(&err) && retries < crate::retry::MAX_RETRIES => {
                    retries += 1;
                    let delay = std::time::Duration::from_millis(
                        OBSERVE_RETRY_INTERVAL_MS * u64::from(retries).pow(2),
                    );
                    tracing::warn!(
                        "Error broadcasting payment: {err}. Retry #{retries} in {delay:?} with the same bytes."
                    );
                    crate::runtime::sleep(delay).await;
                }
                Err(err) => return Err(err.to_string()),
            }
        }
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
        let tx_hash = *tx.tx_hash();
        if let Some(receipt) = rpc(
            "payment receipt",
            Some(OBSERVE_RETRY_INTERVAL_MS),
            || async { provider.get_transaction_receipt(tx_hash).await },
        )
        .await?
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
        let address = self.address();
        let latest_nonce = rpc("latest nonce", Some(OBSERVE_RETRY_INTERVAL_MS), || async {
            provider.get_transaction_count(address).await
        })
        .await?;
        if latest_nonce <= tx.nonce() {
            return Ok(PaymentStatus::Pending);
        }
        let finalized = finalized_header(&provider).await?;
        let finalized_nonce = nonce_at(&provider, address, &finalized).await?;
        if finalized_nonce <= tx.nonce() {
            // The nonce looks consumed but nothing is final. That is either an
            // unfinalised transaction on this nonce (this payment with its receipt
            // not yet visible, a fee replacement, or something else) or simply a
            // `latest` read served by a replica ahead of the one that served the
            // caller's earlier reads — the two are indistinguishable from here, and
            // a public endpoint produces the second routinely. Neither warrants
            // giving up: the journaled bytes can be re-sent safely (a consumed
            // nonce is rejected, never paid twice), and finality resolves a real
            // replacement into `Replaced` below. Reporting `Finalizing` here made
            // every stale read a failed upload (DEV-03 run 589, 2026-09-16).
            return Ok(PaymentStatus::Pending);
        }

        // Find what actually consumed the nonce. It could be the original
        // transaction with a temporarily unavailable receipt, or a fee bump
        // that already paid. Neither permits assuming the payment failed.
        let (replacement_hash, block) =
            find_nonce_transaction(&provider, self.address(), tx.nonce(), &finalized).await?;
        let replacement = rpc(
            "nonce transaction",
            Some(OBSERVE_RETRY_INTERVAL_MS),
            || async { provider.get_transaction_by_hash(replacement_hash).await },
        )
        .await?
        .ok_or("finalized nonce transaction unavailable; retain the journal")?;
        let receipt = rpc("nonce receipt", Some(OBSERVE_RETRY_INTERVAL_MS), || async {
            provider.get_transaction_receipt(replacement_hash).await
        })
        .await?
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
    rpc(
        "finalized block",
        Some(OBSERVE_RETRY_INTERVAL_MS),
        || async {
            provider
                .get_block_by_number(BlockNumberOrTag::Finalized)
                .await
        },
    )
    .await?
    .map(|block| block.header)
    .ok_or_else(|| "finalized block unavailable; retain the journal".into())
}

async fn block_by_number(
    provider: &ProviderWithWallet,
    number: u64,
) -> Result<Option<Block>, String> {
    rpc(
        "block by number",
        Some(OBSERVE_RETRY_INTERVAL_MS),
        || async { provider.get_block_by_number(number.into()).await },
    )
    .await
}

async fn receipt_is_canonical(
    provider: &ProviderWithWallet,
    receipt: &TransactionReceipt,
) -> Result<bool, String> {
    let (Some(number), Some(hash)) = (receipt.block_number, receipt.block_hash) else {
        return Ok(false);
    };
    Ok(block_by_number(provider, number)
        .await?
        .is_some_and(|block| block.header.number == number && block.header.hash == hash))
}

async fn nonce_at(
    provider: &ProviderWithWallet,
    address: crate::common::Address,
    block: &Header,
) -> Result<u64, String> {
    let hash = block.hash;
    rpc(
        "nonce at block",
        Some(OBSERVE_RETRY_INTERVAL_MS),
        || async {
            provider
                .get_transaction_count(address)
                .block_id(BlockId::hash_canonical(hash))
                .await
        },
    )
    .await
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
        let block = block_by_number(provider, probe)
            .await?
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
        let block = block_by_number(provider, mid)
            .await?
            .ok_or("nonce history unavailable; retain the journal")?;
        if nonce_at(provider, address, &block.header).await? > nonce {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    let header = block_by_number(provider, low)
        .await?
        .ok_or("nonce block unavailable; retain the journal")?
        .header;
    let block_hash = header.hash;
    let block: Option<Block<NonceTransaction>> = rpc(
        "nonce block transactions",
        Some(OBSERVE_RETRY_INTERVAL_MS),
        || async {
            provider
                .client()
                .request("eth_getBlockByHash", (block_hash, true))
                .await
        },
    )
    .await?;
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
    use alloy::rpc::json_rpc::ErrorPayload;

    fn error_resp(code: i64, message: &str) -> RpcError<TransportErrorKind> {
        RpcError::ErrorResp(ErrorPayload {
            code,
            message: message.to_string().into(),
            data: None,
        })
    }

    #[test]
    fn transport_failures_are_transient() {
        // What sepolia-rollup.arbitrum.io returned on DEV-03 run 589.
        assert!(is_transient(&RpcError::Transport(
            TransportErrorKind::HttpError(alloy::transports::HttpError {
                status: 429,
                body: "Too Many Requests".into(),
            })
        )));
        assert!(is_transient(&error_resp(
            -32000,
            "Post \"http://10.17.52.14:8547/rpc\": context deadline exceeded"
        )));
        assert!(is_transient(&RpcError::Transport(
            TransportErrorKind::BackendGone
        )));
    }

    #[test]
    fn definitive_rejections_are_not_transient() {
        for message in [
            "nonce too low: address 0x00, tx: 5 state: 6",
            "replacement transaction underpriced",
            "insufficient funds for gas * price + value",
            "execution reverted",
        ] {
            let err = error_resp(-32000, message);
            assert!(!is_transient(&err), "{message}");
            assert!(!is_already_known(&err), "{message}");
        }
    }

    #[test]
    fn already_known_is_success_not_failure() {
        assert!(is_already_known(&error_resp(-32000, "already known")));
        assert!(is_already_known(&error_resp(
            -32000,
            "ALREADY_EXISTS: already known"
        )));
        assert!(!is_transient(&error_resp(-32000, "already known")));
    }

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
