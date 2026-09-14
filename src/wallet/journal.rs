// Copyright 2026 MaidSafe.net limited.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sign before broadcasting so callers can durably journal and recover payments.

use super::Wallet;
use crate::common::{Amount, Calldata, QuotePayment, TxHash, U256};
use crate::contract::payment_vault::{MAX_TRANSFERS_PER_TRANSACTION, handler::PaymentVaultHandler};
use crate::merkle_batch_payment::{PoolCommitment, PoolHash};
use alloy::consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy::eips::eip2718::{Decodable2718, Encodable2718};
use alloy::network::TransactionBuilder;
use alloy::providers::Provider;
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

/// A chain-confirmed payment result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Exact signed transaction hash.
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
    /// Not mined; retain the journal.
    Pending,
    /// Mined and reverted; this transaction cannot subsequently charge storage tokens.
    Reverted,
    /// Successful payment, suitable for proof construction.
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

    /// Observe the exact journaled payment, validating its original signed
    /// calldata before accepting a receipt. This method never broadcasts.
    pub async fn observe_payment(
        &self,
        signed: &SignedPayment,
        request: &PaymentRequest,
    ) -> Result<PaymentStatus, String> {
        let tx = self.validate_payment(signed, request).await?;
        let provider = self.to_provider();
        let Some(receipt) = provider
            .get_transaction_receipt(*tx.tx_hash())
            .await
            .map_err(|e| e.to_string())?
        else {
            return Ok(PaymentStatus::Pending);
        };
        if !receipt.status() {
            return Ok(PaymentStatus::Reverted);
        }
        let (amount, winner_pool) = match request {
            PaymentRequest::Quotes(_) => (request.calldata(self)?.1, None),
            PaymentRequest::Merkle { .. } => {
                let event =
                    PaymentVaultHandler::new(*self.network.payment_vault_address(), provider)
                        .get_merkle_payment_event(*tx.tx_hash())
                        .await
                        .map_err(|e| e.to_string())?;
                (event.totalAmount, Some(event.winnerPoolHash.0))
            }
        };
        Ok(PaymentStatus::Confirmed(PaymentReceipt {
            transaction_hash: *tx.tx_hash(),
            amount,
            winner_pool,
            gas_cost_wei: (receipt.gas_used as u128).saturating_mul(receipt.effective_gas_price),
        }))
    }
}
