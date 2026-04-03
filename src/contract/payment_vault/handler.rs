use crate::common::{Address, Amount, Calldata, TxHash};
use crate::contract::payment_vault::error::Error;
use crate::contract::payment_vault::interface::IPaymentVault;
use crate::contract::payment_vault::interface::IPaymentVault::IPaymentVaultInstance;
use crate::merkle_batch_payment::PoolHash;
use crate::retry::{GasInfo, TransactionError, send_transaction_with_retries};
use crate::transaction_config::TransactionConfig;
use alloy::network::{Network, TransactionResponse};
use alloy::providers::Provider;
use exponential_backoff::Backoff;
use std::time::Duration;

pub struct PaymentVaultHandler<P: Provider<N>, N: Network> {
    pub contract: IPaymentVaultInstance<P, N>,
}

impl<P, N> PaymentVaultHandler<P, N>
where
    P: Provider<N>,
    N: Network,
{
    /// Create a new PaymentVaultHandler instance from a (proxy) contract's address
    pub fn new(contract_address: Address, provider: P) -> Self {
        let contract = IPaymentVault::new(contract_address, provider);
        Self { contract }
    }

    /// Set the provider
    pub fn set_provider(&mut self, provider: P) {
        let address = *self.contract.address();
        self.contract = IPaymentVault::new(address, provider);
    }

    // ── Single-node (quote) payments ────────────────────────────────────

    /// Pay for quotes.
    /// Returns the transaction hash and gas information.
    pub async fn pay_for_quotes<I: IntoIterator<Item: Into<IPaymentVault::DataPayment>>>(
        &self,
        data_payments: I,
        transaction_config: &TransactionConfig,
    ) -> Result<(TxHash, GasInfo), Error> {
        debug!("Paying for quotes.");
        let (calldata, to) = self.pay_for_quotes_calldata(data_payments)?;
        send_transaction_with_retries(
            self.contract.provider(),
            calldata,
            to,
            "pay for quotes",
            transaction_config,
        )
        .await
        .map_err(Error::from)
    }

    /// Returns the pay for quotes transaction calldata.
    pub fn pay_for_quotes_calldata<I: IntoIterator<Item: Into<IPaymentVault::DataPayment>>>(
        &self,
        data_payments: I,
    ) -> Result<(Calldata, Address), Error> {
        let data_payments: Vec<IPaymentVault::DataPayment> =
            data_payments.into_iter().map(|item| item.into()).collect();

        let calldata = self
            .contract
            .payForQuotes(data_payments)
            .calldata()
            .to_owned();

        Ok((calldata, *self.contract.address()))
    }

    // ── Merkle batch payments ───────────────────────────────────────────

    /// Pay for Merkle tree batch.
    ///
    /// Sends `payForMerkleTree` with unpacked `PoolCommitment` structs (candidates have price).
    ///
    /// # Returns
    /// * Tuple of (winner pool hash, total amount paid, gas info)
    pub async fn pay_for_merkle_tree<I, T>(
        &self,
        depth: u8,
        pool_commitments: I,
        merkle_payment_timestamp: u64,
        transaction_config: &TransactionConfig,
    ) -> Result<(PoolHash, Amount, GasInfo), Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<IPaymentVault::PoolCommitment>,
    {
        debug!("Paying for Merkle tree: depth={depth}, timestamp={merkle_payment_timestamp}");

        let (calldata, to) =
            self.pay_for_merkle_tree_calldata(depth, pool_commitments, merkle_payment_timestamp)?;

        let (tx_hash, gas_info) = self
            .send_transaction_and_handle_errors(calldata, to, transaction_config)
            .await?;

        let event = self.get_merkle_payment_event(tx_hash).await?;

        let winner_pool_hash = event.winnerPoolHash.0;
        let total_amount = event.totalAmount;

        debug!(
            "MerklePaymentMade event: winnerPoolHash={}, depth={}, totalAmount={}, timestamp={}",
            hex::encode(winner_pool_hash),
            event.depth,
            total_amount,
            event.merklePaymentTimestamp
        );

        Ok((winner_pool_hash, total_amount, gas_info))
    }

    /// Get calldata for payForMerkleTree.
    ///
    /// Public so external signers can generate calldata without a wallet.
    pub fn pay_for_merkle_tree_calldata<I, T>(
        &self,
        depth: u8,
        pool_commitments: I,
        merkle_payment_timestamp: u64,
    ) -> Result<(Calldata, Address), Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<IPaymentVault::PoolCommitment>,
    {
        let pool_commitments: Vec<IPaymentVault::PoolCommitment> = pool_commitments
            .into_iter()
            .map(|item| item.into())
            .collect();

        let calldata = self
            .contract
            .payForMerkleTree(depth, pool_commitments, merkle_payment_timestamp)
            .calldata()
            .to_owned();

        Ok((calldata, *self.contract.address()))
    }

    /// Get completed merkle payment info for a winner pool hash.
    ///
    /// Calls `getCompletedMerklePayment` on the contract, which returns
    /// `CompletedMerklePayment` containing depth, timestamp, and paid nodes
    /// (each with rewards address, pool index, and amount).
    pub async fn get_completed_merkle_payment(
        &self,
        winner_pool_hash: PoolHash,
    ) -> Result<IPaymentVault::CompletedMerklePayment, Error> {
        debug!(
            "Getting completed merkle payment for pool hash: {}",
            hex::encode(winner_pool_hash)
        );

        let info = self
            .contract
            .getCompletedMerklePayment(winner_pool_hash.into())
            .call()
            .await
            .map_err(Error::Contract)?;

        // Check if payment exists (depth == 0 means not found)
        if info.depth == 0 {
            return Err(Error::PaymentNotFound(hex::encode(winner_pool_hash)));
        }

        debug!(
            "getCompletedMerklePayment returned: depth={}, timestamp={}, paid_nodes={}",
            info.depth,
            info.merklePaymentTimestamp,
            info.paidNodeAddresses.len()
        );

        Ok(info)
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /// Get the MerklePaymentMade event from a transaction hash with retry logic.
    ///
    /// Retries up to 2 times with exponential backoff if the event is not found
    /// immediately (handles cases where the transaction may not be fully indexed).
    async fn get_merkle_payment_event(
        &self,
        tx_hash: TxHash,
    ) -> Result<IPaymentVault::MerklePaymentMade, Error> {
        const MAX_ATTEMPTS: u32 = 3;
        const INITIAL_DELAY_MS: u64 = 500;
        const MAX_DELAY_MS: u64 = 8000;

        let backoff = Backoff::new(
            MAX_ATTEMPTS,
            Duration::from_millis(INITIAL_DELAY_MS),
            Some(Duration::from_millis(MAX_DELAY_MS)),
        );

        let mut last_error = None;
        let mut attempt = 1;

        for duration_opt in backoff {
            match self.try_get_merkle_payment_event(tx_hash).await {
                Ok(event) => return Ok(event),
                Err(e) => {
                    last_error = Some(e);

                    if let Some(duration) = duration_opt {
                        debug!(
                            "Failed to get MerklePaymentMade event (attempt {}/{}), retrying in {}ms",
                            attempt,
                            MAX_ATTEMPTS,
                            duration.as_millis()
                        );
                        tokio::time::sleep(duration).await;
                    }
                    attempt += 1;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            Error::Rpc("Failed to get MerklePaymentMade event after retries".to_string())
        }))
    }

    /// Try to get the MerklePaymentMade event from a transaction hash (single attempt)
    async fn try_get_merkle_payment_event(
        &self,
        tx_hash: TxHash,
    ) -> Result<IPaymentVault::MerklePaymentMade, Error> {
        let tx = self
            .contract
            .provider()
            .get_transaction_by_hash(tx_hash)
            .await
            .map_err(|e| Error::Rpc(format!("Failed to get transaction: {e}")))?
            .ok_or_else(|| Error::Rpc("Transaction not found".to_string()))?;

        let block_number = tx
            .block_number()
            .ok_or_else(|| Error::Rpc("Transaction has no block number".to_string()))?;

        let events = self
            .contract
            .MerklePaymentMade_filter()
            .from_block(block_number)
            .to_block(block_number)
            .query()
            .await
            .map_err(|e| Error::Rpc(format!("Failed to query MerklePaymentMade events: {e}")))?;

        events
            .into_iter()
            .find(|(_, log)| log.transaction_hash == Some(tx_hash))
            .map(|(event, _)| event)
            .ok_or_else(|| {
                Error::Rpc("MerklePaymentMade event not found in transaction".to_string())
            })
    }

    /// Send transaction with retries and handle revert errors
    async fn send_transaction_and_handle_errors(
        &self,
        calldata: Calldata,
        to: Address,
        transaction_config: &TransactionConfig,
    ) -> Result<(TxHash, GasInfo), Error> {
        let tx_result = crate::retry::send_transaction_with_retries(
            self.contract.provider(),
            calldata,
            to,
            "pay for merkle tree",
            transaction_config,
        )
        .await;

        match tx_result {
            Ok((hash, gas_info)) => Ok((hash, gas_info)),
            Err(TransactionError::TransactionReverted {
                message,
                revert_data,
                nonce,
            }) => {
                let error = self.decode_revert_error(message, revert_data, nonce);
                Err(error)
            }
            Err(other_err) => Err(Error::from(other_err)),
        }
    }

    /// Decode revert data or return generic transaction error
    fn decode_revert_error(
        &self,
        message: String,
        revert_data: Option<alloy::primitives::Bytes>,
        nonce: Option<u64>,
    ) -> Error {
        if let Some(revert_data_bytes) = &revert_data
            && let Some(decoded_err) = Error::try_decode_revert(revert_data_bytes)
        {
            return decoded_err;
        }

        Error::Transaction(TransactionError::TransactionReverted {
            message,
            revert_data,
            nonce,
        })
    }
}
