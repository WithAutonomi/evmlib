use crate::contract::payment_vault::interface::IPaymentVault;
use crate::retry;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Contract error: {0}")]
    Contract(#[from] alloy::contract::Error),
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error(transparent)]
    Transaction(#[from] retry::TransactionError),

    // Smart contract custom errors
    #[error("ANT token address is null")]
    AntTokenNull,
    #[error("Batch limit exceeded")]
    BatchLimitExceeded,
    #[error("Merkle tree depth {depth} exceeds maximum allowed depth {max_depth}")]
    DepthTooLarge { depth: u8, max_depth: u8 },
    #[error("Invalid input length")]
    InvalidInputLength,
    #[error("Payment already exists for pool hash: {0}")]
    PaymentAlreadyExists(String),
    #[error("Payment not found for pool hash: {0}")]
    PaymentNotFound(String),
    #[error("Wrong pool count: expected {expected}, got {actual}")]
    WrongPoolCount { expected: u64, actual: u64 },
}

impl Error {
    /// Try to decode a contract error from revert data
    pub(crate) fn try_decode_revert(data: &[u8]) -> Option<Self> {
        use alloy::sol_types::SolInterface;

        // The revert data should start with the 4-byte selector followed by the error data
        if data.len() < 4 {
            return None;
        }

        let selector: [u8; 4] = data[..4].try_into().ok()?;
        let error_data = &data[4..];

        // Try to decode as IPaymentVaultErrors
        if let Ok(contract_error) =
            IPaymentVault::IPaymentVaultErrors::abi_decode_raw(selector, error_data)
        {
            return Some(Self::from_contract_error(contract_error));
        }

        None
    }

    /// Convert a decoded contract error to our Error type
    fn from_contract_error(error: IPaymentVault::IPaymentVaultErrors) -> Self {
        use IPaymentVault::IPaymentVaultErrors;

        match error {
            IPaymentVaultErrors::AntTokenNull(_) => Self::AntTokenNull,
            IPaymentVaultErrors::BatchLimitExceeded(_) => Self::BatchLimitExceeded,
            IPaymentVaultErrors::DepthTooLarge(e) => Self::DepthTooLarge {
                depth: e.depth,
                max_depth: e.maxDepth,
            },
            IPaymentVaultErrors::InvalidInputLength(_) => Self::InvalidInputLength,
            IPaymentVaultErrors::PaymentAlreadyExists(e) => {
                Self::PaymentAlreadyExists(hex::encode(e.winnerPoolHash))
            }
            IPaymentVaultErrors::WrongPoolCount(e) => Self::WrongPoolCount {
                expected: e.expected.try_into().unwrap_or(u64::MAX),
                actual: e.actual.try_into().unwrap_or(u64::MAX),
            },
            IPaymentVaultErrors::SafeERC20FailedOperation(e) => {
                Self::Rpc(format!("SafeERC20 transfer failed for token: {}", e.token))
            }
        }
    }
}
