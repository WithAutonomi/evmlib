const DEFAULT_MAX_FEE_PER_GAS: u128 = 200_000_000; // 0.2 Gwei

#[derive(Clone, Debug)]
pub struct TransactionConfig {
    pub max_fee_per_gas: u128,
}

impl TransactionConfig {
    pub fn new(max_fee_per_gas: u128) -> Self {
        Self { max_fee_per_gas }
    }
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            max_fee_per_gas: DEFAULT_MAX_FEE_PER_GAS,
        }
    }
}
