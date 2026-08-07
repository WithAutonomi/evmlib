// Copyright 2025 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

#[derive(Clone, Debug, Default)]
pub struct TransactionConfig {
    pub max_fee_per_gas: MaxFeePerGas,
}

#[derive(Clone, Debug, Default)]
pub enum MaxFeePerGas {
    /// Use the current market price for fee per gas. WARNING: This can result in unexpected high gas fees!
    #[default]
    Auto,
    /// Use the current market price for fee per gas, but with an upper limit.
    LimitedAuto(u128),
    /// Use no max fee per gas. WARNING: This can result in unexpected high gas fees!
    Unlimited,
    /// Use a custom max fee per gas in WEI.
    Custom(u128),
}
