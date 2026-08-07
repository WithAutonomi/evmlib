// Copyright 2024 MaidSafe.net limited.
//
// This Autonomi Software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use alloy::primitives::FixedBytes;

pub type Address = alloy::primitives::Address;
pub type Hash = FixedBytes<32>;
pub type TxHash = alloy::primitives::TxHash;
pub type U256 = alloy::primitives::U256;
pub type QuoteHash = Hash;
pub type Amount = U256;
pub type QuotePayment = (QuoteHash, Address, Amount);
pub type EthereumWallet = alloy::network::EthereumWallet;
pub type Calldata = alloy::primitives::Bytes;
