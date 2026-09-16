# Browser WASM

Payment types, U256 amounts, quote hashing, pricing, and Merkle algorithms are
available with `default-features = false`. Their native serialization is unchanged.

Enable `rpc` for HTTP providers, contracts, and wallets. Alloy uses browser Fetch;
retry delays and transaction deadlines use JavaScript timers instead of requiring
a Tokio runtime. `external-signer` enables the same RPC support for external wallet
signing. Configure browser networks explicitly using `Network`/`CustomNetwork`.

The default `native` feature additionally enables environment network selection
and local Anvil process management. These OS facilities are excluded from WASM.

```sh
cargo check --lib --no-default-features --target wasm32-unknown-unknown
cargo check --lib --no-default-features --features rpc,external-signer --target wasm32-unknown-unknown
cargo test --lib --no-default-features
```
