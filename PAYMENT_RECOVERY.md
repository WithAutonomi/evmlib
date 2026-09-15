# Native payment recovery

`Wallet::prepare_payment` signs one payment without broadcasting it. Persist the
returned `SignedPayment` and its `PaymentRequest` before calling
`broadcast_payment`. Keep the wallet lock across preparation, persistence, and
submission. Locks do not survive a process restart or reserve a nonce on-chain.

## Recovery states

Call `observe_payment` when resuming an interrupted operation:

| Status | Meaning | Caller action |
| --- | --- | --- |
| `Pending` | No payment receipt or mined nonce consumer is known. | Keep the journal; broadcasting its exact signed bytes is allowed. |
| `Finalizing` | A reverted receipt or consumed nonce has been observed, but is not finalized. | Keep the journal and observe again later; do not broadcast or prepare a new payment. |
| `Reverted` | The payment, or its identical-calldata replacement, reverted in a finalized canonical block. | The original cannot execute again; a fresh attempt is safe. |
| `Replaced { transaction_hash }` | Another transaction with different calldata/value/destination consumed the nonce in finalized history. | The original cannot execute; retain the replacement hash for auditing and prepare a new attempt if needed. |
| `Confirmed(receipt)` | The payment succeeded in the canonical chain, possibly through a fee replacement with identical calldata. | Use the returned settlement hash, amount, and Merkle winner. Success retains the existing wallet's optimistic inclusion semantics. |

An RPC error, missing history, or unexplained nonce advance does not authorize a
new payment. Preserve the journal. A timeout is likewise not evidence of failure.

## Finality and RPC requirements

Retry decisions use the RPC's `finalized` block tag and compare receipt block
hashes with the canonical chain. A fixed count of Arbitrum L2 blocks is not a
substitute for parent-chain finality. The endpoint must provide trustworthy
finality data; unsupported finality results in an error, with the journal retained.
See [Arbitrum finality](https://docs.arbitrum.io/how-arbitrum-works/reference/finality-and-reorgs).

Successful payments retain the existing low-latency behavior: `Confirmed` means
canonical inclusion, not irreversible settlement. Applications needing finality
for successful payments must retain transaction evidence and wait for the receipt
block to finalize before making irreversible decisions.

Nonce recovery first checks whether the nonce was mined, then locates the actual
consumer in finalized history. It searches backwards from the finalized head and
uses binary search within that interval, so recent replacements do not require
state from halfway back to genesis. The RPC must support historical account
nonces and canonical block-hash queries (EIP-1898); older journals may require an
archive endpoint. Arbitrum system transaction types are tolerated during scans.
An unexplained nonce advance, including an EIP-7702 authorization, stays unresolved.

The stored `SignedPayment` format is unchanged. A successful same-intent fee bump
returns the replacement's receipt and transaction hash, preventing another charge.
Merkle events are decoded directly from that receipt.

## Consumer migration

Exhaustive matches on `PaymentStatus` must handle `Finalizing` and `Replaced`.
Keep pending journals on `Finalizing` and every observation error. Only clear a
failed attempt after `Reverted` or a verified `Replaced` result. Do not assume a
recovered receipt's transaction hash is the original signed hash: a fee
replacement may have settled the same payment.
