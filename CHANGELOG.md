# Changelog

## 0.9.0

- **ADR-0004 (commitment-bound quote pricing):** add signed commitment-binding
  fields — `committed_key_count: u32` and `commitment_pin: Option<[u8; 32]>` — to
  `PaymentQuote` and `MerklePaymentCandidateNode`. The fields are covered by
  `bytes_for_signing` (single-node) / `bytes_to_sign` (merkle) and therefore by
  the quote hash. **Breaking wire/signature change** (a v0.8.x quote's signature
  no longer verifies on v0.9.0 and vice-versa); the fleet and clients must
  upgrade together.
