# Pattern adoption

BIP-32/39/44 HD wallet for BTC, ETH, SOL, TRON.

| Pattern | Status | Evidence |
|---|---|---|
| P4 | partial | src/lib.rs:34 (zeroize and ZeroizeOnDrop on the BIP39 seed and derived keys, asserted at src/lib.rs:459; no redacted-Debug wrapper) |
| P64 | adopted | tests/proptest.rs:29 (mnemonic word-count properties; regressions in tests/proptest.proptest-regressions) |
| P65 | adopted | src/bip32_vectors.rs:1 (BIP-32 specification vectors verbatim, including the must-reject vector 5, run by tests/bip32_conformance.rs) |
