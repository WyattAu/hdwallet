# Requirements: multi-chain-wallet (hdwallet)
| REQ-HD-103 | Derivation matches the public BIP39/BIP44 test vectors; a wallet derived from the canonical "abandon…about" mnemonic produces the canonical ETH address at `m/44'/60'/0'/0/0` | MUST |
| REQ-HD-200 | Derivation at extreme account/index values (0 and `u32::MAX`) succeeds or errors gracefully; never panics | MUST |
  callers that need it; the crate cannot revoke that exposure; documented.
| REQ-HD-003 | `btc_address_generation`, `eth_address_generation`, `sol_address_generation`, `tron_address_generation` (`src/lib.rs`); `btc_address_starts_with_bc1q`, `eth_address_format` (`tests/proptest.rs`); `canonical_bip39_44_test_vector` (`src/lib.rs`); **gap test added** | unit |
| REQ-HD-006 | `btc_sign_message`, `eth_sign_message`, `sol_sign_message`, `sign_message_hashes_non_32_byte_input` (`src/lib.rs`; latter **gap test added**) | unit |
| REQ-HD-101 | `secp256k1_signature_verifies` (`src/lib.rs`); **gap test added** (ETH recover + BTC verify) | unit |
| REQ-HD-103 | `canonical_bip39_44_test_vector` (`src/lib.rs`); **gap test added** | unit |
| REQ-HD-104 | `wallet_types_are_zeroize_on_drop` (`src/lib.rs`); **gap test added** (compile-time trait proof) | unit/design |
| REQ-HD-105 | Structural: no `Debug`/`Display` derives on `HdWallet`/`DerivedPrivateKey` (`src/lib.rs`, `src/signing.rs`); audited | design |
| REQ-HD-200 | `derivation_survives_extreme_indices` (`src/lib.rs`); **gap test added** | unit |