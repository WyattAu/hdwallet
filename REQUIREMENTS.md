# Requirements — multi-chain-wallet (hdwallet)

Numbered, testable requirements. Every requirement maps to at least one named
test; every security-relevant test cites at least one requirement. Doc
comments on the implementing public item carry `REQ-HD-NNN` tags.

## Functional

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-HD-001 | `HdWallet::generate(24)` produces a 24-word BIP39 English phrase; `MnemonicConfig::new` accepts only 12/15/18/21/24 | MUST |
| REQ-HD-002 | `from_mnemonic` converts a valid BIP39 phrase (+ optional passphrase) to a 64-byte BIP39 seed; an invalid phrase returns `Err(InvalidMnemonic)` | MUST |
| REQ-HD-003 | Address derivation follows the documented BIP44/84 paths: BTC `m/84'/0'/a'/0/i` (bech32 `bc1q…`), ETH `m/44'/60'/0'/0/i` (0x + 40 hex), SOL `m/44'/501'/0'/0'`, TRON `m/44'/195'/0'/0/i` | MUST |
| REQ-HD-004 | Derivation is deterministic: the same mnemonic + passphrase always yields the same addresses; different passphrases yield different seeds | MUST |
| REQ-HD-005 | `derive_private_key` returns the correct curve per coin (secp256k1 for BTC/ETH/TRON, ed25519 for SOL) | MUST |
| REQ-HD-006 | `sign_message` signs a 32-byte hash directly and SHA-256-hashes any other length; ETH recovers with `v ∈ {27,28}`, BTC/TRON with `v ∈ {0,1}`; SOL signing goes through `sign_message_ed25519` | MUST |

## Security

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-HD-100 | Mnemonic entropy comes from the OS CSPRNG (`bip32::Mnemonic::random(OsRng)`); two generated phrases differ | MUST |
| REQ-HD-101 | A produced secp256k1 signature verifies against the derived public key (recoverable ECDSA round-trip) for BTC/ETH/TRON | MUST |
| REQ-HD-102 | A produced Ed25519 signature verifies against the derived verifying key for SOL | MUST |
| REQ-HD-103 | Derivation matches the public BIP39/BIP44 test vectors — a wallet derived from the canonical "abandon…about" mnemonic produces the canonical ETH address at `m/44'/60'/0'/0/0` | MUST |
| REQ-HD-104 | `HdWallet` (seed) and `DerivedPrivateKey` (key material) are zeroized on drop, enforced by the type system (`ZeroizeOnDrop`) | MUST |
| REQ-HD-105 | Neither `HdWallet` nor `DerivedPrivateKey` implements `Debug`/`Display`, so seed or key bytes cannot leak through formatting | MUST |
| REQ-HD-106 | Signing an invalid coin/curve combination (e.g. secp256k1 sign for SOL) returns `Err`, never falls back to another key | MUST |

## Robustness

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-HD-200 | Derivation at extreme account/index values (0 and `u32::MAX`) succeeds or errors gracefully — never panics | MUST |
| REQ-HD-201 | Index isolation: different indices/accounts always produce different addresses (no collision on the tested ranges) | MUST |
| REQ-HD-202 | SLIP-44 constants match the specification (BTC 0, ETH 60, SOL 501, TRON 195) | MUST |

## Constant-Time Audit

- AUDIT: this crate has **no secret-dependent comparison** (no verify
  functions that compare secret-derived bytes); the only equality checks are
  on public addresses and non-secret test fixtures.
- AUDIT: secp256k1 signing uses `k256::ecdsa` with deterministic RFC 6979
  nonces (no RNG-dependent or secret-dependent branching); Ed25519 signing
  uses `ed25519-dalek` (constant-time scalar arithmetic). ✓
- AUDIT: mnemonic → seed is PBKDF2-HMAC-SHA512 inside the `bip32` crate.
- Note: `HdWallet::seed()` deliberately exposes the raw seed reference for
  callers that need it; the crate cannot revoke that exposure — documented.

## Traceability Matrix

| Requirement | Test (fn, file) | Property class |
|-------------|-----------------|----------------|
| REQ-HD-001 | `generate_and_roundtrip` (`src/mnemonic.rs`); `invalid_word_count`, `valid_word_counts` (`src/mnemonic.rs`); `generate_mnemonic_always_24_words` (`tests/proptest.rs`) | unit/property |
| REQ-HD-002 | `invalid_mnemonic_phrase`, `generate_and_roundtrip` (`src/mnemonic.rs`) | unit |
| REQ-HD-003 | `btc_address_generation`, `eth_address_generation`, `sol_address_generation`, `tron_address_generation` (`src/lib.rs`); `btc_address_starts_with_bc1q`, `eth_address_format` (`tests/proptest.rs`); `canonical_bip39_44_test_vector` (`src/lib.rs`) — **gap test added** | unit |
| REQ-HD-004 | `deterministic_derivation` (`src/lib.rs`); `deterministic_derivation_from_mnemonic`, `different_passphrases_different_seeds` (`tests/proptest.rs`) | unit |
| REQ-HD-005 | `derive_private_key_returns_correct_curve` (`src/lib.rs`) | unit |
| REQ-HD-006 | `btc_sign_message`, `eth_sign_message`, `sol_sign_message`, `sign_message_hashes_non_32_byte_input` (`src/lib.rs` — latter **gap test added**) | unit |
| REQ-HD-100 | `mnemonic_words_are_alphanumeric` (`tests/proptest.rs`); uniqueness via `deterministic_derivation` (two generate calls independent) | unit |
| REQ-HD-101 | `secp256k1_signature_verifies` (`src/lib.rs`) — **gap test added** (ETH recover + BTC verify) | unit |
| REQ-HD-102 | `sol_sign_message` (verifies with `ed25519-dalek`) (`src/lib.rs`) | unit |
| REQ-HD-103 | `canonical_bip39_44_test_vector` (`src/lib.rs`) — **gap test added** | unit |
| REQ-HD-104 | `wallet_types_are_zeroize_on_drop` (`src/lib.rs`) — **gap test added** (compile-time trait proof) | unit/design |
| REQ-HD-105 | Structural: no `Debug`/`Display` derives on `HdWallet`/`DerivedPrivateKey` (`src/lib.rs`, `src/signing.rs`) — audited | design |
| REQ-HD-106 | `sign_sol_message_wrong_coin` (`src/lib.rs`) | unit |
| REQ-HD-200 | `derivation_survives_extreme_indices` (`src/lib.rs`) — **gap test added** | unit |
| REQ-HD-201 | `different_accounts_different_addresses` (`src/lib.rs`); `different_indices_different_addresses` (proptest, `tests/proptest.rs`) | unit/property |
| REQ-HD-202 | `coin_type_constants` (`tests/proptest.rs`) | unit |

## Test Count Delta

- Before: 27 tests (19 unit incl. mnemonic + 8 in `tests/proptest.rs` incl. 2 proptests).
- Added: 5 (`canonical_bip39_44_test_vector`, `secp256k1_signature_verifies`, `sign_message_hashes_non_32_byte_input`, `wallet_types_are_zeroize_on_drop`, `derivation_survives_extreme_indices`).
- After: 32.
