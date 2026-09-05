# Threat Model — multi-chain-wallet

Status: **v1.0** · Method: STRIDE over the public API surface
(`HdWallet::from_mnemonic`/`generate`/`derive_address_at`/
`derive_private_key`/`sign_message*`, `mnemonic` module, per-coin
`btc`/`eth`/`sol`/`tron` modules).

Trust boundaries: (1) the mnemonic phrase and passphrase strings supplied by
the caller, (2) process memory holding the 64-byte BIP39 seed and derived
private keys, (3) the `bip32`/`k256`/`ed25519-dalek` dependency tree.
The seed is the root of all funds — everything downstream is a derivative.

## Assets

| ID | Asset | Example |
|----|-------|---------|
| A1 | The 64-byte BIP39 seed (master key for all chains) | Single leak drains every derived account |
| A2 | Derived private keys (`DerivedPrivateKey`) | Per-account key exfiltration |
| A3 | Mnemonic phrase | Equivalent to A1 at rest |
| A4 | Signature validity | Malleable or non-canonical signatures |
| A5 | Address derivation correctness | Cross-chain collision / wrong-coin derivation |

## STRIDE Analysis

| # | Threat | Category | Surface | Mitigation | Verifying test |
|----|--------|----------|---------|------------|----------------|
| T1 | Mnemonic seed drift (BIP32/39 implementation bugs) | Tampering | `mnemonic_to_seed` | Delegated to the `bip32` crate (`Mnemonic::new` + `to_seed`), checksum validation on parse | `src/mnemonic.rs::generate_and_roundtrip`, `tests/proptest.rs::deterministic_derivation_from_mnemonic`, `different_passphrases_different_seeds` |
| T2 | Seed/key disclosure via `Debug` or `Display` | Info disclosure | `HdWallet`, `DerivedPrivateKey` | `HdWallet` and `DerivedPrivateKey` are `#[derive(Zeroize, ZeroizeOnDrop)]` with **no** `Debug`/`Display` derive; signatures (public) are `Debug` | absence verified structurally: `src/lib.rs:53`, `src/signing.rs:22`; no `debug_does_not_leak` test exists (see OPEN-2) |
| T3 | Residual key material after drop | Info disclosure | `HdWallet`, `DerivedPrivateKey` | `ZeroizeOnDrop` scrubs seed and derived key buffers | derive-level guarantee (`src/lib.rs`, `src/signing.rs`); no byte-level assertion possible without `unsafe` (crate forbids it) |
| T4 | Weak entropy at generation | Spoofing | `generate_mnemonic` | `bip32::Mnemonic::random(OsRng, Language::English)` — OS CSPRNG | `tests/proptest.rs::generate_mnemonic_always_24_words`, `mnemonic_words_are_alphanumeric` |
| T5 | Invalid word count / malformed phrase accepted | Elevation | `MnemonicConfig::new`, `mnemonic_to_seed` | Word count validated against {12,15,18,21,24}; phrase parse is checksum-verified | `src/mnemonic.rs::invalid_word_count`; `WalletError::InvalidMnemonic` path |
| T6 | Non-canonical / failing signatures | Tampering | `sign_btc`/`sign_eth`/`sign_tron`/`sign_sol` | `k256` (RFC 6979 deterministic nonce) and `ed25519-dalek` signing | `src/btc.rs::btc_sign_and_verify`, `tests/proptest.rs` (8 property tests incl. derivation determinism) |
| T7 | Wrong derivation path (cross-chain confusion) | Elevation | `derive_*` | BIP44 paths pinned per coin via SLIP-44 constants (BTC 0, ETH 60, SOL 501, TRON 195); account/index caller-supplied | `tests/proptest.rs::coin_type_constants`, `btc_address_starts_with_bc1q`, `eth_address_format`, `different_indices_different_addresses` |
| T8 | Passphrase choice changes seeds silently | Spoofing | `from_mnemonic` | BIP39 passphrase semantics (empty string default) | `tests/proptest.rs::different_passphrases_different_seeds` |

## OPEN RISKS (missing mitigations — not fabricated)

- **OPEN-1 — `word_count` parameter is accepted then ignored.**
  `MnemonicConfig::new` admits 12/15/18/21/24, but `generate_mnemonic`
  always produces 24 words (`bip32` crate limitation, documented in the
  module docs and pinned by `generate_mnemonic_always_24_words`). A caller
  asking for 12 words cannot detect the substitution except by counting.
- **OPEN-2 — no negative test asserts seed/key absence from `Debug` output.**
  The mitigation in T2 is "no derive exists"; nothing prevents a future
  derive from silently reintroducing the leak. A `format!("{:?}")` regression
  test (as in webauthn-kit) is missing.
- **OPEN-3 — `HdWallet::seed()` returns a live reference to the master
  seed.** Deliberate API (per-coin modules take `&[u8; 64]`), but any caller
  can copy A1 out and bypass all zeroization guarantees.
- **OPEN-4 — mnemonic/passphrase are plain `&str`.** No zeroize of the
  caller-owned phrase; copies may persist in caller memory/logs.
- **OPEN-5 — English wordlist only** (`Language::English`); non-English BIP39
  phrases are rejected as invalid (fail-closed, but an interop surprise).

## Out of Scope

- Transaction construction/broadcast (signing operates on hashes/bytes).
- Hardware wallets, HSMs, secure enclaves — pure-software key custody.
- Slippage/amount logic anywhere in the signing pipeline.

## Residual Risks

- Single mnemonic = single point of failure across all four chains; the
  crate cannot compartmentalize A1 per coin.
- `sign_message` hashes non-32-byte messages with SHA-256 — callers signing
  already-hashed 32-byte messages must pass them raw to avoid double
  hashing (documented in the API shape, easy to misuse).
