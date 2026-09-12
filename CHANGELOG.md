# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.2.1] - 2026-09-12

### Fixed
- **Dead knob: `word_count` accepted 12/15/18/21 but silently minted 24
  words.** `MnemonicConfig::new` validated those counts `Ok`, then
  `generate_mnemonic` ignored the value (`bip32` entropy is fixed at 32
  bytes). `generate_mnemonic` / `HdWallet::generate` now reject any
  non-24 count with `WalletError::InvalidMnemonic` — matching the
  long-documented contract ("Other word counts will return
  `InvalidMnemonic` at generation/parsing time"), which the code never
  implemented.

### Added
- `tests/config_matrix.rs`: every tuning knob behavior-proven —
  `word_count` (24 mints 24 words; 12/15/18/21 and invalid counts
  rejected), `passphrase` (different passphrases → different seeds),
  `coin` / `account` / `index` (each changes derived addresses and
  private keys). Dead-knob sweep found one dead knob (`word_count`,
  fixed above).

## [0.2.0] - 2026-09-11

### Fixed

- 22-gate quality audit pass: documentation completeness
  (README badges, REQUIREMENTS/THREAT-MODEL coverage) and
  feature-gated test hygiene.

## [0.1.0] - 2026-09-01

### Added

- BIP39 mnemonic generation (24-word phrases) and seed derivation.
- BIP44 derivation path support per coin.
- Multi-chain address/keys: Bitcoin, Ethereum, Solana, Tron.
- Pure Rust, `#![forbid(unsafe_code)]`.
