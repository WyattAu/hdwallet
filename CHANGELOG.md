# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.2.2] - 2026-10-05

### Fixed
- **Every BIP-39 phrase shorter than 24 words was rejected, so most recovery
  phrases could not restore a wallet.** `mnemonic_to_seed` delegated to
  `bip32 0.5.3`'s `bip39` feature, whose `Mnemonic::new` requires
  `entropy.len() == KEY_SIZE + 1` with `KEY_SIZE = 32` — that is, exactly 33
  bytes, that is, exactly 24 words. Anything shorter returned `Err(Bip39)`:
  the two canonical 12-word vectors in the BIP-39 specification are both
  refused, and so is any phrase from an 12/15/18/21-word generator or import.
  Verified in this repo's own dependency graph: 24 words parses, 12 and 18 do
  not.

  Parsing now goes through `bip39` directly, which validates every published
  vector correctly; `bip32` is retained for the BIP-32 derivation arithmetic
  that follows, which never touched a phrase. The crate's tests previously
  missed this because they only ever round-tripped phrases the crate itself
  had generated — all of which were 24 words, because generation could only
  make 24.

  Consequence for callers: `mnemonic_to_seed` now accepts a standard phrase,
  so a wallet restored from paper or a password manager works.

- **Generation was 24 words only**, where BIP-39 permits 12, 15, 18, 21 and 24.
  `generate_mnemonic` accepted those counts from `MnemonicConfig` and then
  rejected them, and `0.2.1` hardened that rejection rather than the cause.
  All five lengths are now generated, at exactly the requested length.

### Added
- Regression tests over the BIP-39 specification's own vectors, including the
  seed value for vector 1 with the `TREZOR` passphrase, so the checksum and the
  PBKDF2 derivation are both pinned against the specification rather than
  against this crate.
- A negative test that a phrase whose checksum does not match its entropy is
  refused — with a note that `zoo ... wrong`, the obvious candidate, is in fact
  a *valid* phrase (it decodes to `ff..ff` entropy), which is why it cannot be
  used to test rejection.
- The configuration matrix and property suites now assert that a requested
  word count is honoured exactly, replacing assertions that it was ignored.

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
