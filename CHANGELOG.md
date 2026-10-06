# Changelog

All notable changes to this project are documented here. Format: [Keep a
Changelog](https://keepachangelog.com/) — versions follow [semver](https://semver.org).

## [Unreleased]

## [0.3.0] - 2026-10-05

Upgraded to `bip32 0.6` and `k256 0.14`, and added the BIP-32 conformance
suite that made the upgrade safe to attempt.

### Changed (breaking)

- **`bip32` 0.5 → 0.6.** Upstream 0.6.0 *removed* the `bip39` and `mnemonic`
  features rather than fixing them, so the standalone-`bip39` arrangement
  `0.2.2` introduced is now the only one available. `derive_from_path` borrows
  the seed as plain bytes instead of taking a `bip32::Seed`.
  **Derived addresses are unchanged**: all four of BIP-32's own derivation
  vectors now match the specification byte for byte under 0.6, and the crate's
  pre-existing address tests pass untouched.
- **`k256` 0.13 → 0.14**, which moves `to_encoded_point` to `to_sec1_point` and
  drops `SigningKey::sign_prehash_recoverable`.

### Added

- **The BIP-32 test vectors, verbatim from `bip-0032.mediawiki`** (vectors 1-5).
  A wallet that derives *consistently wrong* addresses round-trips perfectly, so
  round-trip tests prove nothing; only published vectors do. Vector 3 exercises
  the leading-zero handling where vectors 1 and 2 are silent.
- **Strict extended-key import — `parse_xprv` / `parse_xpub`.** Measured against
  `bip32 0.6.0`, that crate refuses twelve of vector 5's sixteen invalid keys and
  **accepts four**: both "zero depth with non-zero parent fingerprint" keys and
  both "zero depth with non-zero index" keys. Those are the depth-0 consistency
  rules — a master key has no parent and no index — so accepting them means the
  same private material has two valid encodings. That is malleability, and
  malleability is what breaks a backup check and any comparison of serialised
  keys. This crate now enforces all sixteen, plus BIP-32's rule that a public key
  may not name a hardened child, plus canonical re-serialisation.
  It also gives the crate an import path it never had: `bip32 0.5` had no
  `FromStr` at all, so a user's existing xpub could not be validated at all.
- `signing_prehash` — recoverable signing over a **prehash**, deterministic per
  RFC 6979. `k256 0.14`'s replacement for the removed method,
  `sign_digest_recoverable`, *hashes* its input; a wallet is handed a digest that
  is already hashed, so using it would sign a different message than the network
  verifies and every transaction would be rejected. Nothing would panic, and any
  test that signed a message by hashing it first would still pass. There is a
  regression test asserting the two paths differ.
- `split_signature`, returning `Option` rather than silently yielding zeroes if
  the serialised form is ever not 64 bytes.

### Fixed

- The property suite asserted that a requested word count is *ignored*; it now
  asserts it is honoured exactly. It previously encoded the 24-word limitation
  as intended behaviour, which is how a wallet shipped that could not restore a
  12-word recovery phrase with a fully green suite.

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
