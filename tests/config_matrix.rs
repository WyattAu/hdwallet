//! Config-knob behavior matrix for hdwallet (crate `multi-chain-wallet`).
//!
//! Every public tuning knob must OBSERVABLY change behavior:
//!
//! * `word_count` (`MnemonicConfig` / `generate_mnemonic` /
//!   `HdWallet::generate`) — 24 yields a 24-word phrase; any other count
//!   is rejected. This is the regression test for the dead-knob incident:
//!   12/15/18/21 used to validate `Ok` and then silently mint 24 words
//!   (the `bip32` backend only supports 32-byte entropy), so the knob was
//!   settable-but-never-read.
//! * `passphrase` (`mnemonic_to_seed` / `HdWallet::from_mnemonic`) —
//!   different passphrases derive different seeds.
//! * `coin` / `account` / `index` (`derive_address_at`,
//!   `derive_private_key`) — each changes the derived output.
//!
//! Fast/deterministic: no network; generation randomness is only ever
//! asserted on word counts, never on values.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use multi_chain_wallet::{Coin, HdWallet, MnemonicConfig, generate_mnemonic};

/// Backend parses 24-word phrases (fixed 32-byte entropy); this is the
/// repo's own test phrase (see `tests/transaction_signing.rs`).
const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn wallet() -> HdWallet {
    HdWallet::from_mnemonic(TEST_PHRASE, "").unwrap()
}

// --- word_count knob (was DEAD for 12/15/18/21) ------------------------------

#[test]
fn word_count_24_mints_24_words() {
    let phrase = generate_mnemonic(24).unwrap();
    assert_eq!(phrase.split_whitespace().count(), 24);
    assert_eq!(
        HdWallet::generate(24).unwrap().split_whitespace().count(),
        24
    );
}

#[test]
fn word_count_non_24_is_rejected_instead_of_silently_minting_24() {
    // BIP39-valid counts the backend cannot generate: must be Err, never
    // a silent 24-word phrase.
    for count in [12u8, 15, 18, 21] {
        assert!(MnemonicConfig::new(count).is_ok());
        assert!(
            generate_mnemonic(count).is_err(),
            "generate({count}) must fail loudly, not mint 24 words"
        );
        assert!(
            HdWallet::generate(count).is_err(),
            "HdWallet::generate({count}) must fail loudly"
        );
    }
}

#[test]
fn word_count_invalid_counts_rejected() {
    for count in [0u8, 11, 13, 23, 25, 100] {
        assert!(MnemonicConfig::new(count).is_err());
        assert!(generate_mnemonic(count).is_err());
    }
}

// --- passphrase knob ----------------------------------------------------------

#[test]
fn passphrase_changes_the_derived_seed() {
    let plain = HdWallet::from_mnemonic(TEST_PHRASE, "").unwrap();
    let with_pass = HdWallet::from_mnemonic(TEST_PHRASE, "TREZOR").unwrap();
    assert_ne!(plain.seed(), with_pass.seed());
    // Same inputs → same seed (deterministic).
    assert_eq!(
        plain.seed(),
        HdWallet::from_mnemonic(TEST_PHRASE, "").unwrap().seed()
    );
}

// --- coin / account / index knobs ----------------------------------------------

#[test]
fn coin_changes_the_derived_address() {
    let wallet = wallet();
    let btc = wallet.derive_address(Coin::Bitcoin).unwrap();
    let eth = wallet.derive_address(Coin::Ethereum).unwrap();
    let sol = wallet.derive_address(Coin::Solana).unwrap();
    let tron = wallet.derive_address(Coin::Tron).unwrap();
    assert_ne!(btc, eth);
    assert_ne!(btc, sol);
    assert_ne!(btc, tron);
    assert_ne!(eth, sol);
    assert_ne!(sol, tron);
}

#[test]
fn account_and_index_change_the_derived_address() {
    let wallet = wallet();
    let base = wallet.derive_address_at(Coin::Bitcoin, 0, 0).unwrap();
    assert_ne!(base, wallet.derive_address_at(Coin::Bitcoin, 1, 0).unwrap());
    assert_ne!(base, wallet.derive_address_at(Coin::Bitcoin, 0, 1).unwrap());
    // Same coordinates → same address.
    assert_eq!(base, wallet.derive_address_at(Coin::Bitcoin, 0, 0).unwrap());
}

#[test]
fn account_and_index_change_the_derived_private_key() {
    let wallet = wallet();
    let key = |account, index| {
        wallet
            .derive_private_key(Coin::Ethereum, account, index)
            .unwrap()
            .secp256k1_secret
            .unwrap()
    };
    assert_ne!(key(0, 0), key(1, 0));
    assert_ne!(key(0, 0), key(0, 1));
    assert_eq!(key(0, 0), key(0, 0));
}
