//! Property-based tests for multi-chain-wallet crate.

// Property tests exercise malformed inputs directly; unwrap/expect, slicing,
// and panicking asserts are the test signal here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use proptest::prelude::*;

use multi_chain_wallet::{Coin, HdWallet};

/// The word counts BIP-39 defines.
const VALID_WORD_COUNTS: [u8; 5] = [12, 15, 18, 21, 24];
const WORD_24: u8 = 24;

fn is_bip39_word_count(count: u8) -> bool {
    VALID_WORD_COUNTS.contains(&count)
}

#[test]
fn a_generated_phrase_has_exactly_the_requested_word_count() {
    // The property this suite used to assert the *absence* of: that any count
    // quietly became 24 words. A request is a request — a caller asking for 12
    // words gets 12, and a length BIP-39 does not define is refused.
    proptest!(|(word_count in 8u8..=28u8)| {
        let result = HdWallet::generate(word_count);
        match result {
            Ok(phrase) => {
                let words: Vec<&str> = phrase.split_whitespace().collect();
                prop_assert_eq!(words.len(), word_count as usize);
                prop_assert!(is_bip39_word_count(words.len() as u8));
            }
            Err(_) => prop_assert!(!is_bip39_word_count(word_count)),
        }
    });
}

#[test]
fn mnemonic_words_are_alphanumeric() {
    let phrase = HdWallet::generate(WORD_24).unwrap();
    for word in phrase.split_whitespace() {
        assert!(word.chars().all(|c| c.is_ascii_lowercase()));
        assert!(word.len() >= 3);
    }
}

#[test]
fn deterministic_derivation_from_mnemonic() {
    let phrase = HdWallet::generate(WORD_24).unwrap();
    let wallet1 = HdWallet::from_mnemonic(&phrase, "").unwrap();
    let wallet2 = HdWallet::from_mnemonic(&phrase, "").unwrap();

    assert_eq!(
        wallet1.derive_address(Coin::Bitcoin).unwrap(),
        wallet2.derive_address(Coin::Bitcoin).unwrap()
    );
    assert_eq!(
        wallet1.derive_address(Coin::Ethereum).unwrap(),
        wallet2.derive_address(Coin::Ethereum).unwrap()
    );
}

#[test]
fn btc_address_starts_with_bc1q() {
    let phrase = HdWallet::generate(WORD_24).unwrap();
    let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
    let addr = wallet.derive_address(Coin::Bitcoin).unwrap();
    assert!(addr.starts_with("bc1q"));
}

#[test]
fn eth_address_format() {
    let phrase = HdWallet::generate(WORD_24).unwrap();
    let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
    let addr = wallet.derive_address(Coin::Ethereum).unwrap();
    assert!(addr.starts_with("0x"));
    assert_eq!(addr.len(), 42);
}

#[test]
fn different_passphrases_different_seeds() {
    let phrase = HdWallet::generate(WORD_24).unwrap();
    let wallet1 = HdWallet::from_mnemonic(&phrase, "").unwrap();
    let wallet2 = HdWallet::from_mnemonic(&phrase, "salt").unwrap();
    assert_ne!(wallet1.seed(), wallet2.seed());
}

#[test]
fn different_indices_different_addresses() {
    proptest!(|(
        index1 in 0u32..100u32,
        index2 in 100u32..200u32,
    )| {
        let phrase = HdWallet::generate(WORD_24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let addr1 = wallet.derive_address_at(Coin::Ethereum, 0, index1).unwrap();
        let addr2 = wallet.derive_address_at(Coin::Ethereum, 0, index2).unwrap();
        prop_assert_ne!(addr1, addr2);
    });
}

#[test]
fn coin_type_constants() {
    assert_eq!(multi_chain_wallet::BTC_COIN_TYPE, 0);
    assert_eq!(multi_chain_wallet::ETH_COIN_TYPE, 60);
    assert_eq!(multi_chain_wallet::SOL_COIN_TYPE, 501);
    assert_eq!(multi_chain_wallet::TRON_COIN_TYPE, 195);
}
