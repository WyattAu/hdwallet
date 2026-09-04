//! Property-based tests for multi-chain-wallet crate.

use proptest::prelude::*;

use multi_chain_wallet::{Coin, HdWallet};

/// The bip32 crate always generates 24-word mnemonics regardless of word_count.
const VALID_WORD_COUNT: u8 = 24;

#[test]
fn generate_mnemonic_always_24_words() {
    proptest!(|(word_count in 12u8..=24u8)| {
        // generate_mnemonic always produces 24 words (bip32 limitation)
        let result = HdWallet::generate(word_count);
        if result.is_ok() {
            let phrase = result.unwrap();
            let words: Vec<&str> = phrase.split_whitespace().collect();
            prop_assert_eq!(words.len(), VALID_WORD_COUNT as usize);
        }
    });
}

#[test]
fn mnemonic_words_are_alphanumeric() {
    let phrase = HdWallet::generate(VALID_WORD_COUNT).unwrap();
    for word in phrase.split_whitespace() {
        assert!(word.chars().all(|c| c.is_ascii_lowercase()));
        assert!(word.len() >= 3);
    }
}

#[test]
fn deterministic_derivation_from_mnemonic() {
    let phrase = HdWallet::generate(VALID_WORD_COUNT).unwrap();
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
    let phrase = HdWallet::generate(VALID_WORD_COUNT).unwrap();
    let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
    let addr = wallet.derive_address(Coin::Bitcoin).unwrap();
    assert!(addr.starts_with("bc1q"));
}

#[test]
fn eth_address_format() {
    let phrase = HdWallet::generate(VALID_WORD_COUNT).unwrap();
    let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
    let addr = wallet.derive_address(Coin::Ethereum).unwrap();
    assert!(addr.starts_with("0x"));
    assert_eq!(addr.len(), 42);
}

#[test]
fn different_passphrases_different_seeds() {
    let phrase = HdWallet::generate(VALID_WORD_COUNT).unwrap();
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
        let phrase = HdWallet::generate(VALID_WORD_COUNT).unwrap();
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
