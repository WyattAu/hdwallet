#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Multi-chain HD wallet — BIP32/39/44 derivation with BTC, ETH, SOL, TRON address generation.

/// Bitcoin address derivation.
pub mod btc;
/// BIP44 derivation path support.
pub mod derivation;
/// Error types.
pub mod error;
/// Ethereum address derivation.
pub mod eth;
/// BIP39 mnemonic support.
pub mod mnemonic;
/// Solana address derivation.
pub mod sol;
/// Tron address derivation.
pub mod tron;

pub use error::WalletError;
pub use mnemonic::{generate_mnemonic, MnemonicConfig};
pub use derivation::DerivationPath;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Supported cryptocurrencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Coin {
    /// Bitcoin (BTC).
    Bitcoin,
    /// Ethereum (ETH).
    Ethereum,
    /// Solana (SOL).
    Solana,
    /// Tron (TRX).
    Tron,
}

/// BIP-44 coin types (SLIP-44).
pub const BTC_COIN_TYPE: u32 = 0;
/// BIP-44 coin types (SLIP-44).
pub const ETH_COIN_TYPE: u32 = 60;
/// BIP-44 coin types (SLIP-44).
pub const SOL_COIN_TYPE: u32 = 501;
/// BIP-44 coin types (SLIP-44).
pub const TRON_COIN_TYPE: u32 = 195;

/// HD wallet supporting BIP32/39/44 multi-chain derivation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HdWallet {
    seed: [u8; 64],
}

impl HdWallet {
    /// Create a wallet from a BIP39 mnemonic phrase and optional passphrase.
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, WalletError> {
        let seed = mnemonic::mnemonic_to_seed(phrase, passphrase)?;
        Ok(Self { seed })
    }

    /// Generate a fresh BIP39 mnemonic with the given word count (12, 15, 18, 21, or 24).
    pub fn generate(word_count: u8) -> Result<String, WalletError> {
        mnemonic::generate_mnemonic(word_count)
    }

    /// Derive an address for the given coin type at account 0, index 0.
    pub fn derive_address(&self, coin: Coin) -> Result<String, WalletError> {
        self.derive_address_at(coin, 0, 0)
    }

    /// Derive an address for the given coin type at a specific account and index.
    pub fn derive_address_at(&self, coin: Coin, account: u32, index: u32) -> Result<String, WalletError> {
        match coin {
            Coin::Bitcoin => btc::derive_btc_address(&self.seed, account, index),
            Coin::Ethereum => eth::derive_eth_address(&self.seed, account, index),
            Coin::Solana => sol::derive_sol_address(&self.seed, account, index),
            Coin::Tron => tron::derive_tron_address(&self.seed, account, index),
        }
    }

    /// Derive an address using a custom BIP44 path string.
    pub fn derive_address_path(&self, coin: Coin, path: &str) -> Result<String, WalletError> {
        let _ = (coin, path);
        Err(WalletError::UnsupportedCoin(
            "custom path derivation not yet implemented".into(),
        ))
    }

    /// Get a reference to the raw 64-byte seed.
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_address_generation() {
        // Generate a 24-word mnemonic and derive BTC address
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let addr = wallet.derive_address(Coin::Bitcoin).unwrap();
        assert!(addr.starts_with("bc1q"));
    }

    #[test]
    fn eth_address_generation() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let addr = wallet.derive_address(Coin::Ethereum).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }

    #[test]
    fn sol_address_generation() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let addr = wallet.derive_address(Coin::Solana).unwrap();
        assert!(!addr.is_empty());
    }

    #[test]
    fn tron_address_generation() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let addr = wallet.derive_address(Coin::Tron).unwrap();
        assert!(!addr.is_empty());
    }

    #[test]
    fn generate_and_derive_all() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let btc = wallet.derive_address(Coin::Bitcoin).unwrap();
        let eth = wallet.derive_address(Coin::Ethereum).unwrap();
        let sol = wallet.derive_address(Coin::Solana).unwrap();
        let tron = wallet.derive_address(Coin::Tron).unwrap();

        assert!(btc.starts_with("bc1q"));
        assert!(eth.starts_with("0x"));
        assert!(!sol.is_empty());
        assert!(!tron.is_empty());
    }

    #[test]
    fn deterministic_derivation() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet1 = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let wallet2 = HdWallet::from_mnemonic(&phrase, "").unwrap();
        assert_eq!(wallet1.derive_address(Coin::Bitcoin).unwrap(), wallet2.derive_address(Coin::Bitcoin).unwrap());
        assert_eq!(wallet1.derive_address(Coin::Ethereum).unwrap(), wallet2.derive_address(Coin::Ethereum).unwrap());
        assert_eq!(wallet1.derive_address(Coin::Solana).unwrap(), wallet2.derive_address(Coin::Solana).unwrap());
        assert_eq!(wallet1.derive_address(Coin::Tron).unwrap(), wallet2.derive_address(Coin::Tron).unwrap());
    }

    #[test]
    fn different_accounts_different_addresses() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let addr0 = wallet.derive_address_at(Coin::Ethereum, 0, 0).unwrap();
        let addr1 = wallet.derive_address_at(Coin::Ethereum, 0, 1).unwrap();
        assert_ne!(addr0, addr1);
    }

    #[test]
    fn different_passphrases_different_seeds() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet1 = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let wallet2 = HdWallet::from_mnemonic(&phrase, "passphrase").unwrap();
        assert_ne!(wallet1.seed(), wallet2.seed());
    }
}
