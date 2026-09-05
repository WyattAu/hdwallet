#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Multi-chain HD wallet — BIP32/39/44 derivation with BTC, ETH, SOL, TRON address generation.

/// Bitcoin address derivation and signing.
pub mod btc;
/// BIP44 derivation path support.
pub mod derivation;
/// Error types.
pub mod error;
/// Ethereum address derivation and signing.
pub mod eth;
/// BIP39 mnemonic support.
pub mod mnemonic;
/// Signature and key types.
pub mod signing;
/// Solana address derivation and signing.
pub mod sol;
/// Tron address derivation and signing.
pub mod tron;

pub use error::WalletError;
pub use mnemonic::{MnemonicConfig, generate_mnemonic};
pub use signing::{DerivedPrivateKey, Ed25519Signature, Secp256k1Signature};

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
    pub fn derive_address_at(
        &self,
        coin: Coin,
        account: u32,
        index: u32,
    ) -> Result<String, WalletError> {
        match coin {
            Coin::Bitcoin => btc::derive_btc_address(&self.seed, account, index),
            Coin::Ethereum => eth::derive_eth_address(&self.seed, account, index),
            Coin::Solana => sol::derive_sol_address(&self.seed, account, index),
            Coin::Tron => tron::derive_tron_address(&self.seed, account, index),
        }
    }

    /// Get a reference to the raw 64-byte seed.
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    /// Derive a private key for the given coin type.
    ///
    /// For BTC/ETH/TRON, returns `secp256k1_secret`.
    /// For SOL, returns `ed25519_secret`.
    pub fn derive_private_key(
        &self,
        coin: Coin,
        account: u32,
        index: u32,
    ) -> Result<DerivedPrivateKey, WalletError> {
        match coin {
            Coin::Bitcoin => {
                let xprv = btc::derive_btc_signing_key(&self.seed, account, index)?;
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&xprv.to_bytes());
                Ok(DerivedPrivateKey {
                    secp256k1_secret: Some(secret),
                    ed25519_secret: None,
                })
            }
            Coin::Ethereum => {
                let xprv = eth::derive_eth_signing_key(&self.seed, account, index)?;
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&xprv.to_bytes());
                Ok(DerivedPrivateKey {
                    secp256k1_secret: Some(secret),
                    ed25519_secret: None,
                })
            }
            Coin::Solana => {
                let signing_key = sol::derive_sol_signing_key(&self.seed, account, index)?;
                Ok(DerivedPrivateKey {
                    secp256k1_secret: None,
                    ed25519_secret: Some(signing_key.to_bytes()),
                })
            }
            Coin::Tron => {
                let xprv = tron::derive_tron_signing_key(&self.seed, account, index)?;
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&xprv.to_bytes());
                Ok(DerivedPrivateKey {
                    secp256k1_secret: Some(secret),
                    ed25519_secret: None,
                })
            }
        }
    }

    /// Sign a 32-byte message hash (for BTC, ETH, TRON).
    ///
    /// Uses recoverable ECDSA. For ETH, `v` is 27/28. For BTC/TRON, `v` is 0/1.
    pub fn sign_message(
        &self,
        coin: Coin,
        account: u32,
        index: u32,
        message: &[u8],
    ) -> Result<Secp256k1Signature, WalletError> {
        let msg_hash: [u8; 32] = if message.len() == 32 {
            let mut h = [0u8; 32];
            h.copy_from_slice(message);
            h
        } else {
            // Hash the message if it's not already 32 bytes
            use sha2::{Digest, Sha256};
            Sha256::digest(message).into()
        };

        match coin {
            Coin::Bitcoin => btc::sign_btc(&self.seed, account, index, &msg_hash),
            Coin::Ethereum => eth::sign_eth(&self.seed, account, index, &msg_hash),
            Coin::Tron => tron::sign_tron(&self.seed, account, index, &msg_hash),
            Coin::Solana => Err(WalletError::SigningFailed(
                "use sign_message_ed25519 for Solana".into(),
            )),
        }
    }

    /// Sign a message with Ed25519 (for SOL).
    pub fn sign_message_ed25519(
        &self,
        account: u32,
        index: u32,
        message: &[u8],
    ) -> Result<Ed25519Signature, WalletError> {
        sol::sign_sol(&self.seed, account, index, message)
    }
}

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations
// surface as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use sha3::Keccak256;

    #[test]
    fn btc_address_generation() {
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
        assert_eq!(
            wallet1.derive_address(Coin::Bitcoin).unwrap(),
            wallet2.derive_address(Coin::Bitcoin).unwrap()
        );
        assert_eq!(
            wallet1.derive_address(Coin::Ethereum).unwrap(),
            wallet2.derive_address(Coin::Ethereum).unwrap()
        );
        assert_eq!(
            wallet1.derive_address(Coin::Solana).unwrap(),
            wallet2.derive_address(Coin::Solana).unwrap()
        );
        assert_eq!(
            wallet1.derive_address(Coin::Tron).unwrap(),
            wallet2.derive_address(Coin::Tron).unwrap()
        );
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

    #[test]
    fn btc_sign_message() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let msg_hash = Sha256::digest(b"hello");
        let sig = wallet.sign_message(Coin::Bitcoin, 0, 0, &msg_hash).unwrap();
        assert!(sig.v <= 1);
    }

    #[test]
    fn eth_sign_message() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let msg_hash = Keccak256::digest(b"hello");
        let sig = wallet
            .sign_message(Coin::Ethereum, 0, 0, &msg_hash)
            .unwrap();
        assert!(sig.v == 27 || sig.v == 28);
    }

    #[test]
    fn sol_sign_message() {
        use ed25519_dalek::Verifier;
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let sig = wallet.sign_message_ed25519(0, 0, b"hello").unwrap();
        assert_eq!(sig.bytes.len(), 64);

        let signing_key = sol::derive_sol_signing_key(wallet.seed(), 0, 0).unwrap();
        let verifying_key = signing_key.verifying_key();
        let ed25519_sig = ed25519_dalek::Signature::from_bytes(&sig.bytes);
        assert!(verifying_key.verify(b"hello", &ed25519_sig).is_ok());
    }

    #[test]
    fn derive_private_key_returns_correct_curve() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();

        let btc_key = wallet.derive_private_key(Coin::Bitcoin, 0, 0).unwrap();
        assert!(btc_key.secp256k1_secret.is_some());
        assert!(btc_key.ed25519_secret.is_none());

        let eth_key = wallet.derive_private_key(Coin::Ethereum, 0, 0).unwrap();
        assert!(eth_key.secp256k1_secret.is_some());
        assert!(eth_key.ed25519_secret.is_none());

        let sol_key = wallet.derive_private_key(Coin::Solana, 0, 0).unwrap();
        assert!(sol_key.secp256k1_secret.is_none());
        assert!(sol_key.ed25519_secret.is_some());

        let tron_key = wallet.derive_private_key(Coin::Tron, 0, 0).unwrap();
        assert!(tron_key.secp256k1_secret.is_some());
        assert!(tron_key.ed25519_secret.is_none());
    }

    #[test]
    fn sign_sol_message_wrong_coin() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let result = wallet.sign_message(Coin::Solana, 0, 0, b"hello");
        assert!(result.is_err());
    }
}
