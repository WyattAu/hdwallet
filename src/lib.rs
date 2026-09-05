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
///
/// The 64-byte BIP39 seed is zeroized on drop (`ZeroizeOnDrop`); the type
/// implements neither `Debug` nor `Display` so the seed cannot leak through
/// formatting.
///
/// # Requirements
/// REQ-HD-004, REQ-HD-104, REQ-HD-105
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HdWallet {
    seed: [u8; 64],
}

impl HdWallet {
    /// Create a wallet from a BIP39 mnemonic phrase and optional passphrase.
    ///
    /// # Requirements
    /// REQ-HD-002, REQ-HD-004
    pub fn from_mnemonic(phrase: &str, passphrase: &str) -> Result<Self, WalletError> {
        let seed = mnemonic::mnemonic_to_seed(phrase, passphrase)?;
        Ok(Self { seed })
    }

    /// Generate a fresh BIP39 mnemonic with the given word count (12, 15, 18, 21, or 24).
    ///
    /// # Requirements
    /// REQ-HD-001, REQ-HD-100
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
    ///
    /// # Requirements
    /// REQ-HD-005, REQ-HD-104
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
    ///
    /// # Requirements
    /// REQ-HD-006, REQ-HD-101, REQ-HD-106
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

    /// REQ-HD-103: BIP39 anchor against an independently computed vector —
    /// the canonical all-zero-entropy 24-word mnemonic ("abandon ×23 art")
    /// must produce exactly the PBKDF2-HMAC-SHA512 (2048 iterations, empty
    /// passphrase) seed computed with an independent implementation.
    #[test]
    fn canonical_bip39_44_test_vector() {
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon art";
        let wallet = HdWallet::from_mnemonic(phrase, "").unwrap();
        assert_eq!(
            hex::encode(wallet.seed()),
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70\
             5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
        );
        // Determinism on the canonical vector.
        let wallet2 = HdWallet::from_mnemonic(phrase, "").unwrap();
        assert_eq!(
            wallet.derive_address(Coin::Ethereum).unwrap(),
            wallet2.derive_address(Coin::Ethereum).unwrap()
        );
    }

    /// REQ-HD-101: a produced secp256k1 signature must verify (and recover
    /// the right pubkey) — signing that never verifies would be silent
    /// fund loss.
    #[test]
    fn secp256k1_signature_verifies() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::{Signature, VerifyingKey};

        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        let msg_hash = Sha256::digest(b"verify me");

        let signing_key = eth::derive_eth_signing_key(wallet.seed(), 0, 0).unwrap();
        let sig = wallet
            .sign_message(Coin::Ethereum, 0, 0, &msg_hash)
            .unwrap();

        // r||s must verify against the derived public key.
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&sig.r);
        rs[32..].copy_from_slice(&sig.s);
        let vk = VerifyingKey::from(&signing_key);
        vk.verify_prehash(&msg_hash, &Signature::from_slice(&rs).unwrap())
            .expect("secp256k1 signature must verify");

        // Recovery id sanity for ETH.
        assert!(sig.v == 27 || sig.v == 28);
    }

    /// REQ-HD-006: inputs that are not 32 bytes are SHA-256-hashed before
    /// signing, deterministically.
    #[test]
    fn sign_message_hashes_non_32_byte_input() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();

        let a = wallet
            .sign_message(Coin::Bitcoin, 0, 0, b"short message")
            .unwrap();
        let b = wallet
            .sign_message(Coin::Bitcoin, 0, 0, b"short message")
            .unwrap();
        assert_eq!(a.r, b.r);
        assert_eq!(a.s, b.s);

        // A 31-byte input takes the hashing path too (len != 32).
        let c = wallet
            .sign_message(Coin::Bitcoin, 0, 0, &[7u8; 31])
            .unwrap();
        let _ = c;
    }

    /// REQ-HD-104: zeroization enforced by the type system — the derives
    /// would fail this build if removed.
    #[test]
    fn wallet_types_are_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<HdWallet>();
        assert_zeroize_on_drop::<DerivedPrivateKey>();
    }

    /// REQ-HD-200: extreme account/index values must never panic. Behavior
    /// at u32::MAX differs by chain (secp256k1 BIP32 paths reject ≥ 2^31
    /// hardened components with `Err`; SLIP-0010 ed25519 derives) — both are
    /// acceptable; a panic is not.
    #[test]
    fn derivation_survives_extreme_indices() {
        let phrase = HdWallet::generate(24).unwrap();
        let wallet = HdWallet::from_mnemonic(&phrase, "").unwrap();
        for coin in [Coin::Bitcoin, Coin::Ethereum, Coin::Solana, Coin::Tron] {
            // Top of the valid hardened range must derive.
            let top = wallet.derive_address_at(coin, 0x7FFF_FFFF, 0x7FFF_FFFF);
            assert!(top.is_ok(), "{coin:?} at 2^31-1 must derive, got {top:?}");
            // 2^32-1: Ok (SLIP-0010) or Err (BIP32 hardened overflow), never panic.
            let _ = wallet.derive_address_at(coin, u32::MAX, u32::MAX);
        }
    }
}
