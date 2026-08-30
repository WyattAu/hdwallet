pub mod btc;
pub mod derivation;
pub mod error;
pub mod eth;
pub mod mnemonic;
pub mod sol;

pub use error::WalletError;

/// Supported blockchain networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Coin {
    Bitcoin,
    Ethereum,
    Solana,
    Tron,
    Liquid,
}

/// HD wallet supporting BIP32/39/44 multi-chain derivation.
pub struct HdWallet {
    seed: [u8; 64],
}

impl HdWallet {
    /// Create a wallet from a BIP39 mnemonic phrase.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, WalletError> {
        let seed = mnemonic::mnemonic_to_seed(phrase)?;
        Ok(Self { seed })
    }

    /// Generate a fresh 24-word BIP39 mnemonic.
    pub fn generate_mnemonic() -> Result<String, WalletError> {
        mnemonic::generate_mnemonic()
    }

    /// Derive an address for the given coin type.
    pub fn derive_address(&self, coin: Coin) -> Result<String, WalletError> {
        match coin {
            Coin::Bitcoin => btc::derive_address(&self.seed),
            Coin::Ethereum => eth::derive_address(&self.seed),
            Coin::Solana => sol::derive_address(&self.seed),
            Coin::Tron => Err(WalletError::UnsupportedCoin("TRON".into())),
            Coin::Liquid => Err(WalletError::UnsupportedCoin("Liquid".into())),
        }
    }

    /// Derive an address using a custom BIP44 path.
    pub fn derive_address_path(&self, coin: Coin, path: &str) -> Result<String, WalletError> {
        let _ = (coin, path);
        Err(WalletError::UnsupportedCoin(
            "custom path derivation not yet implemented".into(),
        ))
    }

    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }
}
