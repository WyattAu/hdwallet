use bip32::{Language, Mnemonic};
use rand_core::OsRng;

use crate::error::WalletError;

/// Configuration for mnemonic generation.
#[derive(Debug, Clone)]
pub struct MnemonicConfig {
    /// Number of words in the mnemonic (12, 15, 18, 21, or 24).
    pub word_count: u8,
}

impl MnemonicConfig {
    /// Create a new config with validated word count.
    ///
    /// **Note:** The `bip32` crate currently only supports 24-word mnemonics.
    /// Other word counts will return `InvalidMnemonic` at generation/parsing time.
    pub fn new(word_count: u8) -> Result<Self, WalletError> {
        match word_count {
            12 | 15 | 18 | 21 | 24 => Ok(Self { word_count }),
            _ => Err(WalletError::InvalidMnemonic(format!(
                "word count must be 12, 15, 18, 21, or 24, got {word_count}"
            ))),
        }
    }
}

/// Generate a random BIP39 mnemonic phrase.
///
/// **Note:** The underlying `bip32` crate currently only supports 24-word mnemonics.
pub fn generate_mnemonic(word_count: u8) -> Result<String, WalletError> {
    let _config = MnemonicConfig::new(word_count)?;
    let mnemonic = Mnemonic::random(OsRng, Language::English);
    Ok(mnemonic.phrase().to_string())
}

/// Convert a BIP39 mnemonic phrase to a 64-byte seed.
///
/// Uses an optional passphrase (empty string by default).
/// **Note:** The `bip32` crate currently only supports 24-word mnemonics.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64], WalletError> {
    let mnemonic = Mnemonic::new(mnemonic, Language::English)
        .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
    let seed = mnemonic.to_seed(passphrase);
    let mut result = [0u8; 64];
    result.copy_from_slice(seed.as_bytes());
    Ok(result)
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

    #[test]
    fn generate_and_roundtrip() {
        let phrase = generate_mnemonic(24).unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        let seed = mnemonic_to_seed(&phrase, "").unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn invalid_word_count() {
        assert!(MnemonicConfig::new(13).is_err());
        assert!(MnemonicConfig::new(0).is_err());
        assert!(MnemonicConfig::new(25).is_err());
    }

    #[test]
    fn valid_word_counts() {
        for &wc in &[12u8, 15, 18, 21, 24] {
            assert!(MnemonicConfig::new(wc).is_ok());
        }
    }

    #[test]
    fn invalid_mnemonic_phrase() {
        assert!(mnemonic_to_seed("invalid phrase here", "").is_err());
    }
}
