use bip39::{Language, Mnemonic};

use crate::error::WalletError;

/// Configuration for mnemonic generation.
#[derive(Debug, Clone)]
pub struct MnemonicConfig {
    /// Number of words in the mnemonic (12, 15, 18, 21, or 24).
    pub word_count: u8,
}

impl MnemonicConfig {
    /// Create a new config with validated word count.
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
/// Every word count BIP-39 permits is supported: 12, 15, 18, 21 and 24.
pub fn generate_mnemonic(word_count: u8) -> Result<String, WalletError> {
    let _config = MnemonicConfig::new(word_count)?;
    let mnemonic = Mnemonic::generate_in(Language::English, word_count as usize)
        .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
    Ok(mnemonic.to_string())
}

/// Convert a BIP39 mnemonic phrase to a 64-byte seed.
///
/// Uses an optional passphrase (empty string by default).
///
/// Parsing goes through `bip39` directly rather than through `bip32`'s `bip39`
/// feature: `bip32 0.5`'s parser rejects every phrase in the BIP-39
/// specification's own test vectors, including "abandon … about", so a wallet
/// built on it accepted only phrases it had generated itself and could not
/// restore a phrase a user had written down. `bip39` parses those vectors
/// correctly, and `bip32` is still used for the BIP-32 derivation arithmetic
/// that follows.
///
/// # Requirements
/// REQ-HD-002, REQ-HD-004
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64], WalletError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
    Ok(mnemonic.to_seed(passphrase))
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
        for count in [12u8, 15, 18, 21, 24] {
            let phrase = generate_mnemonic(count).unwrap();
            let words: Vec<&str> = phrase.split_whitespace().collect();
            assert_eq!(words.len(), count as usize, "generated {count} words");

            let seed = mnemonic_to_seed(&phrase, "").unwrap();
            assert_eq!(seed.len(), 64);
        }
    }

    /// The phrases a user actually has: BIP-39's own published vectors. The
    /// crate previously rejected all three, so a phrase restored from paper,
    /// from a password manager or from another wallet never parsed and every
    /// address derived from it was unreachable.
    #[test]
    fn parses_the_bip39_specification_vectors() {
        for vector in [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ] {
            mnemonic_to_seed(vector, "")
                .unwrap_or_else(|e| panic!("BIP-39 vector rejected: {e}\n  {vector}"));
        }
    }

    #[test]
    fn seed_is_the_specification_value() {
        // BIP-39 vector 1: this seed is fixed by the specification, so it also
        // pins the passphrase handling and not just the checksum check.
        let seed = mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "TREZOR",
        )
        .unwrap();
        assert_eq!(
            seed,
            [
                0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c,
                0x05, 0xed, 0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e, 0x9e, 0xfa, 0x37, 0x08,
                0xe5, 0x34, 0x95, 0x53, 0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82, 0x64, 0xc1,
                0xe1, 0xc9, 0x2f, 0x2c, 0xf1, 0x41, 0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b,
                0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04,
            ],
            "BIP-39 vector 1 with the TREZOR passphrase"
        );
    }

    #[test]
    fn rejects_a_bad_checksum() {
        // All-zero entropy, but the final word carries checksum bits 0000
        // where SHA-256 of that entropy demands 0011 — so the phrase decodes
        // to a valid-looking entropy with a checksum that does not belong to
        // it. "zoo ... wrong" is *not* such a case: it decodes to ff..ff
        // entropy, whose checksum happens to match, which is why the obvious
        // candidate for this test is a trap.
        assert!(
            mnemonic_to_seed(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
                ""
            )
            .is_err(),
            "a phrase whose checksum does not match its entropy is refused"
        );

        // And the phrase that does carry the right checksum for the same
        // entropy parses, so the rejection above is the checksum and not the
        // word count or an unknown word.
        assert!(
            mnemonic_to_seed(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                ""
            )
            .is_ok()
        );
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
