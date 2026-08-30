use crate::error::WalletError;

/// Generate a 24-word BIP39 mnemonic (256-bit entropy).
pub fn generate_mnemonic() -> Result<String, WalletError> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy)
        .map_err(|e| WalletError::Crypto(format!("entropy generation failed: {e}")))?;

    let phrase = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

    Ok(phrase.to_string())
}

/// Convert a BIP39 mnemonic phrase to a 64-byte seed.
///
/// Uses the default BIP39 password (empty string).
pub fn mnemonic_to_seed(phrase: &str) -> Result<[u8; 64], WalletError> {
    let mnemonic = bip39::Mnemonic::parse_normalized(phrase)
        .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;

    let seed = mnemonic.to_seed("");
    let mut result = [0u8; 64];
    result.copy_from_slice(&seed[..64]);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_mnemonic() {
        let phrase = generate_mnemonic().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        let seed = mnemonic_to_seed(&phrase).unwrap();
        assert_eq!(seed.len(), 64);
    }
}
