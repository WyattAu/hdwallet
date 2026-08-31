use std::fmt;

use crate::error::WalletError;
use crate::Coin;

/// BIP-44 purpose constant.
const PURPOSE: u32 = 44;

/// Hardened index offset.
const HARDENED: u32 = 0x80000000;

/// A BIP-44 derivation path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    parts: Vec<u32>,
}

impl DerivationPath {
    /// Build a BIP-44 path: `m / 44' / coin_type' / account' / change / index`.
    pub fn for_coin(coin: Coin, account: u32, change: u32, index: u32) -> Self {
        let coin_type = match coin {
            Coin::Bitcoin => 0,
            Coin::Ethereum => 60,
            Coin::Solana => 501,
            Coin::Tron => 195,
        };
        Self {
            parts: vec![
                PURPOSE | HARDENED,
                coin_type | HARDENED,
                account | HARDENED,
                change,
                index,
            ],
        }
    }

    /// Parse a derivation path string like `m/44'/60'/0'/0/0`.
    pub fn parse(path: &str) -> Result<Self, WalletError> {
        let path = path.strip_prefix("m/").unwrap_or(path);
        let parts: Vec<u32> = path
            .split('/')
            .map(|s| {
                if let Some(stripped) = s.strip_suffix('\'') {
                    stripped
                        .parse::<u32>()
                        .map(|n| n | HARDENED)
                        .map_err(|e| WalletError::DerivationFailed(format!("invalid path component '{s}': {e}")))
                } else {
                    s.parse::<u32>()
                        .map_err(|e| WalletError::DerivationFailed(format!("invalid path component '{s}': {e}")))
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { parts })
    }

    /// Return the raw index values (with hardened bit set where applicable).
    pub fn indices(&self) -> &[u32] {
        &self.parts
    }

    /// Format as a string for bip32 derivation (e.g. "m/44'/60'/0'/0/0").
    pub fn to_bip32_string(&self) -> String {
        let components: Vec<String> = self
            .parts
            .iter()
            .map(|&p| {
                if p & HARDENED != 0 {
                    format!("{}'", p & !HARDENED)
                } else {
                    p.to_string()
                }
            })
            .collect();
        format!("m/{}", components.join("/"))
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_bip32_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_path() {
        let path = DerivationPath::for_coin(Coin::Bitcoin, 0, 0, 0);
        assert_eq!(path.to_bip32_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn ethereum_path() {
        let path = DerivationPath::for_coin(Coin::Ethereum, 0, 0, 0);
        assert_eq!(path.to_bip32_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn solana_path() {
        let path = DerivationPath::for_coin(Coin::Solana, 0, 0, 0);
        assert_eq!(path.to_bip32_string(), "m/44'/501'/0'/0/0");
    }

    #[test]
    fn parse_path() {
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(path.to_bip32_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn parse_invalid() {
        assert!(DerivationPath::parse("m/abc").is_err());
    }
}
