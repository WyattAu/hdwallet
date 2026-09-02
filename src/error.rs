use thiserror::Error;

/// Errors that can occur in wallet operations.
#[derive(Debug, Error)]
pub enum WalletError {
    /// Invalid mnemonic phrase.
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Key derivation failed.
    #[error("derivation failed: {0}")]
    DerivationFailed(String),

    /// Unsupported coin type.
    #[error("unsupported coin: {0}")]
    UnsupportedCoin(String),

    /// Encoding failed.
    #[error("encoding failed: {0}")]
    EncodingFailed(String),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    CryptoError(String),
}
