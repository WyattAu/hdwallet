use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("derivation failed: {0}")]
    DerivationFailed(String),

    #[error("unsupported coin: {0}")]
    UnsupportedCoin(String),

    #[error("encoding failed: {0}")]
    EncodingFailed(String),

    #[error("crypto error: {0}")]
    CryptoError(String),
}
