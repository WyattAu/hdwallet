#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("derivation error: {0}")]
    Derivation(String),

    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("unsupported coin: {0}")]
    UnsupportedCoin(String),

    #[error("crypto error: {0}")]
    Crypto(String),
}
