use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secp256k1 ECDSA signature (used by BTC, ETH, TRON).
#[derive(Debug, Clone)]
pub struct Secp256k1Signature {
    /// The `r` component of the signature.
    pub r: [u8; 32],
    /// The `s` component of the signature.
    pub s: [u8; 32],
    /// Recovery identifier (0 or 1 for recoverable, 27 or 28 for Ethereum).
    pub v: u8,
}

/// An Ed25519 signature (used by SOL).
#[derive(Debug, Clone)]
pub struct Ed25519Signature {
    /// The 64-byte Ed25519 signature.
    pub bytes: [u8; 64],
}

/// A derived private key containing optional keys for different curves.
///
/// Key material is zeroized on drop (`ZeroizeOnDrop`); the type implements
/// neither `Debug` nor `Display`.
///
/// # Requirements
/// REQ-HD-104, REQ-HD-105
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedPrivateKey {
    /// secp256k1 private key (for BTC, ETH, TRON).
    pub secp256k1_secret: Option<[u8; 32]>,
    /// Ed25519 private key (for SOL).
    pub ed25519_secret: Option<[u8; 32]>,
}
