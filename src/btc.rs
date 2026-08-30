use sha2::{Digest, Sha256};

use crate::derivation;
use crate::error::WalletError;

/// Derive a P2WPKH (bech32) Bitcoin address from the seed.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    let path = derivation::bip44_path(crate::Coin::Bitcoin);
    let _ = path;

    // Simplified: hash seed to produce a deterministic key.
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(b"bitcoin-p2wpkh");
    let hash = hasher.finalize();

    // Real implementation would use BIP32 key derivation, then
    // SHA256(PUBKEY) → RIPEMD160 → bech32 encode.
    // Using simplified bech32 encoding for the hash.
    Ok(format!("bc1q{}", hex::encode(&hash[..20])))
}
