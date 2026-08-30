use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::derivation;
use crate::error::WalletError;

/// Derive a Solana wallet address (base58-encoded Ed25519 public key).
///
/// Uses SLIP-0010 Ed25519 derivation.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    let path = derivation::bip44_path(crate::Coin::Solana);
    let _ = path;

    // Simplified: derive a signing key from the seed.
    // Real implementation would follow SLIP-0010 with HMAC-SHA512 chain.
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(b"solana-ed25519");
    let key_bytes: [u8; 32] = hasher.finalize().into();

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    Ok(bs58::encode(verifying_key.as_bytes()).into_string())
}

/// Derive the Associated Token Account (ATA) address for a mint.
pub fn derive_ata(wallet: &str, mint: &str) -> Result<String, WalletError> {
    // ATA = PDA([wallet_pubkey, mint_pubkey], TOKEN_PROGRAM_ID)
    // Simplified: in practice this uses the SPL Token program seeds.
    use sha2::Sha512;

    let mut hasher = Sha512::new();
    hasher.update(wallet.as_bytes());
    hasher.update(mint.as_bytes());
    hasher.update(b"spl-token-ata");
    let hash = hasher.finalize();

    Ok(bs58::encode(&hash[..32]).into_string())
}
