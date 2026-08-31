use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::error::WalletError;

type HmacSha512 = Hmac<Sha512>;

const HARDENED: u32 = 0x80000000;

fn slip10_master_key(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), WalletError> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|e: hmac::digest::InvalidLength| WalletError::CryptoError(e.to_string()))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);
    Ok((key, chain_code))
}

fn slip10_derive_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), WalletError> {
    let index = index | HARDENED;
    let mut data = Vec::with_capacity(37);
    data.push(0x00);
    data.extend_from_slice(parent_key);
    data.extend_from_slice(&index.to_le_bytes());

    let mut mac = HmacSha512::new_from_slice(parent_chain_code)
        .map_err(|e: hmac::digest::InvalidLength| WalletError::CryptoError(e.to_string()))?;
    mac.update(&data);
    let result = mac.finalize().into_bytes();

    let mut child_key = [0u8; 32];
    let mut child_chain_code = [0u8; 32];
    child_key.copy_from_slice(&result[..32]);
    child_chain_code.copy_from_slice(&result[32..]);
    Ok((child_key, child_chain_code))
}

/// Derive a Solana wallet address (base58-encoded Ed25519 public key).
///
/// Uses SLIP-0010 with path: m/44'/501'/account'/index'
pub fn derive_sol_address(seed: &[u8; 64], account: u32, index: u32) -> Result<String, WalletError> {
    let (mut key, mut chain_code) = slip10_master_key(seed)?;

    let child = slip10_derive_child(&key, &chain_code, 44)?;
    key = child.0;
    chain_code = child.1;

    let child = slip10_derive_child(&key, &chain_code, 501)?;
    key = child.0;
    chain_code = child.1;

    let child = slip10_derive_child(&key, &chain_code, account)?;
    key = child.0;
    chain_code = child.1;

    let child = slip10_derive_child(&key, &chain_code, index)?;
    key = child.0;

    let signing_key = SigningKey::from_bytes(&key);
    let verifying_key = signing_key.verifying_key();

    Ok(bs58::encode(verifying_key.as_bytes()).into_string())
}

/// Derive a Solana address for account 0, index 0.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    derive_sol_address(seed, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slip10_master_key_deterministic() {
        let seed = [0x00u8; 64];
        let (key1, chain1) = slip10_master_key(&seed).unwrap();
        let (key2, chain2) = slip10_master_key(&seed).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(chain1, chain2);
    }
}
