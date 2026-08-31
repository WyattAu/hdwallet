use bip32::XPrv;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::WalletError;

const TRON_VERSION_BYTE: u8 = 0x41;

fn double_sha256(data: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&second[..4]);
    checksum
}

/// Derive a TRON address from the seed.
///
/// Uses secp256k1 derivation (same as ETH) with path: m/44'/195'/account'/0/index
/// Prepends 0x41 version byte, double SHA-256 checksum, base58 encode.
pub fn derive_tron_address(seed: &[u8; 64], account: u32, index: u32) -> Result<String, WalletError> {
    let path_str = format!("m/44'/195'/{account}'/0/{index}");
    let path = path_str.parse::<bip32::DerivationPath>()
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))?;
    let seed_obj = bip32::Seed::new(*seed);
    let xprv = XPrv::derive_from_path(&seed_obj, &path)
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))?;

    let xpub = xprv.public_key();
    let verifying_key = xpub.public_key();

    let uncompressed = verifying_key.to_encoded_point(false);
    let pubkey_bytes = uncompressed.as_bytes();

    let mut keccak = Keccak256::new();
    keccak.update(&pubkey_bytes[1..]);
    let hash = keccak.finalize();

    let mut payload = Vec::with_capacity(21);
    payload.push(TRON_VERSION_BYTE);
    payload.extend_from_slice(&hash[12..32]);

    let checksum = double_sha256(&payload);
    payload.extend_from_slice(&checksum);

    Ok(bs58::encode(&payload).into_string())
}

/// Derive a TRON address for account 0, index 0.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    derive_tron_address(seed, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_sha256_deterministic() {
        let data = b"test data";
        let h1 = double_sha256(data);
        let h2 = double_sha256(data);
        assert_eq!(h1, h2);
    }
}
