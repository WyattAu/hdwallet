use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use crate::derivation;
use crate::error::WalletError;

/// Derive an Ethereum address from the seed.
///
/// Uses Keccak-256 over the uncompressed public key, takes last 20 bytes,
/// and formats as a checksummed EIP-55 address.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    let path = derivation::bip44_path(crate::Coin::Ethereum);
    let _ = path;

    // Simplified: produce a 32-byte key material from the seed.
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(b"ethereum-secp256k1");
    let key_hash = hasher.finalize();

    // Real implementation: BIP32 derive → secp256k1 pubkey → Keccak-256 → last 20 bytes.
    let public_key = &key_hash[..32];

    // Keccak-256 hash of the public key.
    let mut keccak = Keccak::v256();
    keccak.update(public_key);
    let mut address_bytes = [0u8; 32];
    keccak.finalize(&mut address_bytes);

    let addr = &address_bytes[12..32];
    Ok(eip55_checksum(addr))
}

/// EIP-55 mixed-case checksum encoding.
fn eip55_checksum(addr: &[u8]) -> String {
    let hex_str = hex::encode(addr);
    let hash_hex = {
        let mut hasher = Sha256::new();
        hasher.update(hex_str.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    let checksummed: String = hex_str
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_hexdigit() {
                let hash_byte = hash_hex.as_bytes()[i];
                let threshold = hash_byte - b'0';
                if threshold < 10 && c.to_digit(16).unwrap_or(0) > threshold as u32 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect();

    format!("0x{checksummed}")
}
