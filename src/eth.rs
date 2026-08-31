use bip32::XPrv;
use sha3::{Digest, Keccak256};

use crate::error::WalletError;

/// Derive an Ethereum address from the seed.
///
/// Derivation path: m/44'/60'/account'/0/index
/// Uses Keccak-256 over the uncompressed public key (without 0x04 prefix),
/// takes the last 20 bytes, and applies EIP-55 checksum.
pub fn derive_eth_address(seed: &[u8; 64], account: u32, index: u32) -> Result<String, WalletError> {
    let path_str = format!("m/44'/60'/{account}'/0/{index}");
    let path = path_str.parse::<bip32::DerivationPath>()
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))?;
    let seed_obj = bip32::Seed::new(*seed);
    let xprv = XPrv::derive_from_path(&seed_obj, &path)
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))?;

    let xpub = xprv.public_key();
    let verifying_key = xpub.public_key();

    // Uncompressed pubkey: 04 || X (32 bytes) || Y (32 bytes) = 65 bytes
    let uncompressed = verifying_key.to_encoded_point(false);
    let pubkey_bytes = uncompressed.as_bytes();

    // Skip 0x04 prefix, hash the 64 coordinate bytes
    let mut keccak = Keccak256::new();
    keccak.update(&pubkey_bytes[1..]);
    let hash = keccak.finalize();

    // Last 20 bytes = address
    let addr = &hash[12..32];
    Ok(eip55_checksum(addr))
}

/// Derive an Ethereum address for account 0, index 0.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    derive_eth_address(seed, 0, 0)
}

/// EIP-55 mixed-case checksum encoding.
fn eip55_checksum(addr: &[u8]) -> String {
    let hex_str = hex::encode(addr);

    // Keccak-256 of lowercase hex string
    let mut keccak = Keccak256::new();
    keccak.update(hex_str.as_bytes());
    let hash = keccak.finalize();

    // hash is 32 bytes, hex_str is 40 chars
    // Use the hex-encoded hash so we can index by character position
    let hash_hex = hex::encode(&hash);

    let checksummed: String = hex_str
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let hash_byte = hash_hex.as_bytes()[i];
            if c.is_ascii_hexdigit() {
                let digit = c.to_digit(16).unwrap() as u8;
                // Uppercase if the corresponding hash nibble >= 8
                if hash_byte >= b'8' && digit >= 8 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_known_vector() {
        // Known EIP-55 test vector
        let addr = hex::decode("fb6916095ca1df60bb79ce92ce3ea74c37c5d359").unwrap();
        let checksummed = eip55_checksum(&addr);
        assert_eq!(checksummed, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
    }
}
