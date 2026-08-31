use bip32::XPrv;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::error::WalletError;

/// Bech32 character set (BIP-173).
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Generator polynomial for bech32 checksum.
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn bech32_polymod(values: &[u32]) -> u32 {
    let mut chk = 1u32;
    for &v in values {
        let b = (chk >> 25) as u8;
        chk = (chk & 0x1ffffff) << 5 ^ v;
        for i in 0..5 {
            if (b >> i) & 1 == 1 {
                chk ^= GEN[i];
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &[u8]) -> Vec<u32> {
    let mut expand = Vec::with_capacity(hrp.len() * 2 + 1);
    for &b in hrp {
        expand.push((b >> 5) as u32);
    }
    expand.push(0);
    for &b in hrp {
        expand.push((b & 0x1f) as u32);
    }
    expand
}

fn bech32_create_checksum(hrp: &[u8], data: &[u32]) -> Vec<u32> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let poly = bech32_polymod(&values);
    let mut checksum = Vec::with_capacity(6);
    for i in 0..6 {
        checksum.push((poly >> 5 * (5 - i)) & 0x1f);
    }
    checksum
}

fn bech32_encode(hrp: &str, data: &[u8], witness_version: u8) -> Result<String, WalletError> {
    let mut acc = 0u32;
    let mut bits = 0u8;
    let mut five_bit: Vec<u32> = Vec::with_capacity(data.len() * 8 / 5 + 1);
    for &byte in data {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            five_bit.push((acc >> bits) & 0x1f);
        }
    }
    if bits > 0 {
        five_bit.push((acc << (5 - bits)) & 0x1f);
    }

    let mut payload = vec![witness_version as u32];
    payload.extend_from_slice(&five_bit);

    let checksum = bech32_create_checksum(hrp.as_bytes(), &payload);
    payload.extend_from_slice(&checksum);

    let encoded: String = payload
        .iter()
        .map(|&v| *BECH32_CHARSET.get(v as usize).unwrap_or(&b'?') as char)
        .collect();

    Ok(format!("{hrp}1{encoded}"))
}

fn pubkey_to_bech32(pubkey_bytes: &[u8], hrp: &str) -> Result<String, WalletError> {
    let sha = Sha256::digest(pubkey_bytes);
    let hash160 = Ripemd160::digest(sha);
    bech32_encode(hrp, &hash160, 0)
}

/// Derive a P2WPKH (bech32 segwit v0) Bitcoin address from the seed.
///
/// Derivation path: m/84'/0'/account'/0/index
pub fn derive_btc_address(seed: &[u8; 64], account: u32, index: u32) -> Result<String, WalletError> {
    let path_str = format!("m/84'/0'/{account}'/0/{index}");
    let path = path_str.parse::<bip32::DerivationPath>()
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))?;
    let seed_obj = bip32::Seed::new(*seed);
    let xprv = XPrv::derive_from_path(&seed_obj, &path)
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))?;

    let xpub = xprv.public_key();
    let verifying_key = xpub.public_key();
    let compressed = verifying_key.to_encoded_point(true);
    pubkey_to_bech32(compressed.as_bytes(), "bc")
}

/// Derive a P2WPKH Bitcoin address for account 0, index 0.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    derive_btc_address(seed, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bech32_encode_known() {
        // Encode 20 zero bytes as P2WPKH
        let hrp = "bc";
        let data = [0x00; 20];
        let result = bech32_encode(hrp, &data, 0).unwrap();
        dbg!(&result);
        assert!(result.starts_with("bc1q"));
        assert_eq!(result.len(), 42);
    }
}
