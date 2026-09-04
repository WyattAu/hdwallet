use bip32::XPrv;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::error::WalletError;
use crate::signing::Secp256k1Signature;

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

fn derive_btc_xprv(seed: &[u8; 64], account: u32, index: u32) -> Result<XPrv, WalletError> {
    let path_str = format!("m/84'/0'/{account}'/0/{index}");
    let path = path_str
        .parse::<bip32::DerivationPath>()
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))?;
    let seed_obj = bip32::Seed::new(*seed);
    XPrv::derive_from_path(&seed_obj, &path)
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))
}

/// Derive a P2WPKH (bech32 segwit v0) Bitcoin address from the seed.
///
/// Derivation path: m/84'/0'/account'/0/index
pub fn derive_btc_address(
    seed: &[u8; 64],
    account: u32,
    index: u32,
) -> Result<String, WalletError> {
    let xprv = derive_btc_xprv(seed, account, index)?;

    let xpub = xprv.public_key();
    let verifying_key = xpub.public_key();
    let compressed = verifying_key.to_encoded_point(true);
    pubkey_to_bech32(compressed.as_bytes(), "bc")
}

/// Derive a P2WPKH Bitcoin address for account 0, index 0.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    derive_btc_address(seed, 0, 0)
}

/// Derive a secp256k1 signing key from the seed for BTC.
pub fn derive_btc_signing_key(
    seed: &[u8; 64],
    account: u32,
    index: u32,
) -> Result<k256::ecdsa::SigningKey, WalletError> {
    let xprv = derive_btc_xprv(seed, account, index)?;
    let secret_bytes = xprv.private_key().to_bytes();
    k256::ecdsa::SigningKey::from_slice(&secret_bytes)
        .map_err(|e| WalletError::SigningFailed(e.to_string()))
}

/// Sign a 32-byte message hash with the BTC signing key.
pub fn sign_btc(
    seed: &[u8; 64],
    account: u32,
    index: u32,
    msg_hash: &[u8; 32],
) -> Result<Secp256k1Signature, WalletError> {
    let signing_key = derive_btc_signing_key(seed, account, index)?;
    let (signature, recid) = signing_key
        .sign_prehash_recoverable(msg_hash)
        .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

    let sig_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..64]);

    Ok(Secp256k1Signature {
        r,
        s,
        v: recid.to_byte(),
    })
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

    #[test]
    fn btc_signing_key_derivation() {
        let phrase = crate::HdWallet::generate(24).unwrap();
        let wallet = crate::HdWallet::from_mnemonic(&phrase, "").unwrap();
        let signing_key = derive_btc_signing_key(wallet.seed(), 0, 0).unwrap();
        let verifying_key = signing_key.verifying_key();
        assert!(!verifying_key.to_encoded_point(false).as_bytes().is_empty());
    }

    #[test]
    fn btc_sign_and_verify() {
        let phrase = crate::HdWallet::generate(24).unwrap();
        let wallet = crate::HdWallet::from_mnemonic(&phrase, "").unwrap();
        let msg_hash = Sha256::digest(b"test message").into();

        let sig = sign_btc(wallet.seed(), 0, 0, &msg_hash).unwrap();

        // Verify signature is valid
        use k256::ecdsa::{VerifyingKey, signature::hazmat::PrehashVerifier};
        let signing_key = derive_btc_signing_key(wallet.seed(), 0, 0).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&sig.r);
        sig_bytes[32..].copy_from_slice(&sig.s);
        let signature = k256::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
        verifying_key
            .verify_prehash(&msg_hash, &signature)
            .expect("signature should be valid");
    }
}
