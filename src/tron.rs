use bip32::XPrv;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::WalletError;
use crate::signing::Secp256k1Signature;

const TRON_VERSION_BYTE: u8 = 0x41;

fn double_sha256(data: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut checksum = [0u8; 4];
    let (prefix, _) = second.split_at(4);
    checksum.copy_from_slice(prefix);
    checksum
}

fn derive_tron_xprv(seed: &[u8; 64], account: u32, index: u32) -> Result<XPrv, WalletError> {
    let path_str = format!("m/44'/195'/{account}'/0/{index}");
    let path = path_str
        .parse::<bip32::DerivationPath>()
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))?;
    let seed_obj = bip32::Seed::new(*seed);
    XPrv::derive_from_path(&seed_obj, &path)
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))
}

/// Derive a TRON address from the seed.
///
/// Uses secp256k1 derivation (same as ETH) with path: m/44'/195'/account'/0/index
/// Prepends 0x41 version byte, double SHA-256 checksum, base58 encode.
pub fn derive_tron_address(
    seed: &[u8; 64],
    account: u32,
    index: u32,
) -> Result<String, WalletError> {
    let xprv = derive_tron_xprv(seed, account, index)?;

    let xpub = xprv.public_key();
    let verifying_key = xpub.public_key();

    let uncompressed = verifying_key.to_encoded_point(false);
    let pubkey_bytes = uncompressed.as_bytes();

    let (_, coords) = pubkey_bytes
        .split_first()
        .ok_or_else(|| WalletError::EncodingFailed("empty public key".to_string()))?;
    let mut keccak = Keccak256::new();
    keccak.update(coords);
    let hash = keccak.finalize();

    let (_, addr) = hash.split_at(12);
    let mut payload = Vec::with_capacity(21);
    payload.push(TRON_VERSION_BYTE);
    payload.extend_from_slice(addr);

    let checksum = double_sha256(&payload);
    payload.extend_from_slice(&checksum);

    Ok(bs58::encode(&payload).into_string())
}

/// Derive a TRON address for account 0, index 0.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    derive_tron_address(seed, 0, 0)
}

/// Derive a secp256k1 signing key from the seed for TRON.
pub fn derive_tron_signing_key(
    seed: &[u8; 64],
    account: u32,
    index: u32,
) -> Result<k256::ecdsa::SigningKey, WalletError> {
    let xprv = derive_tron_xprv(seed, account, index)?;
    let secret_bytes = xprv.private_key().to_bytes();
    k256::ecdsa::SigningKey::from_slice(&secret_bytes)
        .map_err(|e| WalletError::SigningFailed(e.to_string()))
}

/// Sign a 32-byte message hash with the TRON signing key (SHA-256 digest).
pub fn sign_tron(
    seed: &[u8; 64],
    account: u32,
    index: u32,
    msg_hash: &[u8; 32],
) -> Result<Secp256k1Signature, WalletError> {
    let signing_key = derive_tron_signing_key(seed, account, index)?;
    let (signature, recid) = signing_key
        .sign_prehash_recoverable(msg_hash)
        .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

    let sig_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    let (r_bytes, s_bytes) = sig_bytes.split_at(32);
    r.copy_from_slice(r_bytes);
    s.copy_from_slice(s_bytes);

    Ok(Secp256k1Signature {
        r,
        s,
        v: recid.to_byte(),
    })
}

/// Construct and sign a TRON transaction.
///
/// Returns the signed transaction bytes (SHA-256 hash of the tx signed).
// The parameter list intentionally mirrors the on-chain transaction field
// order; grouping them into a struct would decouple the signature from
// the serialization it drives.
#[allow(clippy::too_many_arguments)]
pub fn sign_tron_transaction(
    seed: &[u8; 64],
    account: u32,
    index: u32,
    ref_block_bytes: &[u8; 2],
    ref_block_hash: &[u8; 8],
    expiration: i64,
    contract_address: &[u8; 21],
    call_data: &[u8],
    fee_limit: i64,
    timestamp: i64,
) -> Result<Vec<u8>, WalletError> {
    let signing_key = derive_tron_signing_key(seed, account, index)?;

    // Construct TRON transaction data for hashing
    let mut tx_data = Vec::new();
    tx_data.extend_from_slice(ref_block_bytes);
    tx_data.extend_from_slice(ref_block_hash);
    tx_data.extend_from_slice(&expiration.to_be_bytes());
    tx_data.extend_from_slice(contract_address);
    tx_data.extend_from_slice(call_data);
    tx_data.extend_from_slice(&fee_limit.to_be_bytes());
    tx_data.extend_from_slice(&timestamp.to_be_bytes());

    // SHA-256 hash of the tx data
    let tx_hash: [u8; 32] = Sha256::digest(&tx_data).into();

    let (signature, recid) = signing_key
        .sign_prehash_recoverable(&tx_hash)
        .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

    let sig_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    let (r_bytes, s_bytes) = sig_bytes.split_at(32);
    r.copy_from_slice(r_bytes);
    s.copy_from_slice(s_bytes);

    // Return: tx_hash + r + s + v
    let mut result = Vec::with_capacity(32 + 32 + 32 + 1);
    result.extend_from_slice(&tx_hash);
    result.extend_from_slice(&r);
    result.extend_from_slice(&s);
    result.push(recid.to_byte());
    Ok(result)
}

// Tests exercise failure paths and invariants directly; unwrap/expect,
// slicing, and panicking asserts are acceptable here — violations
// surface as test failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
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

    #[test]
    fn tron_signing_key_derivation() {
        let phrase = crate::HdWallet::generate(24).unwrap();
        let wallet = crate::HdWallet::from_mnemonic(&phrase, "").unwrap();
        let signing_key = derive_tron_signing_key(wallet.seed(), 0, 0).unwrap();
        let verifying_key = signing_key.verifying_key();
        assert!(!verifying_key.to_encoded_point(false).as_bytes().is_empty());
    }

    #[test]
    fn tron_sign_and_verify() {
        let phrase = crate::HdWallet::generate(24).unwrap();
        let wallet = crate::HdWallet::from_mnemonic(&phrase, "").unwrap();
        let msg_hash = Sha256::digest(b"test message").into();

        let sig = sign_tron(wallet.seed(), 0, 0, &msg_hash).unwrap();

        // Verify signature is valid
        use k256::ecdsa::{VerifyingKey, signature::hazmat::PrehashVerifier};
        let signing_key = derive_tron_signing_key(wallet.seed(), 0, 0).unwrap();
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
