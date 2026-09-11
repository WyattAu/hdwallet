use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::error::WalletError;
use crate::signing::Ed25519Signature;

type HmacSha512 = Hmac<Sha512>;

const HARDENED: u32 = 0x80000000;

fn slip10_master_key(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), WalletError> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|e: hmac::digest::InvalidLength| WalletError::CryptoError(e.to_string()))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    let (key_bytes, chain_bytes) = result.split_at(32);
    key.copy_from_slice(key_bytes);
    chain_code.copy_from_slice(chain_bytes);
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
    let (key_bytes, chain_bytes) = result.split_at(32);
    child_key.copy_from_slice(key_bytes);
    child_chain_code.copy_from_slice(chain_bytes);
    Ok((child_key, child_chain_code))
}

/// Derive the raw ed25519 private key bytes via SLIP-0010.
///
/// Uses path: m/44'/501'/account'/index'
fn derive_sol_secret_key(
    seed: &[u8; 64],
    account: u32,
    index: u32,
) -> Result<[u8; 32], WalletError> {
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

    Ok(key)
}

/// Derive a Solana wallet address (base58-encoded Ed25519 public key).
///
/// Uses SLIP-0010 with path: m/44'/501'/account'/index'
pub fn derive_sol_address(
    seed: &[u8; 64],
    account: u32,
    index: u32,
) -> Result<String, WalletError> {
    let key = derive_sol_secret_key(seed, account, index)?;
    let signing_key = SigningKey::from_bytes(&key);
    let verifying_key = signing_key.verifying_key();

    Ok(bs58::encode(verifying_key.as_bytes()).into_string())
}

/// Derive a Solana address for account 0, index 0.
pub fn derive_address(seed: &[u8; 64]) -> Result<String, WalletError> {
    derive_sol_address(seed, 0, 0)
}

/// Derive an ed25519 signing key from the seed for SOL.
pub fn derive_sol_signing_key(
    seed: &[u8; 64],
    account: u32,
    index: u32,
) -> Result<ed25519_dalek::SigningKey, WalletError> {
    let key = derive_sol_secret_key(seed, account, index)?;
    Ok(SigningKey::from_bytes(&key))
}

/// Sign a message with the SOL signing key.
pub fn sign_sol(
    seed: &[u8; 64],
    account: u32,
    index: u32,
    message: &[u8],
) -> Result<Ed25519Signature, WalletError> {
    use ed25519_dalek::Signer;
    let signing_key = derive_sol_signing_key(seed, account, index)?;
    let sig = signing_key.sign(message);

    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&sig.to_bytes());
    Ok(Ed25519Signature { bytes })
}

/// Construct a Solana transaction message and sign it.
///
/// Returns the signed message bytes (64-byte signature || serialized message).
pub fn sign_sol_transaction(
    seed: &[u8; 64],
    account: u32,
    index: u32,
    recent_blockhash: &[u8; 32],
    instruction_data: &[u8],
) -> Result<Vec<u8>, WalletError> {
    use ed25519_dalek::Signer;

    let signing_key = derive_sol_signing_key(seed, account, index)?;

    // Build a minimal Solana message:
    // header: 1 pubkey (signer), 0 read-only signers, 0 read-only non-signers
    // account_keys: [signer_pubkey]
    // recent_blockhash
    // instructions: serialized instruction data
    let pubkey = signing_key.verifying_key().to_bytes();

    let mut msg = Vec::new();
    msg.push(1); // num_signers
    msg.push(0); // num_readonly_signed
    msg.push(0); // num_readonly_unsigned
    msg.extend_from_slice(&pubkey); // account key
    msg.extend_from_slice(recent_blockhash);
    msg.extend_from_slice(instruction_data);

    let sig = signing_key.sign(&msg);

    let mut result = Vec::with_capacity(64 + msg.len());
    result.extend_from_slice(&sig.to_bytes());
    result.extend_from_slice(&msg);
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
    fn slip10_master_key_deterministic() {
        let seed = [0x00u8; 64];
        let (key1, chain1) = slip10_master_key(&seed).unwrap();
        let (key2, chain2) = slip10_master_key(&seed).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(chain1, chain2);
    }

    #[test]
    fn slip10_master_key_matches_slip0010_vector() {
        // SLIP-0010 (ed25519) test vector 1: seed 000102030405060708090a0b0c0d0e0f.
        let seed: &[u8] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let (key, chain_code) = slip10_master_key(seed).unwrap();
        assert_eq!(
            key,
            [
                0x2b, 0x4b, 0xe7, 0xf1, 0x9e, 0xe2, 0x7b, 0xbf, 0x30, 0xc6, 0x67, 0xb6, 0x42, 0xd5,
                0xf4, 0xaa, 0x69, 0xfd, 0x16, 0x98, 0x72, 0xf8, 0xfc, 0x30, 0x59, 0xc0, 0x8e, 0xba,
                0xe2, 0xeb, 0x19, 0xe7,
            ]
        );
        assert_eq!(
            chain_code,
            [
                0x90, 0x04, 0x6a, 0x93, 0xde, 0x53, 0x80, 0xa7, 0x2b, 0x5e, 0x45, 0x01, 0x07, 0x48,
                0x56, 0x7d, 0x5e, 0xa0, 0x2b, 0xbf, 0x65, 0x22, 0xf9, 0x79, 0xe0, 0x5c, 0x0d, 0x8d,
                0x8c, 0xa9, 0xff, 0xfb,
            ]
        );
    }

    #[test]
    fn slip10_child_keys_vary_by_index_and_preserve_hardening() {
        let seed = [0x11u8; 64];
        let (key, chain) = slip10_master_key(&seed).unwrap();

        let c0 = slip10_derive_child(&key, &chain, 0).unwrap();
        let c1 = slip10_derive_child(&key, &chain, 1).unwrap();
        // Distinct non-hardened indices must yield distinct children.
        assert_ne!(c0.0, c1.0);
        assert_ne!(c0.1, c1.1);
        // The hardened bit is OR-ed in: passing it explicitly is a no-op.
        let hardened = slip10_derive_child(&key, &chain, HARDENED).unwrap();
        assert_eq!(hardened, c0);
    }

    #[test]
    fn derive_sol_secret_key_is_seed_and_index_sensitive() {
        let s1 = [0x22u8; 64];
        let s2 = [0x33u8; 64];
        let a = derive_sol_secret_key(&s1, 0, 0).unwrap();
        let b = derive_sol_secret_key(&s1, 0, 1).unwrap();
        let c = derive_sol_secret_key(&s2, 0, 0).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn derive_sol_address_is_base58_of_derived_pubkey() {
        let seed = [0x44u8; 64];
        let addr = derive_sol_address(&seed, 0, 0).unwrap();
        let other = derive_sol_address(&[0x45u8; 64], 0, 0).unwrap();
        assert_ne!(addr, other);

        let raw = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(raw.len(), 32);
        let signing_key = derive_sol_signing_key(&seed, 0, 0).unwrap();
        assert_eq!(
            bs58::encode(signing_key.verifying_key().as_bytes()).into_string(),
            addr
        );
    }

    #[test]
    fn sol_signing_key_derivation() {
        let phrase = crate::HdWallet::generate(24).unwrap();
        let wallet = crate::HdWallet::from_mnemonic(&phrase, "").unwrap();
        let signing_key = derive_sol_signing_key(wallet.seed(), 0, 0).unwrap();
        let verifying_key = signing_key.verifying_key();
        assert!(!verifying_key.as_bytes().is_empty());
    }

    #[test]
    fn sol_sign_and_verify() {
        use ed25519_dalek::Verifier;
        let phrase = crate::HdWallet::generate(24).unwrap();
        let wallet = crate::HdWallet::from_mnemonic(&phrase, "").unwrap();
        let message = b"test message";

        let sig = sign_sol(wallet.seed(), 0, 0, message).unwrap();

        // Verify signature is valid
        let signing_key = derive_sol_signing_key(wallet.seed(), 0, 0).unwrap();
        let verifying_key = signing_key.verifying_key();
        let ed25519_sig = ed25519_dalek::Signature::from_bytes(&sig.bytes);
        assert!(verifying_key.verify(message, &ed25519_sig).is_ok());
    }
}
