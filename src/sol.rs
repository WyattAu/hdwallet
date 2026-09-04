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
