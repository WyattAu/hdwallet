use bip32::XPrv;
use sha3::{Digest, Keccak256};

use crate::error::WalletError;
use crate::signing::Secp256k1Signature;

fn derive_eth_xprv(seed: &[u8; 64], account: u32, index: u32) -> Result<XPrv, WalletError> {
    let path_str = format!("m/44'/60'/{account}'/0/{index}");
    let path = path_str
        .parse::<bip32::DerivationPath>()
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))?;
    let seed_obj = bip32::Seed::new(*seed);
    XPrv::derive_from_path(&seed_obj, &path)
        .map_err(|e| WalletError::DerivationFailed(e.to_string()))
}

/// Derive an Ethereum address from the seed.
///
/// Derivation path: m/44'/60'/account'/0/index
/// Uses Keccak-256 over the uncompressed public key (without 0x04 prefix),
/// takes the last 20 bytes, and applies EIP-55 checksum.
pub fn derive_eth_address(
    seed: &[u8; 64],
    account: u32,
    index: u32,
) -> Result<String, WalletError> {
    let xprv = derive_eth_xprv(seed, account, index)?;

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

/// Derive a secp256k1 signing key from the seed for ETH.
pub fn derive_eth_signing_key(
    seed: &[u8; 64],
    account: u32,
    index: u32,
) -> Result<k256::ecdsa::SigningKey, WalletError> {
    let xprv = derive_eth_xprv(seed, account, index)?;
    let secret_bytes = xprv.private_key().to_bytes();
    k256::ecdsa::SigningKey::from_slice(&secret_bytes)
        .map_err(|e| WalletError::SigningFailed(e.to_string()))
}

/// Sign a 32-byte message hash with the ETH signing key (recoverable ECDSA).
pub fn sign_eth(
    seed: &[u8; 64],
    account: u32,
    index: u32,
    msg_hash: &[u8; 32],
) -> Result<Secp256k1Signature, WalletError> {
    let signing_key = derive_eth_signing_key(seed, account, index)?;
    let (signature, recid) = signing_key
        .sign_prehash_recoverable(msg_hash)
        .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

    let sig_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..64]);

    // Ethereum v = recovery_id + 27
    Ok(Secp256k1Signature {
        r,
        s,
        v: recid.to_byte() + 27,
    })
}

/// Construct, RLP-encode, and sign an EIP-1559 Ethereum transaction.
///
/// Returns the signed raw transaction bytes (ready for broadcast).
pub fn sign_eth_transaction(
    seed: &[u8; 64],
    account: u32,
    index: u32,
    chain_id: u64,
    nonce: u64,
    to: &[u8; 20],
    value: &[u8; 32],
    gas_limit: u64,
    max_fee_per_gas: &[u8; 32],
    max_priority_fee_per_gas: &[u8; 32],
    data: &[u8],
) -> Result<Vec<u8>, WalletError> {
    use rlp::RlpStream;

    let signing_key = derive_eth_signing_key(seed, account, index)?;

    // EIP-1559: tx type 0x02 || RLP([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list])
    let mut stream = RlpStream::new();
    stream.begin_list(9);
    stream.append(&chain_id);
    stream.append(&nonce);
    stream.append(&max_priority_fee_per_gas.as_slice());
    stream.append(&max_fee_per_gas.as_slice());
    stream.append(&gas_limit);
    stream.append(&to.as_slice());
    stream.append(&value.as_slice());
    stream.append(&data);
    stream.begin_list(0); // empty access list

    let mut tx_payload = stream.out().to_vec();
    let mut tx_bytes = Vec::with_capacity(1 + tx_payload.len());
    tx_bytes.push(0x02); // EIP-1559 tx type
    tx_bytes.append(&mut tx_payload);

    // Sign: keccak256(0x02 || rlp_encoded_tx)
    let mut keccak = Keccak256::new();
    keccak.update(&tx_bytes);
    let tx_hash: [u8; 32] = keccak.finalize().into();

    let (signature, recid) = signing_key
        .sign_prehash_recoverable(&tx_hash)
        .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

    let sig_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..64]);

    // v = chain_id * 2 + 35 + recovery_id
    let v = chain_id * 2 + 35 + recid.to_byte() as u64;

    // RLP encode the signed tx: [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, v, r, s]
    let mut signed_stream = RlpStream::new();
    signed_stream.begin_list(12);
    signed_stream.append(&chain_id);
    signed_stream.append(&nonce);
    signed_stream.append(&max_priority_fee_per_gas.as_slice());
    signed_stream.append(&max_fee_per_gas.as_slice());
    signed_stream.append(&gas_limit);
    signed_stream.append(&to.as_slice());
    signed_stream.append(&value.as_slice());
    signed_stream.append(&data);
    signed_stream.append(&v);
    signed_stream.append(&r.as_slice());
    signed_stream.append(&s.as_slice());

    let mut signed_tx = vec![0x02u8];
    signed_tx.extend_from_slice(&signed_stream.out());
    Ok(signed_tx)
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

    #[test]
    fn eth_signing_key_derivation() {
        let phrase = crate::HdWallet::generate(24).unwrap();
        let wallet = crate::HdWallet::from_mnemonic(&phrase, "").unwrap();
        let signing_key = derive_eth_signing_key(wallet.seed(), 0, 0).unwrap();
        let verifying_key = signing_key.verifying_key();
        assert!(!verifying_key.to_encoded_point(false).as_bytes().is_empty());
    }

    #[test]
    fn eth_sign_and_verify() {
        let phrase = crate::HdWallet::generate(24).unwrap();
        let wallet = crate::HdWallet::from_mnemonic(&phrase, "").unwrap();
        let msg_hash = Keccak256::digest(b"test message").into();

        let sig = sign_eth(wallet.seed(), 0, 0, &msg_hash).unwrap();

        // v should be 27 or 28 (Ethereum-style recovery id)
        assert!(sig.v == 27 || sig.v == 28);

        // Verify signature is valid
        use k256::ecdsa::{VerifyingKey, signature::hazmat::PrehashVerifier};
        let signing_key = derive_eth_signing_key(wallet.seed(), 0, 0).unwrap();
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
