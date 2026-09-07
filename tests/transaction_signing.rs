//! End-to-end tests for the transaction-signing constructors.
//!
//! Each test asserts real cryptographic behavior: signatures must recover
//! (secp256k1) or verify (ed25519) against the wallet's own derived key, and
//! serialized outputs must round-trip their documented wire format.
//!
//! Test code may unwrap/slice: violations surface as test failures, not
//! production panics (matches the in-crate test convention).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use multi_chain_wallet::btc;
use multi_chain_wallet::eth;
use multi_chain_wallet::sol;
use multi_chain_wallet::tron;
use multi_chain_wallet::{Coin, HdWallet};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn fixed_wallet() -> HdWallet {
    HdWallet::from_mnemonic(PHRASE, "test-passphrase").unwrap()
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    sha3::Keccak256::digest(data).into()
}

fn eth_address_from_pubkey(pubkey_uncompressed: &[u8]) -> String {
    // pubkey_uncompressed: 0x04 || X(32) || Y(32) — keccak(X||Y), last 20 bytes, EIP-55.
    assert_eq!(pubkey_uncompressed[0], 0x04);
    let hash = keccak256(&pubkey_uncompressed[1..]);
    let hex_str = hex::encode(&hash[12..]);

    let hash_hex = hex::encode(keccak256(hex_str.as_bytes()));
    let checksummed: String = hex_str
        .chars()
        .zip(hash_hex.bytes())
        .map(|(c, hb)| {
            let is_upper = c
                .to_digit(16)
                .map(|d| hb >= b'8' && d >= 8)
                .unwrap_or(false);
            if is_upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    format!("0x{checksummed}")
}

#[test]
fn sign_eth_transaction_produces_recoverable_eip1559_tx() {
    let wallet = fixed_wallet();
    let seed = wallet.seed();
    let (account, index, chain_id) = (3u32, 7u32, 1u64);
    let to = [9u8; 20];
    let value = [0u8; 32];
    let max_fee = [10u8; 32];
    let max_priority = [2u8; 32];
    let data = [0xABu8; 8];

    let signed = eth::sign_eth_transaction(
        seed,
        account,
        index,
        chain_id,
        0,
        &to,
        &value,
        21_000,
        &max_fee,
        &max_priority,
        &data,
    )
    .unwrap();

    // Wire format: 0x02 type byte || RLP list of 12 fields.
    assert_eq!(
        signed[0], 0x02,
        "EIP-1559 transactions start with type byte 0x02"
    );
    let rlp = rlp::Rlp::new(&signed[1..]);
    assert_eq!(rlp.item_count().unwrap(), 12, "12 RLP fields expected");
    assert_eq!(rlp.at(0).unwrap().as_val::<u64>().unwrap(), chain_id);
    assert_eq!(rlp.at(1).unwrap().as_val::<u64>().unwrap(), 0); // nonce
    assert_eq!(rlp.at(4).unwrap().as_val::<u64>().unwrap(), 21_000); // gas limit
    assert_eq!(rlp.at(5).unwrap().data().unwrap(), &to);
    assert_eq!(rlp.at(7).unwrap().data().unwrap(), &data);
    assert_eq!(
        rlp.at(8).unwrap().item_count().unwrap(),
        0,
        "access list must be present and empty"
    );

    // Rebuild the signing payload (0x02 || RLP 9-field list) and its hash.
    let v: u64 = rlp.at(9).unwrap().as_val().unwrap();
    let r_bytes = rlp.at(10).unwrap().data().unwrap();
    let s_bytes = rlp.at(11).unwrap().data().unwrap();
    let mut payload_stream = rlp::RlpStream::new();
    payload_stream.begin_list(9);
    payload_stream.append(&chain_id);
    payload_stream.append(&0u64);
    payload_stream.append(&max_priority.as_slice());
    payload_stream.append(&max_fee.as_slice());
    payload_stream.append(&21_000u64);
    payload_stream.append(&to.as_slice());
    payload_stream.append(&value.as_slice());
    payload_stream.append(&data.as_slice());
    payload_stream.begin_list(0);
    let mut signing_payload = vec![0x02u8];
    signing_payload.extend_from_slice(&payload_stream.out());
    let tx_hash = keccak256(&signing_payload);

    // recid = v - 35 - 2*chain_id (EIP-155); signature must recover to the
    // wallet's own Ethereum address.
    let recid_val = v - 35 - 2 * chain_id;
    assert!(
        recid_val <= 1,
        "recovery id must be 0 or 1, got {recid_val}"
    );
    let recid = k256::ecdsa::RecoveryId::from_byte(recid_val as u8).unwrap();
    let mut sig64 = [0u8; 64];
    sig64[..32].copy_from_slice(r_bytes);
    sig64[32..].copy_from_slice(s_bytes);
    let sig = k256::ecdsa::Signature::from_slice(&sig64).unwrap();
    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(&tx_hash, &sig, recid).unwrap();
    let recovered_addr = eth_address_from_pubkey(recovered.to_encoded_point(false).as_bytes());
    let expected_addr = eth::derive_eth_address(seed, account, index).unwrap();
    assert_eq!(
        recovered_addr, expected_addr,
        "signature must recover to the derived ETH address"
    );
}

#[test]
fn sign_eth_transaction_is_deterministic_and_key_dependent() {
    let wallet = fixed_wallet();
    let seed = wallet.seed();
    let to = [1u8; 20];
    let value = [0u8; 32];
    let fee = [1u8; 32];

    let a = eth::sign_eth_transaction(seed, 0, 0, 137, 5, &to, &value, 30_000, &fee, &fee, &[])
        .unwrap();
    let b = eth::sign_eth_transaction(seed, 0, 0, 137, 5, &to, &value, 30_000, &fee, &fee, &[])
        .unwrap();
    assert_eq!(a, b, "same inputs must produce identical signed tx bytes");

    let c = eth::sign_eth_transaction(seed, 0, 1, 137, 5, &to, &value, 30_000, &fee, &fee, &[])
        .unwrap();
    assert_ne!(a, c, "different derivation index must change the signature");
}

#[test]
fn sign_sol_transaction_output_is_signature_over_documented_message() {
    use ed25519_dalek::Verifier;

    let wallet = fixed_wallet();
    let seed = wallet.seed();
    let (account, index) = (1u32, 2u32);
    let blockhash = [0x42u8; 32];
    let instruction = [0x11u8, 0x22, 0x33];

    let out = sol::sign_sol_transaction(seed, account, index, &blockhash, &instruction).unwrap();

    let signing_key = sol::derive_sol_signing_key(seed, account, index).unwrap();
    let pubkey = signing_key.verifying_key().to_bytes();

    // Documented message: header(1,0,0) || signer pubkey || blockhash || data.
    let mut expected_msg = vec![1u8, 0, 0];
    expected_msg.extend_from_slice(&pubkey);
    expected_msg.extend_from_slice(&blockhash);
    expected_msg.extend_from_slice(&instruction);
    assert_eq!(out.len(), 64 + expected_msg.len());
    assert_eq!(
        &out[64..],
        &expected_msg,
        "payload after the signature must be the documented message"
    );

    // The 64-byte prefix must verify as an ed25519 signature over that message.
    let sig = ed25519_dalek::Signature::from_slice(&out[..64]).unwrap();
    let vk = signing_key.verifying_key();
    vk.verify(&expected_msg, &sig)
        .expect("ed25519 signature must verify against the derived key");
}

#[test]
fn sign_sol_is_deterministic_and_verifies_over_raw_message() {
    use ed25519_dalek::Verifier;

    let wallet = fixed_wallet();
    let seed = wallet.seed();
    let msg = b"solana transfer memo";

    let sig = sol::sign_sol(seed, 0, 0, msg).unwrap();
    assert_eq!(sig.bytes.len(), 64);

    let signing_key = sol::derive_sol_signing_key(seed, 0, 0).unwrap();
    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.bytes);
    signing_key
        .verifying_key()
        .verify(msg, &ed_sig)
        .expect("signature over the exact message must verify");

    let again = sol::sign_sol(seed, 0, 0, msg).unwrap();
    assert_eq!(
        sig.bytes, again.bytes,
        "ed25519 signing must be deterministic"
    );
}

#[test]
fn sign_tron_transaction_output_is_hash_plus_recoverable_signature() {
    let wallet = fixed_wallet();
    let seed = wallet.seed();
    let (account, index) = (0u32, 4u32);
    let ref_block_bytes = [0x00, 0x1A];
    let ref_block_hash = [0x5Bu8; 8];
    let expiration: i64 = 1_700_000_000_123;
    let contract = [0x41u8; 21];
    let call_data = [0x77u8; 16];
    let fee_limit: i64 = 1_000_000;
    let timestamp: i64 = 1_699_999_999_999;

    let out = tron::sign_tron_transaction(
        seed,
        account,
        index,
        &ref_block_bytes,
        &ref_block_hash,
        expiration,
        &contract,
        &call_data,
        fee_limit,
        timestamp,
    )
    .unwrap();

    // Wire format: tx_hash(32) || r(32) || s(32) || recid(1).
    assert_eq!(out.len(), 97);

    // The embedded hash must be SHA-256 over the documented tx_data layout.
    use sha2::Digest;
    let mut tx_data = Vec::new();
    tx_data.extend_from_slice(&ref_block_bytes);
    tx_data.extend_from_slice(&ref_block_hash);
    tx_data.extend_from_slice(&expiration.to_be_bytes());
    tx_data.extend_from_slice(&contract);
    tx_data.extend_from_slice(&call_data);
    tx_data.extend_from_slice(&fee_limit.to_be_bytes());
    tx_data.extend_from_slice(&timestamp.to_be_bytes());
    let expected_hash: [u8; 32] = sha2::Sha256::digest(&tx_data).into();
    assert_eq!(
        &out[..32],
        &expected_hash,
        "output must start with the tx hash"
    );

    // Recover the signer from (hash, r, s, recid) — must be the wallet's key.
    let mut sig64 = [0u8; 64];
    sig64[..32].copy_from_slice(&out[32..64]);
    sig64[32..].copy_from_slice(&out[64..96]);
    let sig = k256::ecdsa::Signature::from_slice(&sig64).unwrap();
    let recid = k256::ecdsa::RecoveryId::from_byte(out[96]).expect("recid byte must be 0 or 1");
    let recovered =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&expected_hash, &sig, recid).unwrap();
    let signing_key = tron::derive_tron_signing_key(seed, account, index).unwrap();
    let expected_pk = k256::ecdsa::VerifyingKey::from(&signing_key);
    assert_eq!(
        recovered.to_encoded_point(true).as_bytes(),
        expected_pk.to_encoded_point(true).as_bytes(),
        "recovered pubkey must equal the derived TRON key"
    );
}

#[test]
fn per_chain_derive_address_defaults_to_account0_index0() {
    let wallet = fixed_wallet();
    let seed = wallet.seed();

    let btc_addr = btc::derive_address(seed).unwrap();
    let btc_nested = btc::derive_btc_address(seed, 0, 0).unwrap();
    assert!(
        btc_addr.starts_with("bc1"),
        "P2WPKH bech32 address must start with bc1: {btc_addr}"
    );
    assert_eq!(btc_addr, btc_nested);

    assert_eq!(
        eth::derive_address(seed).unwrap(),
        eth::derive_eth_address(seed, 0, 0).unwrap()
    );
    assert_eq!(
        sol::derive_address(seed).unwrap(),
        sol::derive_sol_address(seed, 0, 0).unwrap()
    );
    assert_eq!(
        tron::derive_address(seed).unwrap(),
        tron::derive_tron_address(seed, 0, 0).unwrap()
    );
}

#[test]
fn wallet_sign_message_routes_solana_to_dedicated_api() {
    let wallet = fixed_wallet();
    let err = wallet.sign_message(Coin::Solana, 0, 0, b"hello");
    match err {
        Err(multi_chain_wallet::WalletError::SigningFailed(msg)) => {
            assert!(
                msg.contains("sign_message_ed25519"),
                "error must point to the ed25519 API, got: {msg}"
            );
        }
        other => unreachable!("expected SigningFailed routing error, got: {other:?}"),
    }
}
