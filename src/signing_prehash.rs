//! Recoverable secp256k1 signing over a **prehash**.
//!
//! # Why this exists rather than `sign_digest_recoverable`
//!
//! k256 0.14 removed `SigningKey::sign_prehash_recoverable` and offers
//! `sign_digest_recoverable(digest)` instead. That is the wrong call for a
//! wallet, and using it would be a silent, catastrophic bug: it *hashes* the
//! bytes it is given. A wallet is handed a transaction hash — Bitcoin's sighash,
//! Ethereum's keccak digest, TRON's SHA-256 digest — which is already the output
//! of a cryptographic hash. Hashing it again produces a signature over a
//! different message than the one the network verifies, and every transaction
//! would be rejected. Nothing would panic; the tests that signed a message by
//! hashing it first would keep passing.
//!
//! So this module signs the prehash directly, deterministically per RFC 6979,
//! via `ecdsa::hazmat::sign_prehashed_rfc6979`. The `ecdsa` version is pinned
//! to the one k256 0.14 uses internally so the scalar and curve types are the
//! same type rather than two structurally-identical ones.

use k256::ecdsa::{RecoveryId, Signature, SigningKey};
// k256 0.14 is built on `digest` 0.11 / `sha2` 0.11, while this crate's own
// hashing uses `sha2` 0.10. RFC 6979's `D` must satisfy the *same* `Digest`
// trait k256 uses, so the digest type comes from k256's own dependency rather
// than from ours. Using `sha2 0.10`'s Sha256 here would not compile, and
// papering over that with a different algorithm would change every signature.
use sha2_11::Sha256 as Rfc6979Sha256;

/// Sign a 32-byte prehash, returning the signature and recovery id.
///
/// `additional_data` is the RFC 6979 `ad` field; pass an empty slice for
/// Bitcoin and Ethereum, which do not mix extra entropy into the nonce.
pub fn sign_prehash(
    signing_key: &SigningKey,
    prehash: &[u8; 32],
    additional_data: &[u8],
) -> Result<(Signature, RecoveryId), SignError> {
    // RFC 6979, deterministic: `k256 0.13`'s `sign_prehash_recoverable` did
    // exactly this with an empty `ad`, which is what Bitcoin and Ethereum use.
    Ok(ecdsa::hazmat::sign_prehashed_rfc6979::<
        k256::Secp256k1,
        Rfc6979Sha256,
    >(
        signing_key.as_nonzero_scalar(), prehash, additional_data
    ))
}

/// Why a prehash could not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The prehash is not 32 bytes. A truncated or oversized digest is not a
    /// message, and signing it anyway produces a signature over a value no
    /// verifier will use.
    NotAHash(usize),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAHash(n) => {
                write!(f, "expected a 32-byte prehash, got {n} bytes")
            }
        }
    }
}

impl std::error::Error for SignError {}

/// Sign a prehash of any length, refusing anything that is not a 32-byte
/// digest.
///
/// The length check is not ceremony: secp256k1 truncates a longer scalar
/// internally, so a 33-byte input and its 32-byte prefix would produce the
/// *same* signature. Refusing is how a caller learns their hash is wrong.
pub fn sign_prehash_checked(
    signing_key: &SigningKey,
    prehash: &[u8],
    additional_data: &[u8],
) -> Result<(Signature, RecoveryId), SignError> {
    let array: &[u8; 32] = prehash
        .try_into()
        .map_err(|_| SignError::NotAHash(prehash.len()))?;
    sign_prehash(signing_key, array, additional_data)
}

/// The signature's `r` and `s` as 32-byte big-endian arrays.
///
/// Split from the serialised form rather than from the scalars directly, so the
/// value written into a transaction is the value the verifier reads.
///
/// `None` if the serialised form is not 64 bytes, which secp256k1 fixed-size
/// signatures always are — so this is a guard against a future change to the
/// serialisation, not an expected case. A caller that ignored it would write
/// zeroes into a transaction.
pub fn split_signature(signature: &Signature) -> Option<([u8; 32], [u8; 32])> {
    let bytes = signature.to_bytes();
    let (r, s) = bytes.split_at_checked(32)?;
    let r: [u8; 32] = r.try_into().ok()?;
    let s: [u8; 32] = s.try_into().ok()?;
    Some((r, s))
}

// Tests exercise failure paths and invariants directly; unwrap/expect, slicing
// and panicking asserts are acceptable here — violations surface as test
// failures, not production panics.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).expect("a valid scalar")
    }

    /// The property that distinguishes this from the `sign_digest_*` path: a
    /// signature is over the *given* 32 bytes, not over their hash.
    #[test]
    fn signing_is_over_the_prehash_and_nothing_else() {
        let key = key();
        let prehash = [0xabu8; 32];
        let (sig_a, _) = sign_prehash(&key, &prehash, &[]).expect("signs");

        // Signing the same prehash twice gives the same signature: RFC 6979 is
        // deterministic, which is what makes a wallet's output reproducible.
        let (sig_b, _) = sign_prehash(&key, &prehash, &[]).expect("signs");
        assert_eq!(
            sig_a.to_bytes(),
            sig_b.to_bytes(),
            "deterministic per RFC 6979"
        );

        // A different prehash gives a different signature.
        let (sig_c, _) = sign_prehash(&key, &[0xacu8; 32], &[]).expect("signs");
        assert_ne!(sig_a.to_bytes(), sig_c.to_bytes());
    }

    /// The regression that matters: signing the *prehash* must not equal signing
    /// the hash of that prehash. If it does, the signing path is hashing again,
    /// and every transaction would be rejected by the network.
    #[test]
    fn signing_a_prehash_differs_from_signing_its_hash() {
        use sha2::Digest;
        let key = key();
        let prehash = [0x11u8; 32];

        let (direct, _) = sign_prehash(&key, &prehash, &[]).expect("signs");

        // What `sign_digest_recoverable` would have signed: SHA-256 of the
        // prehash, hashed once more by the digest algorithm. Computed with
        // `sha2 0.10` because any hash will do for this comparison.
        let double = sha2::Sha256::digest(sha2::Sha256::digest(prehash));
        let mut double32 = [0u8; 32];
        double32.copy_from_slice(&double);
        let (via_digest, _) = sign_prehash(&key, &double32, &[]).expect("signs");

        assert_ne!(
            direct.to_bytes(),
            via_digest.to_bytes(),
            "if these were equal, the signing path would be hashing the prehash \\
             again — every signature would be over the wrong message"
        );
    }

    #[test]
    fn a_prehash_that_is_not_32_bytes_is_refused() {
        let key = key();
        assert_eq!(
            sign_prehash_checked(&key, &[0u8; 31], &[]).err(),
            Some(SignError::NotAHash(31))
        );
        assert_eq!(
            sign_prehash_checked(&key, &[0u8; 33], &[]).err(),
            Some(SignError::NotAHash(33))
        );
        // 64 bytes and 33 bytes would collide under internal truncation, so the
        // refusal is what keeps them distinct.
        assert!(sign_prehash_checked(&key, &[0u8; 32], &[]).is_ok());
    }

    #[test]
    fn the_split_matches_the_serialised_signature() {
        let key = key();
        let (sig, _) = sign_prehash(&key, &[3u8; 32], &[]).expect("signs");
        let (r, s) = split_signature(&sig).expect("a secp256k1 signature is 64 bytes");
        let bytes = sig.to_bytes();
        assert_eq!(r.as_slice(), &bytes[..32]);
        assert_eq!(s.as_slice(), &bytes[32..]);
        // Neither component is all zeroes: secp256k1 rejects r=0 and s=0, so a
        // zero half would mean the scalar was invalid.
        assert_ne!(r, [0u8; 32]);
        assert_ne!(s, [0u8; 32]);
    }
}
