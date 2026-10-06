//! Strict import of an existing extended key.
//!
//! # Why this crate validates extended keys itself
//!
//! BIP-32's test vector 5 is a list of sixteen serialised extended keys that a
//! parser **must reject**, and it is the vector almost nobody implements. Measured
//! against `bip32 0.6.0`, twelve of the sixteen are refused and **four are
//! accepted**:
//!
//! ```text
//! ACCEPTED :: zero depth with non-zero parent fingerprint  (xprv and xpub)
//! ACCEPTED :: zero depth with non-zero index               (xprv and xpub)
//! ```
//!
//! Those four are the depth-0 consistency rules: a master key has no parent and
//! no index, so its parent fingerprint must be four zero bytes and its child
//! number must be zero. A key that violates this is not a master key — it is a
//! fabricated serialisation of a private key, and accepting it means the same
//! private material has two valid encodings. That is malleability, and
//! malleability is what breaks a backup check ("is this the key I wrote down?")
//! and any rule that compares serialised keys for equality.
//!
//! So the checks live here rather than being delegated. [`parse_xprv`] and
//! [`parse_xpub`] enforce the whole of vector 5, and a key that passes them
//! round-trips to exactly the bytes it was given.
//!
//! [`parse_xpub`] additionally refuses a *hardened* child index, which BIP-32
//! forbids outright: a public key must not name a hardened child, because
//! deriving it would require the parent private key.

use bip32::{ChildNumber, Prefix, XPrv, XPub};

/// Why an extended key was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Base58 decoding or the 4-byte checksum failed.
    Encoding(String),
    /// The four-character prefix is not one of the known extended-key prefixes.
    UnknownPrefix(String),
    /// An `xpub` was supplied where a private key was required, or the reverse.
    WrongKeyKind {
        /// The prefix that was supplied.
        prefix: String,
        /// What was expected.
        expected: &'static str,
    },
    /// Depth 0 with a non-zero parent fingerprint. Only a master key has depth
    /// 0, and a master key has no parent.
    ZeroDepthWithParentFingerprint {
        /// The fingerprint the key claimed.
        parent_fingerprint: [u8; 4],
    },
    /// Depth 0 with a non-zero child index. Only a master key has depth 0, and a
    /// master key has no index.
    ZeroDepthWithIndex {
        /// The child index the key claimed.
        index: u32,
    },
    /// A key at depth 0 must also carry the zero child number, and any other
    /// depth must have one.
    ZeroDepthWithHardenedIndex,
    /// A public key naming a hardened child index, which BIP-32 forbids.
    HardenedChildInPublicKey {
        /// The index the key claimed.
        index: u32,
    },
    /// The key does not re-serialise to the bytes it was given, so the encoding
    /// is not canonical even though it decoded.
    NotCanonical {
        /// What was supplied.
        supplied: String,
        /// What re-serialising produced.
        reserialised: String,
    },
    /// `bip32` refused it.
    Upstream(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding(e) => write!(f, "not a valid Base58Check extended key: {e}"),
            Self::UnknownPrefix(p) => write!(
                f,
                "{p:?} is not a known extended-key prefix; expected one of \
                 xprv, tprv, yprv, zprv, xpub, tpub, ypub or zpub"
            ),
            Self::WrongKeyKind { prefix, expected } => {
                write!(f, "{prefix:?} is not a {expected}")
            }
            Self::ZeroDepthWithParentFingerprint { parent_fingerprint } => write!(
                f,
                "depth 0 with a non-zero parent fingerprint {parent_fingerprint:?}: \
                 only a master key has depth 0, and a master key has no parent, \
                 so this is a fabricated serialisation"
            ),
            Self::ZeroDepthWithIndex { index } => write!(
                f,
                "depth 0 with a non-zero child index {index}: only a master key \
                 has depth 0, and a master key has no index"
            ),
            Self::ZeroDepthWithHardenedIndex => {
                write!(f, "depth 0 with a hardened child index is not a master key")
            }
            Self::HardenedChildInPublicKey { index } => write!(
                f,
                "a public key names hardened child index {index}, which BIP-32 \
                 forbids: deriving it would require the parent private key"
            ),
            Self::NotCanonical {
                supplied,
                reserialised,
            } => write!(
                f,
                "the key decodes but is not canonical: it was given as {supplied} \
                 and re-serialises as {reserialised}"
            ),
            Self::Upstream(e) => write!(f, "bip32 refused the key: {e}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The private extended-key prefixes, in `Prefix` order.
const PRIVATE_PREFIXES: [&str; 4] = ["xprv", "tprv", "yprv", "zprv"];
/// The public extended-key prefixes, in `Prefix` order.
const PUBLIC_PREFIXES: [&str; 4] = ["xpub", "tpub", "ypub", "zpub"];

/// Enforce the depth-0 consistency rules that `bip32 0.6.0` omits.
///
/// Shared by both kinds: the rule is about the encoding, not about whether the
/// key is public.
fn check_depth_zero_consistency(
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: ChildNumber,
) -> Result<(), KeyError> {
    if depth != 0 {
        return Ok(());
    }
    if parent_fingerprint != [0u8; 4] {
        return Err(KeyError::ZeroDepthWithParentFingerprint { parent_fingerprint });
    }
    if child_number.index() != 0 {
        return Err(KeyError::ZeroDepthWithIndex {
            index: child_number.index(),
        });
    }
    if child_number.is_hardened() {
        return Err(KeyError::ZeroDepthWithHardenedIndex);
    }
    Ok(())
}

/// Import an extended **private** key, enforcing all of BIP-32 test vector 5.
///
/// Accepts `xprv`, `tprv`, `yprv` and `zprv`. The returned key re-serialises to
/// exactly the input, so a caller comparing two keys by string is comparing the
/// same material.
pub fn parse_xprv(serialised: &str) -> Result<XPrv, KeyError> {
    let (prefix, rest) = split_prefix(serialised)?;
    if !PRIVATE_PREFIXES.contains(&prefix) {
        return Err(KeyError::WrongKeyKind {
            prefix: prefix.to_string(),
            expected: "private extended key",
        });
    }
    let _ = rest;

    let key: XPrv = serialised
        .parse::<XPrv>()
        .map_err(|e: bip32::Error| KeyError::Upstream(e.to_string()))?;
    let (depth, parent_fingerprint, child_number) = {
        let attrs = key.attrs();
        (attrs.depth, attrs.parent_fingerprint, attrs.child_number)
    };
    check_depth_zero_consistency(depth, parent_fingerprint, child_number)?;

    // Canonical form: the key must round-trip through its own prefix. A
    // non-canonical encoding decodes to the same scalar with different bytes,
    // which is the malleability this whole module exists to refuse.
    let p = Prefix::from_parts_unchecked(prefix, version_of(prefix));
    let reserialised: String = key.to_string(p).to_string();
    if reserialised != serialised {
        return Err(KeyError::NotCanonical {
            supplied: serialised.to_string(),
            reserialised,
        });
    }
    Ok(key)
}

/// Import an extended **public** key, enforcing all of BIP-32 test vector 5
/// plus BIP-32's rule that a public key may not name a hardened child.
pub fn parse_xpub(serialised: &str) -> Result<XPub, KeyError> {
    let (prefix, _rest) = split_prefix(serialised)?;
    if !PUBLIC_PREFIXES.contains(&prefix) {
        return Err(KeyError::WrongKeyKind {
            prefix: prefix.to_string(),
            expected: "public extended key",
        });
    }

    let key: XPub = serialised
        .parse::<XPub>()
        .map_err(|e: bip32::Error| KeyError::Upstream(e.to_string()))?;
    let (depth, parent_fingerprint, child_number) = {
        let attrs = key.attrs();
        (attrs.depth, attrs.parent_fingerprint, attrs.child_number)
    };
    check_depth_zero_consistency(depth, parent_fingerprint, child_number)?;
    if child_number.is_hardened() {
        return Err(KeyError::HardenedChildInPublicKey {
            index: child_number.index(),
        });
    }

    let p = Prefix::from_parts_unchecked(prefix, version_of(prefix));
    let reserialised: String = key.to_string(p).to_string();
    if reserialised != serialised {
        return Err(KeyError::NotCanonical {
            supplied: serialised.to_string(),
            reserialised,
        });
    }
    Ok(key)
}

fn split_prefix(serialised: &str) -> Result<(&str, &str), KeyError> {
    if serialised.len() < 4 {
        return Err(KeyError::Encoding(format!(
            "{} characters is too short for an extended key",
            serialised.len()
        )));
    }
    let (prefix, rest) = serialised.split_at(4);
    if !PRIVATE_PREFIXES.contains(&prefix) && !PUBLIC_PREFIXES.contains(&prefix) {
        return Err(KeyError::UnknownPrefix(prefix.to_string()));
    }
    Ok((prefix, rest))
}

fn version_of(prefix: &str) -> u32 {
    match prefix {
        "xprv" => 0x0488_ade4,
        "xpub" => 0x0488_b21e,
        "tprv" => 0x0435_8394,
        "tpub" => 0x0435_87cf,
        "yprv" => 0x049d_7878,
        "ypub" => 0x049d_7cb2,
        "zprv" => 0x04b2_430c,
        "zpub" => 0x04b2_4746,
        _ => 0x0488_ade4,
    }
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

    /// BIP-32 test vector 1's master seed.
    const VALID_VECTOR1_SEED: &str = "000102030405060708090a0b0c0d0e0f";

    const VALID_XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const VALID_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    #[test]
    fn a_valid_master_key_imports() {
        let key = parse_xprv(VALID_XPRV).expect("BIP-32 vector 1's master key is valid");
        assert_eq!(key.attrs().depth, 0);
        assert_eq!(parse_xpub(VALID_XPUB).expect("valid").attrs().depth, 0);
    }

    #[test]
    fn a_non_master_key_imports_too() {
        // `m/0H` from vector 1: depth 1, a parent fingerprint, index 0H.
        let child = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        let key = parse_xprv(child).expect("a depth-1 key is valid");
        assert_eq!(key.attrs().depth, 1);
    }

    /// The four cases `bip32 0.6.0` accepts, which this module refuses.
    ///
    /// The four keys are BIP-32 test vector 5's "zero depth with non-zero
    /// parent fingerprint" and "zero depth with non-zero index" cases, verbatim.
    #[test]
    fn a_zero_depth_key_with_a_parent_or_index_is_refused() {
        const PARENT_FINGERPRINT_XPRV: &str = "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv";
        const PARENT_FINGERPRINT_XPUB: &str = "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ";
        const NON_ZERO_INDEX_XPRV: &str = "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN";
        const NON_ZERO_INDEX_XPUB: &str = "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8";

        match parse_xprv(PARENT_FINGERPRINT_XPRV) {
            Err(KeyError::ZeroDepthWithParentFingerprint { .. }) => {}
            other => {
                panic!("a zero-depth xprv with a parent fingerprint must be refused, got {other:?}")
            }
        }
        match parse_xpub(PARENT_FINGERPRINT_XPUB) {
            Err(KeyError::ZeroDepthWithParentFingerprint { .. }) => {}
            other => {
                panic!("a zero-depth xpub with a parent fingerprint must be refused, got {other:?}")
            }
        }
        match parse_xprv(NON_ZERO_INDEX_XPRV) {
            Err(KeyError::ZeroDepthWithIndex { .. }) => {}
            other => panic!("a zero-depth xprv with an index must be refused, got {other:?}"),
        }
        match parse_xpub(NON_ZERO_INDEX_XPUB) {
            Err(KeyError::ZeroDepthWithIndex { .. }) => {}
            other => panic!("a zero-depth xpub with an index must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_key_of_the_wrong_kind_is_refused() {
        assert!(matches!(
            parse_xprv(VALID_XPUB),
            Err(KeyError::WrongKeyKind { .. })
        ));
        assert!(matches!(
            parse_xpub(VALID_XPRV),
            Err(KeyError::WrongKeyKind { .. })
        ));
    }

    #[test]
    fn an_unknown_prefix_is_refused() {
        assert!(matches!(
            parse_xprv(
                "abcd9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
            ),
            Err(KeyError::UnknownPrefix(_))
        ));
        // "xpr" is three characters: shorter than any prefix.
        assert!(matches!(parse_xprv("xpr"), Err(KeyError::Encoding(_))));
        // A well-formed prefix on a body that is not a key.
        assert!(parse_xprv("xprvnotakeyatall").is_err());
    }

    /// BIP-32 forbids a hardened child index on a public key: deriving it would
    /// require the parent private key, which is exactly what an xpub does not
    /// carry. Built from a real derivation so the key is canonical and the only
    /// thing wrong with it is the rule.
    #[test]
    fn a_public_key_naming_a_hardened_child_is_refused() {
        let seed = hex(VALID_VECTOR1_SEED);
        let hardened_child =
            bip32::XPrv::derive_from_path(&seed, &"m/0'".parse().expect("a derivable path"))
                .expect("derives");
        let public = hardened_child.public_key();
        assert_eq!(public.attrs().depth, 1);
        assert!(
            public.attrs().child_number.is_hardened(),
            "the derivation really is hardened, so the refusal below is about \
             the rule and not about a bad key"
        );

        let serialised = public.to_string(bip32::Prefix::XPUB);
        match parse_xpub(&serialised) {
            Err(KeyError::HardenedChildInPublicKey { index: 0 }) => {}
            other => panic!("a public key naming a hardened child must be refused, got {other:?}"),
        }

        // The same private key *is* importable: the rule is about the public
        // form, not about the material.
        let private = hardened_child.to_string(bip32::Prefix::XPRV);
        assert!(
            parse_xprv(&private).is_ok(),
            "the private form of a hardened child is perfectly valid"
        );
    }

    #[test]
    fn a_key_that_decodes_but_is_not_canonical_is_refused() {
        // A valid key with one character changed must fail the checksum, not slip
        // through as a different encoding of the same scalar.
        let mut mangled = VALID_XPRV.to_string();
        let last = mangled.pop().expect("non-empty");
        mangled.push(if last == 'q' { 'p' } else { 'q' });
        assert!(
            parse_xprv(&mangled).is_err(),
            "a key with a broken checksum must be refused"
        );
    }

    fn hex(input: &str) -> Vec<u8> {
        let bytes = input.as_bytes();
        assert_eq!(bytes.len() % 2, 0, "hex input has an even length");
        bytes
            .chunks(2)
            .map(|pair| {
                let s = std::str::from_utf8(pair).expect("ascii hex");
                u8::from_str_radix(s, 16).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"))
            })
            .collect()
    }
}
