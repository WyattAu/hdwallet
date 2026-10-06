// `expect` and `panic!` are how a conformance test reports a violation of
// the specification; the crate-level denies are production rules.
#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

//! BIP-32 conformance, against the specification's own vectors.
//!
//! This suite exists because the crate's round-trip tests prove nothing about
//! derivation: a wallet that derives *consistently wrong* addresses round-trips
//! perfectly. Every assertion below compares against `bip-0032.mediawiki`'s
//! published data, transcribed into [`crate::bip32_vectors`].

use bip32::{Prefix, XPrv, XPub};
use multi_chain_wallet::bip32_vectors::{INVALID, VALID};
use multi_chain_wallet::extended_key;

/// Parse a `m/0H/1/2H/...` path as the specification writes it.
fn path(spec: &str) -> bip32::DerivationPath {
    // `DerivationPath` requires the literal leading "m"; `m/0'` and `m/0` both
    // parse, `/0'` does not. Starting the buffer with "m" is what makes the
    // master case and the child cases the same code path.
    let mut normalised = String::with_capacity(spec.len() + 1);
    normalised.push('m');
    for segment in spec.split('/').skip(1) {
        if segment == "m" {
            continue;
        }
        let (index, hardened) = match segment.strip_suffix('H') {
            Some(index) => (index, true),
            None => (segment, false),
        };
        normalised.push('/');
        normalised.push_str(index);
        // bip32 0.6 writes a hardened index with a trailing `'`, and a soft one
        // with no suffix. 0.5 used `H`/`h`, which 0.6 no longer parses — worth
        // stating, because a path that used to parse and now does not is a
        // migration hazard for anyone storing derived paths as strings.
        if hardened {
            normalised.push('\'');
        }
    }
    // `m` alone is the master key: an empty derivation path, which is not the
    // same as the string "m".
    if normalised.is_empty() {
        return "m"
            .parse::<bip32::DerivationPath>()
            .expect("the master path parses");
    }
    normalised
        .parse::<bip32::DerivationPath>()
        .unwrap_or_else(|e| panic!("{spec:?} is not a derivable path: {e}"))
}

/// Every valid vector: the derived private and public keys must match exactly.
#[test]
fn derivation_matches_every_published_bip32_vector() {
    for vector in VALID {
        let seed = hex(vector.seed);
        for (spec_path, expected_pub, expected_prv) in vector.chains {
            let derived = XPrv::derive_from_path(&seed, &path(spec_path))
                .unwrap_or_else(|e| panic!("{} {spec_path}: {e}", vector.name));

            assert_eq!(
                derived.to_string(Prefix::XPRV).as_str(),
                *expected_prv,
                "{} {spec_path}: the extended *private* key must match the \
                 specification byte for byte",
                vector.name
            );
            assert_eq!(
                derived.public_key().to_string(Prefix::XPUB),
                *expected_pub,
                "{} {spec_path}: the extended *public* key must match the \
                 specification byte for byte",
                vector.name
            );
        }
    }
}

/// Vector 3 exists to catch leading-zero handling: its seed begins
/// `4b3815…` and one of its derived keys has a fingerprint with leading zero
/// bytes. An implementation that trims or zero-pads incorrectly still passes
/// vectors 1 and 2.
#[test]
fn leading_zero_bytes_are_retained() {
    let vector = VALID
        .iter()
        .find(|v| v.name == "vector 3")
        .expect("vector 3 is present");
    let seed = hex(vector.seed);
    let master = XPrv::new(&seed).expect("master key derives");

    // The specification's master xprv for vector 3, verbatim.
    let (spec_path, expected_pub, expected_prv) = vector.chains[0];
    assert_eq!(
        master.to_string(Prefix::XPRV).as_str(),
        expected_prv,
        "{spec_path}"
    );
    assert_eq!(
        master.public_key().to_string(Prefix::XPUB),
        expected_pub,
        "{spec_path}"
    );

    // And the hardened child, which is where the leading zeros land.
    let child = XPrv::derive_from_path(&seed, &path("m/0H")).expect("derives");
    assert_eq!(child.to_string(Prefix::XPRV).as_str(), vector.chains[1].2);
}

/// A hardened child cannot be derived from a *public* key. This is BIP-32's
/// central security property, and a wallet that violates it has published the
/// ability to spend from an account xpub.
#[test]
fn a_hardened_child_cannot_be_derived_from_a_public_key() {
    let seed = hex(VALID[0].seed);
    let account = XPrv::derive_from_path(&seed, &path("m/0H/1")).expect("account key");
    let account_pub = account.public_key();

    // Soft derivation from a public key works, by design: that is the point of
    // handing out an account xpub for watch-only use.
    let soft = bip32::ChildNumber::new(0, false).expect("index 0");
    assert!(
        account_pub.derive_child(soft).is_ok(),
        "a soft child is derivable from a public key — that is what an account \
         xpub is for"
    );

    // Hardened derivation must be refused. If it succeeded, an attacker holding
    // the account xpub could walk into hardened children — and BIP-32 is
    // explicit that a parent xpub plus any non-hardened child private key *is*
    // the parent private key.
    let hardened = bip32::ChildNumber::new(0, true).expect("index 0 hardened");
    let result = account_pub.derive_child(hardened);
    assert!(
        result.is_err(),
        "**a public key derived a hardened child** — BIP-32's central security \
         property is violated, and an xpub holder could spend"
    );
    assert_eq!(
        result.err(),
        Some(bip32::Error::ChildNumber),
        "and the refusal must name the child number as the reason, so a caller \
         can tell 'this is hardened' from 'the key was malformed'"
    );
}

/// **Vector 5: all sixteen invalid extended keys must be refused** — by
/// [`multi_chain_wallet::extended_key`], not by `bip32`.
///
/// `bip32 0.6.0` refuses twelve of the sixteen and accepts four: both
/// "zero depth with non-zero parent fingerprint" keys and both "zero depth with
/// non-zero index" keys. The crate therefore validates extended keys itself
/// (see `src/extended_key.rs`), which is also how it gained an import path it
/// never had — `bip32 0.5` had no `FromStr` at all.
///
///
/// This is the vector almost nobody implements. Each case is a Base58Check
/// extended key whose encoding is malformed in a specific way — a public key
/// carrying the private version prefix, an invalid pubkey prefix, a bad
/// checksum, zero depth and parent fingerprint. A parser that accepts any of
/// them will hand out addresses derived from attacker-chosen material, and a
/// parser that accepts *only* some of them is still wrong: which ones it
/// tolerates is decided by the attacker's preference.
#[test]
fn every_invalid_extended_key_is_refused() {
    for case in INVALID {
        // An xpub must not parse as a private key, and vice versa.
        // An xpub must not import as a private key and an xprv must not import
        // as a public one. Both directions are checked, because a parser that
        // only validates the four-character prefix lets half the vector through.
        let is_public = case.key.starts_with("xpub");
        let result = if is_public {
            extended_key::parse_xpub(case.key).map(|_| "parsed")
        } else {
            extended_key::parse_xprv(case.key).map(|_| "parsed")
        };
        assert!(
            result.is_err(),
            "{} ({}): must be refused, and it imported as {:?}",
            case.key,
            case.reason,
            result
        );
    }
}

/// A key that parses must also round-trip to the same string. Serialisation is
/// where a wallet loses a key silently: it derives correctly, prints something
/// that looks right, and the user restores into a different wallet.
#[test]
fn a_parsed_key_serialises_back_to_itself() {
    let seed = hex(VALID[0].seed);
    for (spec_path, expected_pub, expected_prv) in VALID[0].chains {
        let derived = XPrv::derive_from_path(&seed, &path(spec_path)).expect("derives");

        let serialised = derived.to_string(Prefix::XPRV);
        let reparsed: XPrv = serialised.as_str().parse().expect("re-parses");
        assert_eq!(
            reparsed.to_string(Prefix::XPRV).as_str(),
            *expected_prv,
            "{spec_path}"
        );

        let pub_serialised = derived.public_key().to_string(Prefix::XPUB);
        let pub_reparsed: XPub = pub_serialised.parse().expect("the public key re-parses");
        assert_eq!(
            pub_reparsed.to_string(Prefix::XPUB),
            *expected_pub,
            "{spec_path}"
        );
    }
}

/// Depth and parent fingerprint are part of the key, not decoration: they are
/// what proves a key came from the derivation the caller asked for.
#[test]
fn depth_and_parent_fingerprint_track_the_path() {
    let seed = hex(VALID[0].seed);
    let master = XPrv::new(&seed).expect("derives");
    assert_eq!(master.attrs().depth, 0, "the master key is at depth 0");
    assert_eq!(
        master.attrs().parent_fingerprint,
        [0u8; 4],
        "and has no parent"
    );

    let expected_depths = [0usize, 1, 2, 3, 4, 5];
    for ((spec_path, _, _), expected_depth) in VALID[0].chains.iter().zip(expected_depths) {
        let derived = XPrv::derive_from_path(&seed, &path(spec_path)).expect("derives");
        assert_eq!(
            derived.attrs().depth,
            expected_depth as u8,
            "{spec_path}: depth must match the path length"
        );
    }

    // A child at depth 1 carries the master's fingerprint.
    let child = XPrv::derive_from_path(&seed, &path("m/0H")).expect("derives");
    assert_eq!(child.attrs().depth, 1);
    assert_eq!(
        child.attrs().parent_fingerprint,
        master.public_key().fingerprint(),
        "the child names its parent"
    );
}

/// BIP-32 requires the implementation to reject a seed that produces an
/// invalid master key. `XPrv::new` is the chokepoint, so it is what we test.
#[test]
fn an_empty_seed_is_refused_rather_than_producing_a_weak_key() {
    assert!(
        XPrv::new(&[]).is_err(),
        "a zero-length seed must not become a master key"
    );
    assert!(
        XPrv::new(&[0u8; 1]).is_err(),
        "and neither must a one-byte seed"
    );
    // BIP-32 says a seed between 128 and 512 bits; the upper bound is a limit,
    // not a requirement, so a long seed is fine.
    assert!(
        XPrv::new(&[0u8; 64]).is_ok(),
        "64 bytes is a valid seed length"
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
