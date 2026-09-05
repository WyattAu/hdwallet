/// BIP-44 derivation path utilities.
///
/// Chain modules build paths manually as strings and parse with `bip32::DerivationPath`.
/// This module provides constants used across the crate.
/// BIP-44 purpose constant.
pub const PURPOSE: u32 = 44;

/// Hardened index offset.
pub const HARDENED: u32 = 0x80000000;
