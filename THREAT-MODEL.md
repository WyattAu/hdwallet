# Threat Model: multi-chain-wallet
The seed is the root of all funds; everything downstream is a derivative.
| T4 | Weak entropy at generation | Spoofing | `generate_mnemonic` | `bip32::Mnemonic::random(OsRng, Language::English)`; OS CSPRNG | `tests/proptest.rs::generate_mnemonic_always_24_words`, `mnemonic_words_are_alphanumeric` |
## OPEN RISKS (missing mitigations: not fabricated)
- **OPEN-1; `word_count` parameter is accepted then ignored.**
- **OPEN-2; no negative test asserts seed/key absence from `Debug` output.**
- **OPEN-3; `HdWallet::seed()` returns a live reference to the master
- **OPEN-4; mnemonic/passphrase are plain `&str`.** No zeroize of the
- **OPEN-5; English wordlist only** (`Language::English`); non-English BIP39
- Hardware wallets, HSMs, secure enclaves; pure-software key custody.
- `sign_message` hashes non-32-byte messages with SHA-256; callers signing