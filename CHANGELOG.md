Changelog](https://keepachangelog.com/); versions follow [semver](https://semver.org).
- **Strict extended-key import; `parse_xprv` / `parse_xpub`.** Measured against
  rules; a master key has no parent and no index; so accepting them means the
- `signing_prehash`; recoverable signing over a **prehash**, deterministic per
  `entropy.len() == KEY_SIZE + 1` with `KEY_SIZE = 32`; that is, exactly 33
  had generated; all of which were 24 words, because generation could only
  refused; with a note that `zoo ... wrong`, the obvious candidate, is in fact
  non-24 count with `WalletError::InvalidMnemonic`; matching the
- `tests/config_matrix.rs`: every tuning knob behavior-proven -