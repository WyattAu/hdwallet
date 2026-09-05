# multi-chain-wallet

HD wallet for Rust — BIP32/39/44 derivation with multi-chain address generation (BTC, ETH, SOL, TRON).

## Features

- **BIP39 mnemonics** — 24-word phrase generation and seed derivation
- **BIP44 paths** — Per-coin derivation path support
- **Multi-chain** — Bitcoin, Ethereum, Solana, Tron
- **No unsafe** — Pure Rust with `#![forbid(unsafe_code)]`

## Derivation Paths

| Coin | Path | SLIP-44 |
|---|---|---|
| Bitcoin | `m/84'/0'/account'/0/index` | 0 |
| Ethereum | `m/44'/60'/0'/0/0` | 60 |
| Solana | `m/44'/501'/0'/0'` | 501 |
| Tron | `m/44'/195'/0'/0/0` | 195 |

## Usage

```rust
use hdwallet::{HdWallet, Coin};

fn main() -> Result<(), hdwallet::WalletError> {
    let mnemonic = HdWallet::generate_mnemonic()?;
    println!("Mnemonic: {mnemonic}");

    let wallet = HdWallet::from_mnemonic(&mnemonic, "")?;

    let btc_addr = wallet.derive_address(Coin::Bitcoin)?;
    let eth_addr = wallet.derive_address(Coin::Ethereum)?;
    let sol_addr = wallet.derive_address(Coin::Solana)?;

    println!("BTC: {btc_addr}");
    println!("ETH: {eth_addr}");
    println!("SOL: {sol_addr}");

    Ok(())
}
```

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.

## Security

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md).
