use crate::Coin;

/// BIP44 derivation path components per coin.
///
/// Format: `m / purpose' / coin_type' / account' / change / address_index`
pub fn bip44_path(coin: Coin) -> &'static str {
    match coin {
        Coin::Bitcoin => "m/44'/0'/0'/0/0",
        Coin::Ethereum => "m/44'/60'/0'/0/0",
        Coin::Solana => "m/44'/501'/0'/0'",
        Coin::Tron => "m/44'/195'/0'/0/0",
        Coin::Liquid => "m/44'/0'/0'/0/0",
    }
}

/// Coin type numbers from SLIP-44.
pub fn slip44_coin_type(coin: Coin) -> u32 {
    match coin {
        Coin::Bitcoin => 0,
        Coin::Ethereum => 60,
        Coin::Solana => 501,
        Coin::Tron => 195,
        Coin::Liquid => 0,
    }
}
