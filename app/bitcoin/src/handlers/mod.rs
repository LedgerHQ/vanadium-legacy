mod get_extended_pubkey;
mod get_master_fingerprint;
mod get_version;
mod get_wallet_address;
mod register_wallet;
mod sign_psbt;

pub use self::get_extended_pubkey::handle_get_extended_pubkey;
pub use self::get_master_fingerprint::handle_get_master_fingerprint;
pub use self::get_version::handle_get_version;
pub use self::get_wallet_address::handle_get_wallet_address;
pub use self::register_wallet::handle_register_wallet;
pub use self::sign_psbt::handle_sign_psbt;
