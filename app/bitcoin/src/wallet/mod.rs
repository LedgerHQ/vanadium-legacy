mod wallet;
mod script;
mod merkle;

pub use self::wallet::{KeyOrigin, KeyInformation, KeyPlaceholder, WalletPolicy, SegwitVersion};
pub use self::wallet::DescriptorTemplate;
pub use self::script::ToScript;