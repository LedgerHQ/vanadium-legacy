use alloc::{borrow::Cow, format, vec, vec::Vec};

use crate::{
    message::message::{RequestRegisterWallet, ResponseRegisterWallet},
    wallet::{DescriptorTemplate, WalletPolicy},
};

#[cfg(not(test))]
use vanadium_sdk::{
    glyphs::{ICON_CROSSMARK, ICON_EYE, ICON_VALIDATE},
    ux::{app_loading_stop, ux_validate, UxAction, UxItem},
};

#[cfg(not(test))]
use alloc::string::String;

use error::*;

// TODO: this is a dummy hmac until we implement SLIP-21
const DUMMY_HMAC: [u8; 32] = [0x42; 32];

pub fn ui_validate_wallet_policy(wallet_policy: &WalletPolicy) -> bool {
    #[cfg(test)]
    {
        true
    }
    #[cfg(not(test))]
    {
        let mut ux: Vec<UxItem> = vec![
            UxItem {
                icon: Some(&ICON_EYE),
                line1: "Register wallet",
                line2: None,
                action: UxAction::None,
            },
            UxItem {
                icon: Some(&ICON_EYE),
                line1: "Wallet name:",
                line2: Some(&wallet_policy.name),
                action: UxAction::None,
            },
            UxItem {
                icon: None,
                line1: "Wallet policy",
                line2: Some(wallet_policy.descriptor_template_raw()),
                action: UxAction::None,
            },
        ];

        let first_lines: Vec<String> = (0..wallet_policy.key_information.len())
            .map(|pos| format!("Key @{}", pos))
            .collect();

        for (pos, key) in wallet_policy.key_information_raw().enumerate() {
            ux.push(UxItem {
                icon: None,
                line1: &first_lines[pos],
                line2: Some(key),
                action: UxAction::None,
            });
        }

        ux.extend([
            UxItem {
                icon: Some(&ICON_VALIDATE),
                line1: "Register",
                line2: Some("wallet"),
                action: UxAction::Validate,
            },
            UxItem {
                icon: Some(&ICON_CROSSMARK),
                line1: "Reject",
                line2: None,
                action: UxAction::Reject,
            },
        ]);

        // TODO: ux framework doesn't have pagination, so this will truncate long strings

        // TODO: the screen flickers in a weird way without this; why does that happen?
        app_loading_stop();

        ux_validate(&ux)
    }
}

pub fn handle_register_wallet<'a>(
    req: RequestRegisterWallet,
) -> Result<ResponseRegisterWallet<'a>> {
    if !is_policy_name_acceptable(&req.name) {
        return Err(AppError::new("Invalid policy name"));
    }

    let wallet_policy = WalletPolicy::new(
        req.name.into(),
        &req.descriptor_template.clone().into_owned(),
        req.keys_info
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<&str>>(),
    )
    .map_err(|err| AppError::new(&format!("Invalid wallet policy: {}", err)))?;

    if !wallet_policy.is_acceptable() {
        return Err(AppError::new("Unacceptable or invalid policy"));
    }

    if !ui_validate_wallet_policy(&wallet_policy) {
        return Err(AppError::new("Denied by the user"));
    }

    let id = wallet_policy.id();
    let hmac = DUMMY_HMAC; // TODO: compute hmac using SLIP-21

    Ok(ResponseRegisterWallet {
        wallet_id: Cow::Owned(id.into()),
        wallet_hmac: Cow::Owned(hmac.into()),
    })
}

const MAX_WALLET_NAME_LENGTH: usize = 64;

fn is_policy_name_acceptable(name: &str) -> bool {
    let name_len = name.len();

    // between 1 and MAX_WALLET_NAME_LENGTH characters
    if name_len == 0 || name_len > MAX_WALLET_NAME_LENGTH {
        return false;
    }

    // first and last characters must not be whitespace
    if name.chars().nth(0) == Some(' ') || name.chars().nth(name_len - 1) == Some(' ') {
        return false;
    }

    // only allow ascii characters in the range from 0x20 to 0x7E (inclusive)
    for c in name.chars() {
        if c < '\u{0020}' || c > '\u{007E}' {
            return false;
        }
    }

    true
}


impl WalletPolicy {
    // TODO
    fn is_acceptable(&self) -> bool {
        match self.descriptor_template {
            DescriptorTemplate::Pkh(_) => true,
            DescriptorTemplate::Wpkh(_) => true,
            DescriptorTemplate::Sh(_) => true,
            DescriptorTemplate::Wsh(_) => true,
            DescriptorTemplate::Tr(..) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    const H: u32 = 0x80000000u32;

    #[test]
    fn test_register_wallet() {
        let req = RequestRegisterWallet {
            name: "Cold storage".into(),
            descriptor_template: "sh(wsh(sortedmulti(2,@0/**,@1/**)))".into(),
            keys_info: vec![
                Cow::Borrowed("[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g"),
                Cow::Borrowed("[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY"),
            ],
        };

        let resp = handle_register_wallet(req);

        // hmac 1f498e7444841b883c4a63e2b88a5cad297c289d235794f8e3e17cf559ed0654
        // id 763926f53be53ad89a9248dc15bc2f3ed577a59a87d81cd88f14279b263b31f6

        assert_eq!(
            resp.unwrap().wallet_id.as_ref(),
            hex!("763926f53be53ad89a9248dc15bc2f3ed577a59a87d81cd88f14279b263b31f6"),
        );
    }
}
