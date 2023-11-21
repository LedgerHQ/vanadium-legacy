use vanadium_sdk::glyphs::{ICON_CROSSMARK, ICON_EYE, ICON_VALIDATE};
use vanadium_sdk::ux::*;
use alloc::string::String;

pub fn sign_tx_validation(to: &str, amount: &str) -> bool {
    let sign_ui: [UxItem; 5] = [
        UxItem {
            icon: Some(&ICON_EYE),
            line1: "Review",
            line2: Some("Transaction"),
            action: UxAction::None,
        },
        UxItem {
            icon: Some(&ICON_EYE),
            line1: "To",
            line2: Some(to),
            action: UxAction::None,
        },
        UxItem {
            icon: Some(&ICON_EYE),
            line1: "Amount",
            line2: Some(amount),
            action: UxAction::None,
        },
        UxItem {
            icon: Some(&ICON_VALIDATE),
            line1: "Accept",
            line2: Some("and sign"),
            action: UxAction::Validate,
        },
        UxItem {
            icon: Some(&ICON_CROSSMARK),
            line1: "Reject",
            line2: None,
            action: UxAction::Reject,
        },
    ];

    app_loading_stop();
    ux_validate(&sign_ui)
}

pub fn address_validation(address: &String) -> bool {
    
    let validate_ui: [UxItem; 5] = [
            UxItem {
                icon: Some(&ICON_EYE),
                line1: "Confirm Address",
                line2: None,
                action: UxAction::None,
            },
            UxItem {
                icon: Some(&ICON_EYE),
                line1: &address[..16],
                line2: Some(&address[16..32]),
                action: UxAction::None,
            },
            UxItem {
                icon: Some(&ICON_EYE),
                line1: &address[32..],
                line2: None,
                action: UxAction::None,
            },
            UxItem {
                icon: Some(&ICON_VALIDATE),
                line1: "Accept",
                line2: Some("and send"),
                action: UxAction::Validate,
            },
            UxItem {
                icon: Some(&ICON_CROSSMARK),
                line1: "Reject",
                line2: None,
                action: UxAction::Reject,
            }
        ];
        app_loading_stop();
        
        ux_validate(&validate_ui)
}