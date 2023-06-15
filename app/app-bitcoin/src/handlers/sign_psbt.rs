use alloc::{borrow::Cow, format, vec, vec::Vec};

use crate::{
    message::message::{RequestSignPsbt, ResponseSignPsbt},
    wallet::{self, DescriptorTemplate, WalletPolicy},
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

pub fn handle_sign_psbt<'a>(req: RequestSignPsbt) -> Result<ResponseSignPsbt<'a>> {
    Ok(ResponseSignPsbt {
        partial_signature: vec![], // TODO
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_psbt() {
        todo!()
    }
}
