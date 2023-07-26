use alloc::{borrow::Cow, format, vec, vec::Vec};

use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::Address;

use crate::{
    message::message::{RequestGetWalletAddress, ResponseGetWalletAddress},
    wallet::{ToScript, WalletPolicy},
};

#[cfg(not(test))]
use vanadium_sdk::{
    glyphs::{ICON_CROSSMARK, ICON_EYE, ICON_VALIDATE},
    ux::{app_loading_stop, ux_validate, UxAction, UxItem},
};

#[cfg(not(test))]
use alloc::string::String;

use subtle::ConstantTimeEq;

use error::*;

// TODO: this is a dummy hmac until we implement SLIP-21
const DUMMY_HMAC: [u8; 32] = [0x42; 32];

const BIP32_FIRST_HARDENED_CHILD: u32 = 0x80000000u32;

// TODO: implement UX to show derived address on screen

pub fn handle_get_wallet_address<'a>(
    req: RequestGetWalletAddress,
) -> Result<ResponseGetWalletAddress<'a>> {
    // Ok(ResponseGetWalletAddress {
    //     wallet_id: Cow::Owned(id.into()),
    //     wallet_hmac: Cow::Owned(hmac.into())
    // })

    if req.address_index >= BIP32_FIRST_HARDENED_CHILD {
        return Err(AppError::new("Address index too large"));
    }

    let wallet_policy = match WalletPolicy::new(
        req.name.into(),
        &req.descriptor_template.clone().into_owned(),
        req.keys_info
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<&str>>(),
    ) {
        Ok(w) => w,
        Err(err) => return Err(AppError::new(&format!("Invalid wallet policy: {}", err))),
    };

    let is_wallet_default = req.wallet_hmac.len() == 0;
    
    if is_wallet_default {
        // check that it's actually a standard policy
        if !wallet_policy.is_default() {
            return Err(AppError::new("Non-standard policy, and no hmac provided"));
        }
    } else {
        let hmac = DUMMY_HMAC; // TODO: compute hmac using SLIP-21

        // check hmac
        if !bool::from(hmac.ct_eq(&req.wallet_hmac)) {
            return Err(AppError::new("Incorrect hmac"));
        }
    }

    let script = wallet_policy
        .to_script(req.change, req.address_index)
        .map_err(|_| AppError::new("Failed to produce script"))?;

    let addr: Address<NetworkChecked> =
        Address::from_script(script.as_script(), bitcoin::Network::Testnet)
            .map_err(|_| AppError::new("Failed to produce address"))?;

    Ok(ResponseGetWalletAddress {
        address: Cow::Owned(format!("{}", addr)),
    })
}


// TODO: add more tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_wallet_address_singlesig_wit() {
        let req = RequestGetWalletAddress {
            name: "".into(),
            descriptor_template: "wpkh(@0/**)".into(),
            keys_info: vec!["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".into()],
            wallet_hmac: Cow::Owned([].into()),
            address_index: 0,
            change: false,
            display: false,
        };

        let resp = handle_get_wallet_address(req).unwrap();

        assert_eq!(resp.address, "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk");
    }
}
