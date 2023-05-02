use alloc::{borrow::Cow, format, vec, vec::Vec};

use bitcoin::Address;
use bitcoin::address::{NetworkUnchecked, NetworkChecked};

use crate::{message::message::{RequestGetWalletAddress, ResponseGetWalletAddress}, wallet::{WalletPolicy, ToScript}};

#[cfg(not(test))]
use vanadium_sdk::{ux::{app_loading_stop, ux_validate, UxItem, UxAction}, glyphs::{ICON_EYE, ICON_VALIDATE, ICON_CROSSMARK}};

#[cfg(not(test))]
use alloc::string::String;

use subtle::ConstantTimeEq;

use error::*;

// TODO: this is a dummy hmac until we implement SLIP-21
const DUMMY_HMAC: [u8; 32] = [0x42; 32];

const BIP32_FIRST_HARDENED_CHILD: u32 = 0x80000000u32;


impl WalletPolicy {
    fn is_standard(&self) -> bool {
        // TODO, for now we're optimistic
        true
    }
}

pub fn handle_get_wallet_address<'a>(req: RequestGetWalletAddress) -> Result<ResponseGetWalletAddress<'a>> {
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
        req.keys_info.iter().map(|s| s.as_ref()).collect::<Vec<&str>>()
    ) {
        Ok(w) => w,
        Err(err) => return Err(AppError::new(&format!("Invalid wallet policy: {}", err))),
    };

    
    let is_wallet_canonical = if req.wallet_hmac.len() == 0 {
        // check that it's a standard policy
        if !wallet_policy.is_standard() {
            return Err(AppError::new("Non-standard policy, and no hmac provided"));
        }
        true
    } else {
        let hmac = DUMMY_HMAC; // TODO: compute hmac using SLIP-21

        // check hmac
        if !bool::from(hmac.ct_eq(&req.wallet_hmac)) {
            return Err(AppError::new("Incorrect hmac"));
        }        

        false
    };

    let script = wallet_policy
        .to_script(req.change, req.address_index)
        .map_err(|_| AppError::new("Failed to produce script"))?;

    let addr: Address<NetworkChecked> = Address::from_script(script.as_script(), bitcoin::Network::Testnet)
        .map_err(|_| AppError::new("Failed to produce address"))?;

    Ok(ResponseGetWalletAddress { address: Cow::Owned(format!("{}", addr)) })
}


