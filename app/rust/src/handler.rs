use version::{APP_VERSION, APP_NAME};
use message::boiler::*;
use alloc::borrow::Cow;
use alloc::string::String;
use vanadium_sdk::crypto::*;
use error::*;

use alloc::format;
use ui;


pub fn handle_get_version<'a>() -> ResponseGetVersion<'a> {
    ResponseGetVersion {
        version: Cow::Borrowed(core::str::from_utf8(APP_VERSION.as_slice()).unwrap()),
    }
}

pub fn handle_get_appname<'a>() -> ResponseGetAppName<'a> {
    ResponseGetAppName {
        appname: Cow::Borrowed(core::str::from_utf8(APP_NAME.as_slice()).unwrap()),
    }
}

pub fn handle_get_pubkey<'a>(req: &RequestGetPubKey) -> Result<ResponseGetPubKey<'a>> {
    
    // Get public key
    let pkey = vanadium_sdk::crypto::EcfpPrivateKey::from_path(vanadium_sdk::crypto::CxCurve::Secp256k1, req.path.as_slice()).unwrap();
    let pubkey = pkey.pubkey()
        .unwrap()
        .as_bytes()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();


    // Get chain code
    let chain_code = pkey.chaincode()
        .unwrap()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();

    if req.display {
        // Get address from public key
        let digest = CtxSha3::new().update(&pubkey.as_bytes()[1..]).r#final();
        let address = hex::encode(&digest[12..]);

        // Check address validation and return the appropriate response
        if ui::address_validation(&address) {
            Ok(ResponseGetPubKey {
                pubkey: Cow::Owned(pubkey),
                chaincode: Cow::Owned(chain_code),
            })
        } else {
            Err(AppError::new("Not validated"))
        }
    } else {
        // If `req.display` is false, return the positive response
        Ok(ResponseGetPubKey {
            pubkey: Cow::Owned(pubkey),
            chaincode: Cow::Owned(chain_code),
        })
    }
}