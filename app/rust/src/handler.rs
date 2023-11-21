use version::{APP_VERSION, APP_NAME};
use message::boiler::*;
use alloc::borrow::Cow;
use alloc::string::String;
use vanadium_sdk::crypto::*;
use error::*;

use alloc::format;
use ui;
use alloc::vec::Vec;

use core::convert::TryInto;


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

pub fn handle_sign_tx<'a>(req: RequestSignTx) -> Result<ResponseSignTx<'a>> {

    if ui::sign_tx_validation(req.address.as_ref(), format!("{}", req.value).as_str()) {

        // Get private key
        let pkey = vanadium_sdk::crypto::EcfpPrivateKey::from_path(vanadium_sdk::crypto::CxCurve::Secp256k1, req.path.as_slice()).unwrap();

        // Compute Tx hash 
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut req.nonce.to_be_bytes().to_vec());

        let address = match req.address.as_ref().strip_prefix("0x") {
            Some(address) => address,
            None => req.address.as_ref()
        }; 
        buf.append(&mut hex::decode(address).unwrap());
        buf.append(&mut req.value.to_be_bytes().to_vec());

        match req.memo.as_bytes().len() {
            l if l < 0xFC => buf.append(&mut l.to_le_bytes()[..1].to_vec()),
            l if l <= u16::MAX.into() => {
                buf.push(0xFD);
                buf.append(&mut l.to_le_bytes()[..2].to_vec());
            },
            l if l <= u32::MAX.try_into().unwrap() => {
                buf.push(0xFE);
                buf.append(&mut l.to_le_bytes()[..4].to_vec());
            },
            l if l <= u64::MAX.try_into().unwrap() => {
                buf.push(0xFF);
                buf.append(&mut l.to_le_bytes()[..8].to_vec());
            },
            _l => return Err(AppError::new("Can't write to varint"))
        }

        buf.append(&mut req.memo.as_bytes().to_vec());

        let hash = CtxSha3::new().update(buf.as_slice()).r#final();
        let hash_s= hash.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();

        
        let (signature, v) = pkey.sign(CX_RND_RFC6979 | CX_LAST, CxMd::Sha256, &hash)?;

        let sig = signature.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
        
        Ok(ResponseSignTx {
            hash: Cow::Owned(hash_s),
            siglen: signature.len() as u32,
            sig: Cow::Owned(sig),
            v
        })
    }
    else {
        Err(AppError::new("Not validated"))
    } 
}