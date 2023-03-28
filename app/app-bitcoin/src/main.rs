#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;
extern crate bitcoin;
extern crate byteorder;
extern crate quick_protobuf;
extern crate vanadium_sdk;

extern crate hex_literal;

#[cfg(not(target_arch = "riscv32"))]
extern crate core;

mod error;
mod message;
mod ui;
mod version;
mod crypto;

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::{vec, format};
use alloc::vec::Vec;
use quick_protobuf::{BytesReader, BytesWriter, MessageRead, MessageWrite, Writer};

use error::*;
use message::message::mod_Request::OneOfrequest;
use message::message::mod_Response::OneOfresponse;
use message::message::*;

use vanadium_sdk::crypto::{CxCurve, EcfpPublicKey, derive_node_bip32, EcfpPrivateKey};
use vanadium_sdk::fatal;

fn handle_get_version<'a>() -> Result<ResponseGetVersion<'a>> {
    Ok(ResponseGetVersion {
        version: Cow::Borrowed("0.0.1"),
    })
}

fn handle_get_master_fingerprint() -> Result<ResponseGetMasterFingerprint> {
    Ok(ResponseGetMasterFingerprint {
        fingerprint: vanadium_sdk::crypto::get_master_fingerprint()?,
    })
}


fn handle_get_extended_pubkey<'a>(req: RequestGetExtendedPubkey) -> Result<ResponseGetExtendedPubkey<'a>> {
    if req.display {
        return Err(AppError::new("Not yet implemented")); // TODO
    }

    // Check the path depth
    const MAX_DEPTH: usize = 10;
    if req.bip32_path.len() > MAX_DEPTH {
        return Err(AppError::new(&format!(
            "Too many derivation steps in bip32 path: the maximum is {}",
            MAX_DEPTH
        )));
    }


    let parent_fpr: u32 = if req.bip32_path.len() == 0 {
        0
    } else {
        let parent_path = &req.bip32_path[..req.bip32_path.len() - 1];
        let parent_pubkey: EcfpPublicKey = EcfpPublicKey::from_path(CxCurve::Secp256k1, parent_path)?;
        crypto::get_key_fingerprint(&parent_pubkey)
    };

    let mut privkey_bytes = [0u8; 32];
    let mut chaincode = [0u8; 32];
    derive_node_bip32(
        CxCurve::Secp256k1,
        &req.bip32_path,
        Some(&mut privkey_bytes),
        Some(&mut chaincode)
    )?;

    // TODO: avoid double derivation; currently no way of getting chaincode and pubkey from the sdk
    let pubkey: EcfpPublicKey = EcfpPublicKey::from_path(CxCurve::Secp256k1, &req.bip32_path)?;

    let child_number = req.bip32_path.last().cloned().unwrap_or(0);

    let mut serialized_pubkey = Vec::new();

    // Version
    serialized_pubkey.extend_from_slice(&0x043587CFu32.to_be_bytes()); // TODO: generalize to other networks

    // Depth
    if req.bip32_path.len() > 10 {
        return Err(AppError::new("Too many derivation steps in bip32 path: the maximum is 10"));
    }
    serialized_pubkey.push(req.bip32_path.len() as u8);

    // Parent Fingerprint
    serialized_pubkey.extend_from_slice(&parent_fpr.to_be_bytes());

    // Child number
    serialized_pubkey.extend_from_slice(&child_number.to_be_bytes());

    // chain_code
    serialized_pubkey.extend_from_slice(&chaincode);

    // Compressed pubkey
    serialized_pubkey.extend_from_slice(&crypto::get_compressed_pubkey(&pubkey));

    // Checksum
    serialized_pubkey.extend_from_slice(&crypto::get_checksum(&serialized_pubkey).to_be_bytes());

    bitcoin::base58::encode(&serialized_pubkey);

    Ok(ResponseGetExtendedPubkey {
        pubkey: Cow::Owned(bitcoin::base58::encode(&serialized_pubkey)),
    })
}


fn set_error(msg: &'_ str) -> ResponseError {
    ResponseError {
        error_msg: Cow::Borrowed(msg),
    }
}

impl From<&'static str> for ResponseError<'_> {
    fn from(msg: &'static str) -> Self {
        ResponseError {
            error_msg: Cow::Borrowed(msg),
        }
    }
}

fn handle_req_(buffer: &[u8]) -> Result<Response> {
    let pb_bytes = buffer.to_vec();
    let mut reader = BytesReader::from_bytes(&pb_bytes);
    let request: Request = Request::from_reader(&mut reader, &pb_bytes)?;

    let response = Response {
        response: match request.request {
            OneOfrequest::get_version(_) => OneOfresponse::get_version(handle_get_version()?),
            OneOfrequest::get_master_fingerprint(_) => OneOfresponse::get_master_fingerprint(handle_get_master_fingerprint()?),
            OneOfrequest::get_extended_pubkey(req) => OneOfresponse::get_extended_pubkey(handle_get_extended_pubkey(req)?),
            OneOfrequest::None => OneOfresponse::error("request unset".into()),
        },
    };

    Ok(response)
}

fn handle_req(buffer: &[u8]) -> Vec<u8> {
    let error_msg: String;

    let response = match handle_req_(buffer) {
        Ok(response) => response,
        Err(error) => {
            error_msg = error.to_string();
            Response {
                response: OneOfresponse::error(set_error(&error_msg)),
            }
        }
    };

    let mut out = vec![0; response.get_size()];
    let mut writer = Writer::new(BytesWriter::new(&mut out));
    response.write_message(&mut writer).unwrap();

    out.to_vec()
}

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    fatal("panic");
    loop {}
}

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub fn atexit(_f: *const u8) {
    /* required by libcrypto */
    fatal("atexit");
    panic!("atexit called");
}

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub fn _start(_argc: isize, _argv: *const *const u8) -> isize {
    main();
    0
}


#[start]
pub extern "C" fn main() {
    version::setup_app();

    vanadium_sdk::ux::ux_idle();
    loop {
        let buffer = vanadium_sdk::xrecv(512);

        vanadium_sdk::ux::app_loading_start("Handling request...\x00");

        let result = handle_req(&buffer);

        vanadium_sdk::ux::app_loading_stop();
        vanadium_sdk::ux::ux_idle();

        vanadium_sdk::xsend(&result);
    }
}
