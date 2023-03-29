use alloc::borrow::Cow;
use alloc::format;
use alloc::vec::Vec;
use vanadium_sdk::crypto::{EcfpPublicKey, CxCurve, derive_node_bip32};

use crate::{message::message::{RequestGetExtendedPubkey, ResponseGetExtendedPubkey}, crypto::{get_key_fingerprint, get_compressed_pubkey, get_checksum}};

use error::*;

pub fn handle_get_extended_pubkey<'a>(req: RequestGetExtendedPubkey) -> Result<ResponseGetExtendedPubkey<'a>> {
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
        get_key_fingerprint(&parent_pubkey)
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
    serialized_pubkey.extend_from_slice(&get_compressed_pubkey(&pubkey));

    // Checksum
    serialized_pubkey.extend_from_slice(&get_checksum(&serialized_pubkey).to_be_bytes());

    bitcoin::base58::encode(&serialized_pubkey);

    Ok(ResponseGetExtendedPubkey {
        pubkey: Cow::Owned(bitcoin::base58::encode(&serialized_pubkey)),
    })
}
