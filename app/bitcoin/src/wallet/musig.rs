use core::{convert::TryInto, ptr};

use hex_literal::hex;
use schnorr_fun::{musig::AggKey, fun::marker::Normal};
use vanadium_sdk::crypto::EcfpPublicKey;

use crate::error::AppError;

// by convention, chaincode for the aggregate key obtained by musig() expressions in descriptors.
pub const MUSIG_AGGR_CHAINCODE: [u8; 32] = hex!("868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965");


pub fn get_musig_bip32_tweaks(agg_key: &AggKey<Normal>, steps: Vec<u32>) -> Result<Vec<[u8; 32]>, AppError> {
    let mut result: Vec<[u8; 32]> = vec![];

    let mut cur_pubkey = agg_key.agg_public_key().to_bytes_uncompressed();
    let mut cur_chaincode = MUSIG_AGGR_CHAINCODE;

    for i in steps {
        if i >= 0x80000000u32 {
            return Err(AppError::new("Unhardened derivation step too high"));
        }
    
        let mut hmac_data: Vec<u8> = Vec::new();
        hmac_data.extend_from_slice(&EcfpPublicKey::from_slice(&cur_pubkey)?.to_compressed());
        hmac_data.extend_from_slice(&i.to_be_bytes());
    
        let hmac_result: [u8; 64] = vanadium_sdk::crypto::hmac_sha512(&cur_chaincode[..], &hmac_data);
    
        let sk: [u8; 32] = hmac_result[0..32].try_into().expect("Cannot fail");
        cur_chaincode = hmac_result[32..].try_into().expect("Cannot fail");

        if vanadium_sdk::secp256k1::secp256k1_ec_pubkey_tweak_add(
            ptr::null(),
            &mut cur_pubkey,
            sk.as_ptr(),
        ) != 1 {
            return Err(AppError::new("Failed to derive from musig2 aggregate key"));
        }

        result.push(sk);
    }

    Ok(result)
}


// TODO: add some tests
