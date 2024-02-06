use core::{convert::TryInto, ptr};

use bitcoin::Psbt;
use hex_literal::hex;
use schnorr_fun::fun::marker::{Public, Zero};
use schnorr_fun::fun::{Point, Scalar};
use schnorr_fun::{musig::AggKey, fun::marker::Normal};
use vanadium_sdk::crypto::EcfpPublicKey;

use crate::error::*;

use crate::wallet::HARDENED_INDEX;

// by convention, chaincode for the aggregate key obtained by musig() expressions in descriptors.
pub const MUSIG_AGGR_CHAINCODE: [u8; 32] = hex!("868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965");


// TODO: this should rather replace agg_key with a pubkey, and at that point it's
// a generic feature for bip32
pub fn get_musig_bip32_tweaks(agg_key: &AggKey<Normal>, steps: Vec<u32>) -> Result<Vec<[u8; 32]>> {
    let mut result: Vec<[u8; 32]> = vec![];

    let mut cur_pubkey = agg_key.agg_public_key().to_bytes_uncompressed();
    let mut cur_chaincode = MUSIG_AGGR_CHAINCODE;

    let mut hmac_data = Vec::with_capacity(cur_pubkey.len() + 4);

    for (index, &step) in steps.iter().enumerate() {
        if step >= HARDENED_INDEX {
            return Err(AppError::new("Unhardened derivation step too high"));
        }
    
        hmac_data.clear();
        hmac_data.extend_from_slice(&EcfpPublicKey::from_slice(&cur_pubkey)?.to_compressed());
        hmac_data.extend_from_slice(&step.to_be_bytes());
    
        let hmac_result: [u8; 64] = vanadium_sdk::crypto::hmac_sha512(&cur_chaincode[..], &hmac_data);
    
        let sk: [u8; 32] = hmac_result[0..32].try_into().expect("Cannot fail");
        cur_chaincode = hmac_result[32..].try_into().expect("Cannot fail");

        result.push(sk);

        if index < steps.len() - 1 {
            // it's unnecessary to call secp256k1_ec_pubkey_tweak_add in the last iteration
            if vanadium_sdk::secp256k1::secp256k1_ec_pubkey_tweak_add(
                ptr::null(),
                &mut cur_pubkey,
                sk.as_ptr(),
            ) != 1 {
                return Err(AppError::new("Failed to derive from musig2 aggregate key"));
            }
        }
    }

    Ok(result)
}


// temporary struct while the Psbt class doesn't have fields for the partial signatures 
// TODO: remove once implemented in Psbt
#[derive(Debug)]
pub struct MusigPartialSig {
    pub input_index: usize,
    pub participant_public_key: EcfpPublicKey,
    pub xonly_key: [u8; 32],
    pub leaf_hash: Option<[u8; 32]>,
    pub partial_sig: Scalar<Public, Zero>, 
}

pub trait PsbtMuSig2Cosigner {
    fn get_participant_pubkey(&self) -> Point;
    fn generate_public_nonces(&mut self, psbt: &mut Psbt) -> Result<()>;
    fn generate_partial_signatures(&mut self, psbt: &Psbt) -> Result<Vec<MusigPartialSig>>;
}
