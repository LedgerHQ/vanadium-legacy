use core::str::FromStr;
use core::{convert::TryInto, ptr};
use std::collections::HashMap;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::SighashCache;
use bitcoin::{Psbt, TapLeafHash, XOnlyPublicKey};
use hex_literal::hex;
use rand_chacha::ChaCha20Rng;
use schnorr_fun::fun::marker::{NonZero, Public, Zero};
use schnorr_fun::fun::{KeyPair, Point, Scalar};
use schnorr_fun::musig::{new_with_deterministic_nonces, Nonce};
use schnorr_fun::Message;
use schnorr_fun::{musig::AggKey, fun::marker::Normal};
use vanadium_sdk::crypto::{CxCurve, EcfpPrivateKey, EcfpPublicKey};

use crate::error::*;

use crate::state::MusigSession;
use crate::taproot::{compute_taproot_sighash, tagged_hash, GetTapLeafHash, GetTapTreeHash, BIP0341_TAPTWEAK_TAG};
use crate::wallet::HARDENED_INDEX;

use super::{DescriptorTemplate, ExtendedPubKey, KeyPlaceholder, MySha256, SegwitVersion, WalletPolicy};

// by convention, chaincode for the aggregate key obtained by musig() expressions in descriptors.
pub const MUSIG_AGGR_CHAINCODE: [u8; 32] = hex!("868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965");


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
    input_index: usize,
    participant_public_key: EcfpPublicKey,
    xonly_key: [u8; 32],
    leaf_hash: Option<[u8; 32]>,
    partial_sig: Scalar<Public, Zero>, 
}

#[derive(Debug)]
pub struct HotMuSig2Cosigner<'a> {
    wallet_policy: &'a WalletPolicy,
    cosigner_xpriv: bitcoin::bip32::Xpriv,
    cosigner_keypair: schnorr_fun::fun::KeyPair,
    aggregate_key: AggKey<Normal>,
    musig_sessions: HashMap<Vec<u8>, MusigSession>,
}

fn find_change_and_addr_index(input: &bitcoin::psbt::Input, placeholder: &KeyPlaceholder) -> Option<(bool, u32)> {
    let (&num1, &num2) = match placeholder {
        KeyPlaceholder::Musig { num1, num2, .. } => (num1, num2),
        _ => return None,
    };

    for (_, (_, (fpr, der_path))) in input.tap_key_origins.iter() {
        if *fpr.as_bytes() == [0u8; 4]
            && der_path.len() == 2
            && der_path[0].is_normal() && der_path[1].is_normal()
            && (der_path[0] == num1.into() || der_path[0] == num2.into()
        ) {
            // TODO: we should actually check if the derivation matches!
            return Some((der_path[0] == num2.into(), der_path[1].into()))
        }
    }
    return None
}

impl<'a> HotMuSig2Cosigner<'a> {
    pub fn new(wallet_policy: &'a WalletPolicy, cosigner_xpriv: bitcoin::bip32::Xpriv) -> Result<Self> {
        let secp = Secp256k1::new();

        // Derive the cosigner's keypair from `cosigner_xpriv`
        let cosigner_xpub = bitcoin::bip32::Xpub::from_priv(&secp, &cosigner_xpriv);
        let cosigner_privkey_scalar = Scalar::from_bytes(cosigner_xpriv.private_key.secret_bytes()).ok_or("Failed to deserialize privkey")?.non_zero().unwrap();
        let cosigner_keypair: schnorr_fun::fun::KeyPair = schnorr_fun::fun::KeyPair::<Normal>::new(cosigner_privkey_scalar);


        for (placeholder, _) in wallet_policy.descriptor_template.placeholders() {
            if let KeyPlaceholder::Musig { key_indices, num1: _, num2: _ } = placeholder {
                // TODO: care needs to be taken with deterministic nonces
                let musig: schnorr_fun::musig::MuSig<MySha256, schnorr_fun::nonce::Deterministic<MySha256>> = new_with_deterministic_nonces::<MySha256>();

                // TODO: this code is adapted from script.rs; refactor
                let root_pubkeys = key_indices.iter()
                    .map(|k| {
                        let key_info = wallet_policy.key_information
                            .get(*k as usize)
                            .ok_or("Invalid key index")?;

                        let root_pubkey = ExtendedPubKey::from_str(&key_info.pubkey).map_err(|_| "Invalid pubkey")?;
                        Point::from_bytes_uncompressed(*root_pubkey.public_key.as_bytes())
                            .ok_or(AppError::new("Failed to derive key"))
                    })
                    .collect::<Result<Vec<Point>>>()?;

                let aggregate_key = musig.new_agg_key(root_pubkeys.clone());

                if key_indices.iter().find(|&i| wallet_policy.key_information[*i as usize].pubkey == cosigner_xpub.to_string()).is_none() {
                    return Err(AppError::new("No internal key found in musig"));
                }

                return Ok(HotMuSig2Cosigner {
                    wallet_policy,
                    cosigner_xpriv,
                    cosigner_keypair,
                    aggregate_key,
                    musig_sessions: HashMap::new()
                });
            }
        }

        return Err(AppError::new("No matching MuSig placeholder found"));
    }

    pub fn generate_public_nonces(&mut self, psbt: &mut Psbt) -> Result<()> {
        let my_privkey = EcfpPrivateKey::new(CxCurve::Secp256k1, &self.cosigner_xpriv.private_key.secret_bytes());
        let my_pubkey = my_privkey.pubkey()?;

        for (placeholder, tapleaf_desc) in self.wallet_policy.descriptor_template.placeholders() {
            if let KeyPlaceholder::Musig { key_indices, num1, num2 } = placeholder {
                // TODO: care needs to be taken with deterministic nonces
                let musig: schnorr_fun::musig::MuSig<MySha256, schnorr_fun::nonce::Deterministic<MySha256>> = new_with_deterministic_nonces::<MySha256>();

                for input in psbt.inputs.iter_mut() {
                    if let Some((is_change, addr_index)) = find_change_and_addr_index(&input, placeholder) {
                        // None if the placeholder is not in a Leaf, otherwise the taproot leaf hash
                        let leaf_hash = match self.wallet_policy.get_segwit_version() {
                            Ok(SegwitVersion::Taproot) => {
                                tapleaf_desc
                                    .map(|desc| desc.get_tapleaf_hash(&self.wallet_policy.key_information, is_change, addr_index))
                                    .transpose()?
                            },
                            _ => return Err(AppError::new("Unexpected state: MuSig can only be used in Taproot wallet policies")),
                        };

                        let change_step = if !is_change { *num1 } else { *num2 };

                        let mut agg_key = self.aggregate_key.clone();
                        let bip32_tweaks = get_musig_bip32_tweaks(&agg_key, vec![change_step, addr_index])?;

                        for tweak in bip32_tweaks {
                            let scalar: Scalar<Public, Zero> = Scalar::from_bytes(tweak).ok_or(AppError::new("Failed to create tweak"))?;
                            agg_key = agg_key.tweak(scalar).ok_or(AppError::new("Failed to apply tweak"))?;
                        }

                        let (is_keypath, taptree_hash) = match &self.wallet_policy.descriptor_template {
                            DescriptorTemplate::Tr(kp, tree) => {
                                (
                                    kp == placeholder,
                                    tree.as_ref().map(|t| t.get_taptree_hash(&self.wallet_policy.key_information, is_change, addr_index)).transpose()?
                                )
                            }
                            _ => return Err(AppError::new("Unexpected state: should be a Taproot wallet policy")),
                        };

                        let mut agg_key_xonly = agg_key
                            .clone()  // TODO: get rid of this clone()
                            .into_xonly_key();

                        // apply the taptweak if the musig we're signing for is in the keypath
                        if is_keypath {
                            let t = tagged_hash(
                                BIP0341_TAPTWEAK_TAG,
                                &agg_key_xonly.agg_public_key().to_xonly_bytes(), 
                                taptree_hash.as_ref().map(|array| array.as_ref()));
                            let taptweak_scalar: Scalar<Public, NonZero> = Scalar::from_bytes(t)
                                .ok_or(AppError::new("Unexpected error"))?
                                .non_zero()
                                .ok_or(AppError::new("Unexpected zero scalar"))?;
                            agg_key_xonly = agg_key_xonly.tweak(taptweak_scalar).unwrap();    
                        }

                        let psbt_identifier = (
                            bitcoin::secp256k1::PublicKey::from_slice(&my_pubkey.to_compressed())?,
                            XOnlyPublicKey::from_slice(&agg_key_xonly.agg_public_key().to_xonly_bytes())?,
                            leaf_hash.map(|lh: [u8; 32]| TapLeafHash::from_byte_array(lh))
                        );

                        // TODO: the session ID _must_ be different for every signing session! We're just having fun here, so good for now
                        let session_id: &[u8] = b"signing-ominous-message-about-banks-attempt-1".as_slice();

                        let my_privkey_scalar = Scalar::from_bytes(*my_privkey.as_bytes())
                            .ok_or(AppError::new("Failed to create scalar from privkey"))?
                            .non_zero().ok_or(AppError::new("Conversion to NonZero scalar failed"))?;


                        // TODO: we'll want a rng based on vanadium-sdk, or a different method for nonce generation
                        let mut nonce_rng: ChaCha20Rng = musig.seed_nonce_rng(&agg_key, &my_privkey_scalar, session_id);
                        let my_nonce = musig.gen_nonce(&mut nonce_rng);
                        let my_public_nonce = my_nonce.public().to_bytes();

                        self.musig_sessions.insert(session_id.to_vec(), MusigSession {
                            nonce_keypair: my_nonce,
                        });

                        input.musig2_pub_nonces.insert(psbt_identifier, my_public_nonce.to_vec());
                    }
                }
            } 
        }

        Ok(())
    }


    pub fn generate_partial_signatures(&mut self, psbt: &Psbt) -> Result<Vec<MusigPartialSig>> {
        let secp = Secp256k1::new();
        let cosigner_xpub = bitcoin::bip32::Xpub::from_priv(&secp, &self.cosigner_xpriv);

        let my_privkey = EcfpPrivateKey::new(CxCurve::Secp256k1, &self.cosigner_xpriv.private_key.secret_bytes());
        let my_privkey_scalar = Scalar::from_bytes(my_privkey.as_bytes().clone()).ok_or("Failed to deserialize privkey")?.non_zero().unwrap();
        let my_keypair: schnorr_fun::fun::KeyPair = KeyPair::<Normal>::new(my_privkey_scalar);

        let mut result: Vec<MusigPartialSig> = vec![];

        for (placeholder, tapleaf_desc) in self.wallet_policy.descriptor_template.placeholders() {
            if let KeyPlaceholder::Musig { key_indices, num1, num2 } = placeholder {
                // TODO: care needs to be taken with deterministic nonces
                let musig: schnorr_fun::musig::MuSig<MySha256, schnorr_fun::nonce::Deterministic<MySha256>> = new_with_deterministic_nonces::<MySha256>();

                for (input_index, input) in psbt.inputs.iter().enumerate() {
                    if let Some((is_change, addr_index)) = find_change_and_addr_index(&input, placeholder) {
                        // DUPLICATED PART START

                        // None if the placeholder is not in a Leaf, otherwise the taproot leaf hash
                        let leaf_hash = match self.wallet_policy.get_segwit_version() {
                            Ok(SegwitVersion::Taproot) => {
                                tapleaf_desc
                                    .map(|desc| desc.get_tapleaf_hash(&self.wallet_policy.key_information, is_change, addr_index))
                                    .transpose()?
                            },
                            _ => return Err(AppError::new("Unexpected state: MuSig can only be used in Taproot wallet policies")),
                        };

                        let change_step = if !is_change { *num1 } else { *num2 };

                        let mut agg_key = self.aggregate_key.clone();
                        let bip32_tweaks = get_musig_bip32_tweaks(&agg_key, vec![change_step, addr_index])?;

                        for tweak in bip32_tweaks {
                            let scalar: Scalar<Public, Zero> = Scalar::from_bytes(tweak).ok_or(AppError::new("Failed to create tweak"))?;
                            agg_key = agg_key.tweak(scalar).ok_or(AppError::new("Failed to apply tweak"))?;
                        }

                        let (is_keypath, taptree_hash) = match &self.wallet_policy.descriptor_template {
                            DescriptorTemplate::Tr(kp, tree) => {
                                (
                                    kp == placeholder,
                                    tree.as_ref().map(|t| t.get_taptree_hash(&self.wallet_policy.key_information, is_change, addr_index)).transpose()?
                                )
                            }
                            _ => return Err(AppError::new("Unexpected state: should be a Taproot wallet policy")),
                        };

                        let mut agg_key_xonly = agg_key
                            .clone()  // TODO: get rid of this clone()
                            .into_xonly_key();

                        // apply the taptweak if the musig we're signing for is in the keypath
                        if is_keypath {
                            let t = tagged_hash(
                                BIP0341_TAPTWEAK_TAG,
                                &agg_key_xonly.agg_public_key().to_xonly_bytes(), 
                                taptree_hash.as_ref().map(|array| array.as_ref()));
                            let taptweak_scalar: Scalar<Public, NonZero> = Scalar::from_bytes(t)
                                .ok_or(AppError::new("Unexpected error"))?
                                .non_zero()
                                .ok_or(AppError::new("Unexpected zero scalar"))?;
                            agg_key_xonly = agg_key_xonly.tweak(taptweak_scalar).unwrap();    
                        }
                        // DUPLICATED PART END

                        let (my_key_index_in_musig, _) = key_indices
                            .iter()
                            .enumerate() // Add enumerate to keep track of the index
                            .find(|(_, &i)| self.wallet_policy.key_information[i as usize].pubkey == cosigner_xpub.to_string())
                            .ok_or("No internal key found in musig")?;
    
                        // TODO: the session ID _must_ be different for every signing session! We're just having fun here, so good for now
                        let session_id: &[u8] = b"signing-ominous-message-about-banks-attempt-1".as_slice();

                        let musig_session = self.musig_sessions.remove(&session_id.to_vec())
                            .ok_or(AppError::new("Private nonce not found for this session id"))?;

                        let mut nonces: Vec<Nonce> = vec![];

                        for participant_key in agg_key.keys() {
                            if let Some(nonce_bytes) = input.musig2_pub_nonces.get(&(
                                bitcoin::secp256k1::PublicKey::from_slice(&participant_key.to_bytes())?,
                                XOnlyPublicKey::from_slice(&agg_key_xonly.agg_public_key().to_xonly_bytes())?,
                                leaf_hash.map(|lh: [u8; 32]| TapLeafHash::from_byte_array(lh))
                            )) {
                                let nonce = Nonce::from_bytes(
                                    nonce_bytes.iter().copied().collect::<Vec<u8>>().try_into()
                                        .map_err(|_| AppError::new("Failed to deserialize nonce"))?
                                ).ok_or(AppError::new("Failed to deserialize nonce"))?;
                                nonces.push(nonce);
                            } else {
                                return Err(AppError::new("Missing public nonce"));
                            }
                        }


                        let sighash_type = bitcoin::TapSighashType::Default; // TODO: only DEFAULT is supported for now
                        let mut sighash_cache = SighashCache::new(psbt.unsigned_tx.clone());
                        let sighash = compute_taproot_sighash(&psbt, input_index, &mut sighash_cache, leaf_hash, sighash_type)?;

                        let message = Message::<Public>::raw(sighash.as_byte_array());

                        let session = musig.start_sign_session(&agg_key_xonly, nonces, message);

                        let partial_sig = musig.sign(&agg_key_xonly, &session, my_key_index_in_musig as usize, &my_keypair, musig_session.nonce_keypair);

                        result.push(MusigPartialSig {
                            input_index,
                            participant_public_key: my_privkey.pubkey()?,
                            xonly_key: agg_key_xonly.agg_public_key().to_xonly_bytes().into(),
                            leaf_hash,
                            partial_sig,
                        });
                    }
                }
            }
        }
        
        Ok(result)
    }
}


#[cfg(test)]
mod tests {
    use crate::wallet::MySha256;

    use super::*;
    use bitcoin::{hashes::Hash, TapSighashType};
    use error::Result;
    use base64::{engine::general_purpose, Engine as _};
    use schnorr_fun::fun::{marker::{NonZero, Public}, Point};

    fn run_test(psbt_base64: &str, wallet_policy: &WalletPolicy, participant_xprivs: Vec<bitcoin::bip32::Xpriv>) -> Result<()> {
        let psbt_bin = general_purpose::STANDARD.decode(psbt_base64).unwrap();
        let mut psbt = Psbt::deserialize(&psbt_bin)?;

        // TODO: For now, we assume there is only one input in this test
        assert_eq!(psbt.inputs.len(), 1);

        let secp = Secp256k1::new();

        let musig_placeholders: Vec<(&KeyPlaceholder, Option<&DescriptorTemplate>)> = wallet_policy
            .descriptor_template
            .placeholders().filter(|(p, _)| p.is_musig())
            .collect();

        assert!(musig_placeholders.len() == 1);

        let placeholder = musig_placeholders.first().unwrap().0;

        let tapleaf_desc = musig_placeholders.first().unwrap().1;

        let mut musig_cosigners: Vec<HotMuSig2Cosigner> = vec![];
        for xpriv in &participant_xprivs {
            let cosigner =  HotMuSig2Cosigner::new(&wallet_policy, *xpriv)?;
            musig_cosigners.push(cosigner);
        }

        // Get signers to add nonces to Psbt
        for musig_cosigner in &mut musig_cosigners {
            musig_cosigner.generate_public_nonces(&mut psbt)?
        }

        // Get partial signatures
        let mut partial_sigs: Vec<Scalar<Public, Zero>> = vec![];
        for musig_cosigner in &mut musig_cosigners {
            let result = musig_cosigner.generate_partial_signatures(&psbt)?;
            assert!(result.len() == 1);
            partial_sigs.push(result[0].partial_sig);    
        }

        let musig = schnorr_fun::musig::new_with_deterministic_nonces::<MySha256>();

        let participant_keys: Vec<Point> = participant_xprivs
            .iter()
            .map(|xpriv| bitcoin::bip32::Xpub::from_priv(&secp, &xpriv))
            .map(|xpub| Point::from_bytes(xpub.public_key.serialize()).unwrap())
            .collect();

        let mut agg_key = musig.new_agg_key(participant_keys);


        let (is_change, addr_index) = find_change_and_addr_index(&psbt.inputs[0], placeholder)
           .ok_or(AppError::new("Error"))?;

        let change_step = match placeholder {
            KeyPlaceholder::Musig { num1, num2, .. } => if !is_change { *num1 } else { *num2 },
            _ => Err(AppError::new("This can never happen"))?,
        };
        
        let bip32_tweaks: Vec<[u8; 32]> = get_musig_bip32_tweaks(&agg_key, vec![change_step, addr_index])?;

        for tweak in bip32_tweaks {
            let scalar: Scalar =
                Scalar::from_bytes(tweak).ok_or(AppError::new("Failed to create tweak"))?
                .non_zero().ok_or(AppError::new("Failed to create tweak"))?;

            agg_key = agg_key.tweak(scalar).ok_or(AppError::new("Failed to apply tweak"))?;
        }

        let (is_keypath, _) = match &wallet_policy.descriptor_template {
            DescriptorTemplate::Tr(kp, tree) => {
                (
                    kp == placeholder,
                    tree.as_ref().map(|t| t.get_taptree_hash(&wallet_policy.key_information, is_change, addr_index)).transpose()?
                )
            }
            _ => return Err(AppError::new("Unexpected state: should be a Taproot wallet policy")),
        };

        let mut agg_key_xonly = agg_key
            .clone()  // TODO: get rid of this clone()
            .into_xonly_key();

        // apply the taptweak if the musig we're signing for is in the keypath
        if is_keypath {
            let t = crate::taproot::tagged_hash(
                crate::taproot::BIP0341_TAPTWEAK_TAG, 
                &agg_key_xonly.agg_public_key().to_xonly_bytes(), 
                None);
            let taptweak_scalar: Scalar<Public, NonZero> = Scalar::from_bytes(t)
                .ok_or(AppError::new("Unexpected error"))?
                .non_zero()
                .ok_or(AppError::new("Unexpected zero scalar"))?;
            agg_key_xonly = agg_key_xonly.tweak(taptweak_scalar).unwrap();
        }

        let leaf_hash_bytes = tapleaf_desc
            .map(|desc| desc.get_tapleaf_hash(&wallet_policy.key_information, false, 3).unwrap());

        let leaf_hash = leaf_hash_bytes.map(|h| TapLeafHash::from_byte_array(h));


        // Collect nonces, making sure they are in the right order
        let mut nonces: Vec<Nonce> = vec![];
        for participant_key in agg_key.keys() {
            if let Some(nonce_bytes) = psbt.inputs[0].musig2_pub_nonces.get(&(
                bitcoin::secp256k1::PublicKey::from_slice(&participant_key.to_bytes())?,
                XOnlyPublicKey::from_slice(&agg_key_xonly.agg_public_key().to_xonly_bytes())?,
                leaf_hash
            )) {
                let nonce = Nonce::from_bytes(
                    nonce_bytes.iter().copied().collect::<Vec<u8>>().try_into()
                        .map_err(|_| AppError::new("Failed to deserialize nonce"))?
                ).ok_or(AppError::new("Failed to deserialize nonce"))?;
                nonces.push(nonce);
            } else {
                return Err(AppError::new("Missing public nonce"));
            }
        }

        let mut sighash_cache = SighashCache::new(psbt.unsigned_tx.clone());
        let sighash_type = TapSighashType::Default; // TODO: only DEFAULT is supported for now
        let sighash = compute_taproot_sighash(&psbt, 0, &mut sighash_cache, leaf_hash_bytes, sighash_type)?;
        let message = schnorr_fun::Message::<Public>::raw(sighash.as_byte_array());

        let session = musig.start_sign_session(&agg_key_xonly, nonces, message);
        let sig = musig.combine_partial_signatures(&agg_key_xonly, &session, partial_sigs);

        let result = musig
            .schnorr
            .verify(&agg_key_xonly.agg_public_key(), message, &sig);

        assert!(result);

        Ok(())
    }


    #[test]
    fn test_musig2_cosigner_keypath() -> Result<()> {
        let secp: Secp256k1<bitcoin::secp256k1::All> = Secp256k1::new();

        let psbt_b64 = "cHNidP8BAIACAAAAAWbcwfJ78yV/+Jn0waX9pBWhDp2pZCm0GuTEXe2wXcP2AQAAAAD9////AQAAAAAAAAAARGpCVGhpcyBpbnB1dHMgaGFzIHR3byBwdWJrZXlzIGJ1dCB5b3Ugb25seSBzZWUgb25lLiAjbXBjZ2FuZyByZXZlbmdlAAAAAAABASuf/gQAAAAAACJRIPSL0RqGcuiQxWUrpyqc9CJwAk7i1Wk1p+YZWmGpB5tmIRbGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7Bxg0AAAAAAAAAAAADAAAAAAA=";

        let cosigner_1_xpriv = bitcoin::bip32::Xpriv::from_str("tprv8gFWbQBTLFhbVcpeAJ1nGbPetqLo2a5Duqu3E5wXUFJ4auLcBAfwhJscGbPjzKNvpCdG3KK3BLCTLi8YKy4PXnA1hxdowdpTaMqTcF5ZpUz")?;
        let cosigner_1_xpub = bitcoin::bip32::Xpub::from_priv(&secp, &cosigner_1_xpriv);
        let cosigner_2_xpriv = bitcoin::bip32::Xpriv::from_str("tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf")?;
        let cosigner_2_xpub = bitcoin::bip32::Xpub::from_priv(&secp, &cosigner_2_xpriv);

        let wallet_policy = WalletPolicy::new(
            "Musig for my ears".into(),
            "tr(musig(@0,@1)/**)".into(),
            vec![
                &cosigner_1_xpub.to_string(),
                &cosigner_2_xpub.to_string()
            ]
        )?;

        run_test(psbt_b64, &wallet_policy, vec![cosigner_1_xpriv, cosigner_2_xpriv])
    }

    #[test]
    fn test_musig2_cosigner_scriptpath() -> Result<()> {
        let secp: Secp256k1<bitcoin::secp256k1::All> = Secp256k1::new();

        let psbt_b64 = "cHNidP8BAFoCAAAAAeyfHxrwzXffQqF9egw6KMS7RwCLP4rW95dxtXUKYJGFAQAAAAD9////AQAAAAAAAAAAHmocTXVzaWcyLiBOb3cgZXZlbiBpbiBTY3JpcHRzLgAAAAAAAQErOTAAAAAAAAAiUSDZqQIMWvfc0h2w2z6+0vTt0z1YoUHA6JHynopzSe3hgiIVwethFsEeXf/x51pIczoAIsj9RoVePIBTyk/rOMW8B6uIIyDGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7BxqzAIRbGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7Bxi0BkW61VIaT9Qaz/k0SzoZ1UBsjkrXzPqXQbCbBjbNZP/kAAAAAAAAAAAMAAAABFyDrYRbBHl3/8edaSHM6ACLI/UaFXjyAU8pP6zjFvAeriAEYIJFutVSGk/UGs/5NEs6GdVAbI5K18z6l0GwmwY2zWT/5AAA=";
        
        let cosigner_1_xpriv = bitcoin::bip32::Xpriv::from_str("tprv8gFWbQBTLFhbVcpeAJ1nGbPetqLo2a5Duqu3E5wXUFJ4auLcBAfwhJscGbPjzKNvpCdG3KK3BLCTLi8YKy4PXnA1hxdowdpTaMqTcF5ZpUz")?;
        let cosigner_1_xpub = bitcoin::bip32::Xpub::from_priv(&secp, &cosigner_1_xpriv);
        let cosigner_2_xpriv = bitcoin::bip32::Xpriv::from_str("tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf")?;
        let cosigner_2_xpub = bitcoin::bip32::Xpub::from_priv(&secp, &cosigner_2_xpriv);

        assert!(cosigner_1_xpub.to_string() == "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT");
        assert!(cosigner_2_xpub.to_string() == "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm");

        let wallet_policy = WalletPolicy::new(
            "Musig2 in the scriptpath".into(),
            "tr(@0/**,pk(musig(@1,@2)/**))".into(),
            vec![
                "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN".into(),
                &cosigner_1_xpub.to_string(),
                &cosigner_2_xpub.to_string()
            ]
        )?;

        run_test(psbt_b64, &wallet_policy, vec![cosigner_1_xpriv, cosigner_2_xpriv])
    }
}
