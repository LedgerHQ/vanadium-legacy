use core::{str::FromStr, convert::TryInto};

use alloc::{borrow::Cow, format, vec, vec::Vec};
use subtle::ConstantTimeEq;
use vanadium_sdk::crypto::{CxCurve, CxMd, EcfpPrivateKey, CX_RND_RFC6979};

use rand_chacha::ChaCha20Rng;

use schnorr_fun::{musig::{new_with_deterministic_nonces, Nonce}, fun::{Point, Scalar, marker::{Public, NonZero, Normal, Zero}, KeyPair}, Message};

use crate::{
    message::message::{PartialSignature, RequestSignPsbt, ResponseSignPsbt, MusigPublicNonce, MusigPartialSignature},
    wallet::{WalletPolicy, SegwitVersion, KeyOrigin, KeyPlaceholder, DescriptorTemplate, MySha256, ExtendedPubKey, musig::get_musig_bip32_tweaks},
    taproot::{TapTweak, GetTapTreeHash, GetTapLeafHash, tagged_hash, BIP0341_TAPTWEAK_TAG}, state::{AppState, MusigSession},
};

#[cfg(not(test))]
use vanadium_sdk::{
    glyphs::{ICON_CROSSMARK, ICON_EYE, ICON_VALIDATE},
    ux::{app_loading_stop, ux_validate, UxAction, UxItem},
};

use bitcoin::{psbt::Psbt, sighash::SighashCache, ScriptBuf, bip32::{Fingerprint, DerivationPath}, Transaction, TapSighashType, TxOut, TapLeafHash, hashes::Hash, PublicKey, XOnlyPublicKey, TapSighash};

#[cfg(not(test))]
use alloc::string::String;

use error::*;

// TODO: this is a dummy hmac until we implement SLIP-21
const DUMMY_HMAC: [u8; 32] = [0x42; 32];

pub fn ui_authorize_wallet_policy_spend(wallet_policy: &WalletPolicy) -> bool {
    #[cfg(test)]
    {
        true
    }
    #[cfg(not(test))]
    {
        let mut ux: Vec<UxItem> = vec![UxItem {
            icon: Some(&ICON_EYE),
            line1: "Spend from",
            line2: Some(&wallet_policy.name),
            action: UxAction::None,
        }];

        ux.extend([
            UxItem {
                icon: Some(&ICON_VALIDATE),
                line1: "Continue",
                line2: None,
                action: UxAction::Validate,
            },
            UxItem {
                icon: Some(&ICON_CROSSMARK),
                line1: "Reject",
                line2: None,
                action: UxAction::Reject,
            },
        ]);

        // TODO: ux framework doesn't have pagination, so this will truncate long strings

        // TODO: the screen flickers in a weird way without this; why does that happen?
        app_loading_stop();

        ux_validate(&ux)
    }
}


fn sign_input_ecdsa<'a>(psbt: &Psbt, input_index: usize, sighash_cache: &mut SighashCache<Transaction>, path: &[u32]) -> Result<PartialSignature<'a>> {
    let (sighash, sighash_type) = psbt
        .sighash_ecdsa(input_index, sighash_cache)
        .map_err(|_| AppError::new("Error computing sighash"))?;

    let privkey = EcfpPrivateKey::from_path(CxCurve::Secp256k1, path)?;
    let pubkey = privkey.pubkey()?;

    let (mut signature, _) = privkey.ecdsa_sign(CX_RND_RFC6979, CxMd::Sha256, sighash.as_ref())?;
    signature.push(sighash_type.to_u32() as u8);

    Ok(PartialSignature {
        input_index: input_index as u32,
        signature: Cow::Owned(signature),
        public_key: Cow::Owned(pubkey.to_compressed().to_vec()),
        leaf_hash: Cow::Owned(vec![]),
    })
}

fn compute_taproot_sighash(
    psbt: &Psbt,
    input_index: usize,
    sighash_cache: &mut SighashCache<Transaction>,
    leaf_hash: Option<[u8; 32]>,
    sighash_type: TapSighashType
) -> Result<TapSighash> {
    let prevouts = psbt.inputs.iter()
        .map(|input| input.witness_utxo.clone().ok_or(AppError::new("Missing witness utxo")))
        .collect::<Result<Vec<TxOut>>>()?;

    if let Some(leaf_hash_bytes) = leaf_hash {
        sighash_cache.taproot_script_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            TapLeafHash::from_byte_array(leaf_hash_bytes),
            sighash_type
        ).map_err(|_| AppError::new("Error computing sighash"))
    } else {
        sighash_cache.taproot_key_spend_signature_hash(
            input_index,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            sighash_type
        ).map_err(|_| AppError::new("Error computing sighash"))
    }
}

fn sign_input_schnorr<'a>(psbt: &Psbt, input_index: usize, sighash_cache: &mut SighashCache<Transaction>, path: &[u32], taptree_hash: Option<[u8; 32]>, leaf_hash: Option<[u8; 32]>) -> Result<PartialSignature<'a>> {
    let sighash_type = TapSighashType::Default; // TODO: only DEFAULT is supported for now

    let sighash = compute_taproot_sighash(psbt, input_index, sighash_cache, leaf_hash, sighash_type)?;

    let mut privkey = EcfpPrivateKey::from_path(CxCurve::Secp256k1, path)?;

    if leaf_hash.is_none() {
        if let Some(t) = taptree_hash {
            privkey.taptweak(&t)?;
        } else {
            // BIP-86-compliant tweak
            privkey.taptweak(&[])?;
        }
    }

    let pubkey = privkey.pubkey()?;

    let mut signature = privkey.schnorr_sign(sighash.as_ref())?;
    
    if sighash_type != TapSighashType::Default {
        signature.push(sighash_type as u8)
    }

    Ok(PartialSignature {
        input_index: input_index as u32,
        signature: Cow::Owned(signature),
        public_key: Cow::Owned(pubkey.to_compressed()[1..].to_vec()), // x-only pubkey
        leaf_hash: Cow::Owned(match leaf_hash {
            Some(hash) => hash.to_vec(),
            None => Vec::new(),
        }),
    })
}


// TODO: this is wrong, will need to be fixed when the input/output validation is implemented
fn find_change_and_addr_index(input: &bitcoin::psbt::Input, wallet_policy: &WalletPolicy, placeholder: &KeyPlaceholder, key_origin: &KeyOrigin, master_fpr: u32) -> Option<(bool, u32)> {
    let (match_fpr, placeholder_num1, placeholder_num2) = match placeholder {
        KeyPlaceholder::PlainKey { key_index: _, num1, num2 } => (master_fpr, *num1, *num2),
        KeyPlaceholder::Musig { key_indices: _, num1, num2 } => (0u32, *num1, *num2), // assuming the aggregate key has fingerprint 0
    };

    let keys_and_origins: Vec<&(Fingerprint, DerivationPath)> = if wallet_policy.get_segwit_version() == Ok(SegwitVersion::Taproot) {
        input.tap_key_origins.iter().map(|(_, (_, x))| x).collect()
    } else {
        input.bip32_derivation.iter().map(|(_, x)| x).collect()
    };

    for (fpr, der) in keys_and_origins {
        let fpr = u32::from_be_bytes(*fpr.as_bytes());
        let der: Vec<u32> = der.into_iter().map(|x| u32::from(*x)).collect();

        if fpr == match_fpr && der.len() >= 2 {
            let change_step = der[der.len() - 2];
            let addr_index = der[der.len() - 1];

            if change_step == placeholder_num1 {
                return Some((false, addr_index));
            } else if change_step == placeholder_num2 {
                return Some((true, addr_index));
            }
        }
    }

    None
}

pub fn handle_sign_psbt<'a>(req: RequestSignPsbt, state: &'a mut AppState) -> Result<ResponseSignPsbt<'a>> {
    let wallet_policy = WalletPolicy::new(
        req.name.into(),
        &req.descriptor_template.clone().into_owned(),
        req.keys_info
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<&str>>(),
    )
    .map_err(|err| AppError::new(&format!("Invalid wallet policy: {}", err)))?;

    // compare the hmac to 0 in constant time
    let hmac_or = req.wallet_hmac.iter().fold(0u8, |acc, x| acc | x);
    let is_wallet_default = hmac_or == 0;

    if is_wallet_default {
        // check that the wallet is indeed canonical
        if !wallet_policy.is_default() {
            return Err(AppError::new("Non-standard policy needs a valid HMAC"));
        }
        // TODO: should still check that we can derive the same pubkey using the key origin
    } else {
        // verify hmac
        // IMPORTANT: we use a constant time comparison
        if req.wallet_hmac.ct_eq(&DUMMY_HMAC).unwrap_u8() == 0 {
            return Err(AppError::new("Invalid hmac"));
        }
    }


    // steps:

    // TODO: inputs/outputs verification

    // TODO: confirm transaction amounts

    // for each placeholder, for each input, sign if internal
    let mut partial_signatures: Vec<PartialSignature> = vec![];
    let mut musig_public_nonces: Vec<MusigPublicNonce> = vec![];
    let mut musig_partial_signatures: Vec<MusigPartialSignature> = vec![];

    let psbt = Psbt::deserialize(&req.psbt)
        .map_err(|_| AppError::new("Error deserializing psbt"))?;

    let mut sighash_cache = SighashCache::new(psbt.unsigned_tx.clone());

    let master_fingerprint = vanadium_sdk::crypto::get_master_fingerprint()?;

    for (placeholder, tapleaf_desc) in wallet_policy.descriptor_template.placeholders() {
        match placeholder {
            KeyPlaceholder::PlainKey { key_index, num1, num2 } => {
                // TODO: check if key is internal; for now we just trust the fingerprint
                let key_info = wallet_policy.key_information[*key_index as usize].clone();
                if let Some(key_origin) = key_info.origin_info.as_ref().filter(|x| x.fingerprint == master_fingerprint) {
                    // for each input, verify if we can match the derivation with the current placeholder
                    for (input_index, input) in psbt.inputs.iter().enumerate() {
                        // TODO: find_change_and_addr_index isn't quite right
                        if let Some((is_change, addr_index)) = find_change_and_addr_index(input, &wallet_policy, &placeholder, &key_origin, master_fingerprint) {
                            let mut path = key_origin.derivation_path.clone();

                            path.push(if !is_change { *num1 } else { *num2 });
                            path.push(addr_index);

                            if let Some(witness_utxo) = &input.witness_utxo {
                                // sign all segwit types (including wrapped)
                                if let Some(redeem_script) = &input.redeem_script {
                                    // check that P2WSH(redeem_script) == witness_utxo.script_pubkey
                                    if witness_utxo.script_pubkey != ScriptBuf::new_p2sh(&redeem_script.script_hash()) {
                                        return Err(AppError::new("witnessUtxo's scriptPubKey does not match redeemScript"));
                                    }
                                }

                                match wallet_policy.get_segwit_version() {
                                    Ok(SegwitVersion::SegwitV0) => {
                                        // sign as segwit v0
                                        let partial_signature = sign_input_ecdsa(&psbt, input_index, &mut sighash_cache, &path)?;
                                        partial_signatures.push(partial_signature);
                                    },
                                    Ok(SegwitVersion::Taproot) => {
                                        let taptree_hash = match &wallet_policy.descriptor_template {
                                            DescriptorTemplate::Tr(_, tree) => {
                                                tree.as_ref().map(|t| t.get_taptree_hash(&wallet_policy.key_information, is_change, addr_index)).transpose()
                                            }
                                            _ => return Err(AppError::new("Unexpected state: should be a Taproot wallet policy")),
                                        }?;

                                        let leaf_hash = tapleaf_desc
                                        .map(|desc| desc.get_tapleaf_hash(&wallet_policy.key_information, is_change, addr_index))
                                        .transpose()?;

                                        let partial_signature = sign_input_schnorr(&psbt, input_index, &mut sighash_cache, &path, taptree_hash, leaf_hash)?;
                                        partial_signatures.push(partial_signature);
                                    },
                                    _ => return Err(AppError::new("Unexpected state: should be SegwitV0 or Taproot")),
                                }
                            } else {
                                // sign as legacy p2pkh or p2sh
                                let partial_signature = sign_input_ecdsa(&psbt, input_index, &mut sighash_cache, &path)?;
                                partial_signatures.push(partial_signature);
                            }
                        }
                    }
                }
            },
            KeyPlaceholder::Musig { key_indices, num1, num2 } => {
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


                let mut agg_key = musig.new_agg_key(root_pubkeys.clone());

                // index of our key (in the musig, not in the wallet policy)
                let (my_key_index_in_musig, my_key_index_in_policy) = key_indices
                    .iter()
                    .enumerate() // Add enumerate to keep track of the index
                    .find(|(_, &i)|
                        wallet_policy
                            .key_information[i as usize]
                            .origin_info.as_ref()
                            .is_some_and(|ko| ko.fingerprint == master_fingerprint)
                    )
                    .ok_or("No internal key found in musig")?;

                let my_key_info = wallet_policy.key_information
                    .get(*my_key_index_in_policy as usize)
                    .ok_or("Invalid key index")?;
                let my_key_origin = my_key_info.origin_info.as_ref().ok_or("This can never fail")?;

                let path = &my_key_info.origin_info.as_ref().unwrap().derivation_path;
                let my_privkey = EcfpPrivateKey::from_path(CxCurve::Secp256k1, path)?;
                let my_pubkey = my_privkey.pubkey()?;
                let my_privkey_scalar = Scalar::from_bytes(my_privkey.as_bytes().clone()).ok_or("Failed to deserialize privkey")?.non_zero().unwrap();
                let my_keypair: schnorr_fun::fun::KeyPair = KeyPair::<Normal>::new(my_privkey_scalar);

                for (input_index, input) in psbt.inputs.iter().enumerate() {
                    if let Some((is_change, addr_index)) = find_change_and_addr_index(input, &wallet_policy, &placeholder, my_key_origin, master_fingerprint) {
                        // None if the placeholder is not in a Leaf, otherwise the taproot leaf hash
                        let leaf_hash = match wallet_policy.get_segwit_version() {
                            Ok(SegwitVersion::Taproot) => {
                                tapleaf_desc
                                    .map(|desc| desc.get_tapleaf_hash(&wallet_policy.key_information, is_change, addr_index))
                                    .transpose()?
                            },
                            _ => return Err(AppError::new("Unexpected state: MuSig can only be used in Taproot wallet policies")),
                        };
        
                        // if there is no nonce that we provided for this input, we generate the nonce;
                        // otherwise, we want to provide the partial signature
                        // to check the psbt we need:
                        // - our own participant pubkey (the one used to compute the agg_key) as a 33-byte compressed pubkey
                        // - the final pubkey after tweaking with change/address_index (and possibly taptweaking with the merkle root)
                        //   as a 32-byte x-only pubkey
                        // - the leaf hash if present


                        // TWEAKS:
                        // for taproot, we would have
                        // - 2 tweaks for agg_key, matching the BIP-32 derivations
                        // - then, after converting to x-only, taptweak with the merkle root
                        //   (unless it's in taproot script - in that case there's no additional tweak)

                        let change_step = if !is_change { *num1 } else { *num2 };

                        let bip32_tweaks = get_musig_bip32_tweaks(&agg_key, vec![change_step, addr_index])?;

                        for tweak in bip32_tweaks {
                            let scalar: Scalar<Public, Zero> = Scalar::from_bytes(tweak).ok_or(AppError::new("Failed to create tweak"))?;
                            agg_key = agg_key.tweak(scalar).ok_or(AppError::new("Failed to apply tweak"))?;
                        }

                        let (is_keypath, taptree_hash) = match &wallet_policy.descriptor_template {
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

                        // TODO: this assumes that _no_ pubnonce is present, not just ours
                        match input.musig2_pub_nonces.get(&psbt_identifier) {
                            None => {
                                if let std::collections::hash_map::Entry::Occupied(o) = state.musig_sessions.entry(session_id.to_vec()) {
                                    o.remove();
                                    return Err(AppError::new("Unexpected musig session already existing"));
                                }

                                let my_privkey_scalar = Scalar::from_bytes(*my_privkey.as_bytes())
                                    .ok_or(AppError::new("Failed to create scalar from privkey"))?
                                    .non_zero().ok_or(AppError::new("Conversion to NonZero scalar failed"))?;
                    

                                // TODO: we'll want a rng based on vanadium-sdk, or a different method for nonce generation
                                let mut nonce_rng: ChaCha20Rng = musig.seed_nonce_rng(&agg_key, &my_privkey_scalar, session_id);
                                let my_nonce = musig.gen_nonce(&mut nonce_rng);
                                let my_public_nonce = my_nonce.public().to_bytes();

                                state.musig_sessions.insert(session_id.to_vec(), MusigSession {
                                    nonce_keypair: my_nonce,
                                });

                                musig_public_nonces.push(MusigPublicNonce {
                                    input_index: input_index as u32,
                                    pubnonce: Cow::Owned(my_public_nonce.into()),
                                    participant_public_key: Cow::Owned(my_privkey.pubkey()?.to_compressed().into()),
                                    xonly_key: Cow::Owned(agg_key_xonly.agg_public_key().to_xonly_bytes().into()),
                                    leaf_hash: match leaf_hash {
                                        Some(lh) => Cow::Owned(lh.into()),
                                        None => Cow::Owned(vec![]),
                                    }
                                });
                            },
                            Some(_) => {
                                let musig_session = state.musig_sessions.remove(&session_id.to_vec())
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


                                let sighash_type = TapSighashType::Default; // TODO: only DEFAULT is supported for now
                                let sighash = compute_taproot_sighash(&psbt, input_index, &mut sighash_cache, leaf_hash, sighash_type)?;

                                let message = Message::<Public>::raw(sighash.as_byte_array());

                                let session = musig.start_sign_session(&agg_key_xonly, nonces, message);


                                let partial_sig = musig.sign(&agg_key_xonly, &session, my_key_index_in_musig as usize, &my_keypair, musig_session.nonce_keypair);

                                musig_partial_signatures.push(MusigPartialSignature {
                                    input_index: input_index as u32,
                                    participant_public_key: Cow::Owned(my_privkey.pubkey()?.to_compressed().into()),
                                    xonly_key: Cow::Owned(agg_key_xonly.agg_public_key().to_xonly_bytes().into()),
                                    leaf_hash: Cow::Owned(vec![]),
                                    signature: Cow::Owned(partial_sig.to_bytes().to_vec()),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(ResponseSignPsbt { 
        partial_signatures,
        musig_public_nonces,
        musig_partial_signatures,
    })
}

#[cfg(test)]
mod tests {
    use core::convert::TryInto;

    use super::*;

    use bitcoin::{Psbt, secp256k1::Secp256k1, bip32::Xpub};
    use base64::{engine::general_purpose, Engine as _};
    use hex_literal::hex;
    use vanadium_sdk::crypto::EcfpPublicKey;

    #[test]
    fn test_sign_psbt_singlesig_pkh_1to1() {
        let mut state = AppState::new();

        let psbt_b64 = "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA";
        let psbt = general_purpose::STANDARD.decode(psbt_b64).unwrap();

        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt),
            name: "".into(),
            descriptor_template: "pkh(@0/**)".into(),
            keys_info: vec!["[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".into()],
            wallet_hmac: Cow::Owned([0u8; 32].into()),
        };

        let resp = handle_sign_psbt(req, &mut state).unwrap();

        assert_eq!(1, resp.partial_signatures.len());
        assert_eq!(
            resp.partial_signatures[0].public_key.as_ref(),
            hex!("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718")
        );
        assert_eq!(
            resp.partial_signatures[0].signature.as_ref(),
            hex!("3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401")
        );
    }

    #[test]
    fn test_sign_psbt_singlesig_sh_wpkh_1to2() {
        let mut state = AppState::new();

        let psbt_b64 = "cHNidP8BAHICAAAAAXT0yaTajRSLu1boaayjaQ3aDOOsvPgWCcyUbRtvFkrOAQAAAAD9////AlDUEgAAAAAAFgAUMxjgT65sEq/LAJxpzVflslBK5rT1cQgAAAAAABepFG1IUtrzpUCfdyFtu46j1ZIxLX7phwAAAAAAAQCMAgAAAAHQ47WR3EhO23HqtmoOmUcxAH/rfQgqUMdC8CPqCQFNHgEAAAAXFgAU4xDQRPiNqxtCdp5KhMrwg2P57MH9////AmDqAAAAAAAAGXapFEWIHtDTWHVQ95SEe3yLn6A+3Qo8iKx/ZhsAAAAAABepFPBGTZ+g6kLYDk1fFFeIOYLiO47shwAAAAABASB/ZhsAAAAAABepFPBGTZ+g6kLYDk1fFFeIOYLiO47shwEEFgAUyweAh+/0haqiJg6UpT19bRxd0VEiBgJLo7d9kz3p+j+VgzSMQPPKry7/rVtuJE7Oirv8xyRPZxj1rML9MQAAgAEAAIAAAACAAQAAAAAAAAAAAAEAFgAUTLRHxTu3NSNPKxOQ1F2dhksVdtMiAgOKsR70a0i1XwDFPv3fOM3f+dYzW8r1L6n5k4R/LM0vVxj1rML9MQAAgAEAAIAAAACAAQAAAAIAAAAA";
        let psbt = general_purpose::STANDARD.decode(psbt_b64).unwrap();
        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt),
            name: "".into(),
            descriptor_template: "sh(wpkh(@0/**))".into(),
            keys_info: vec!["[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3".into()],
            wallet_hmac: Cow::Owned([0u8; 32].into()),
        };

        let resp = handle_sign_psbt(req, &mut state).unwrap();

        assert_eq!(1, resp.partial_signatures.len());
        assert_eq!(
            resp.partial_signatures[0].public_key.as_ref(),
            hex!("024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67")
        );
        assert_eq!(
            resp.partial_signatures[0].signature.as_ref(),
            hex!("30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201")
        );
    }

    #[test]
    fn test_sign_psbt_taproot_1to2_sighash_default() {
        let mut state = AppState::new();

        let psbt_b64 = "cHNidP8BAH0CAAAAAeFoYcDSl0n1LNLt3hDLzE9ZEhBxD2QOXY4UQM6F2W3GAQAAAAD9////Ao00lwAAAAAAIlEgC450hrwwagrvt6fACvBAVULbGs1z7syoJ3HM9f5etg+ghgEAAAAAABYAFBOZuKCYR6A5sDUvWNISwYC6sX93AAAAAAABASvfu5gAAAAAACJRIImQSmNI1/+aRNSduLaoB8Yi6Gg2TFR9pCbzC1piExhqIRbpxpsJXtBLVir8jUFpGTa6Vz629om8I2YAvk+jkm9kEhkA9azC/VYAAIABAACAAAAAgAEAAAADAAAAARcg6cabCV7QS1Yq/I1BaRk2ulc+tvaJvCNmAL5Po5JvZBIAAQUgApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwohBwKQgezlYWqhy5kxn8SHTv7kfwjOul9gBGNsjENAml8KGQD1rML9VgAAgAEAAIAAAACAAQAAAAIAAAAAAA==";
        let psbt = general_purpose::STANDARD.decode(psbt_b64).unwrap();

        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt),
            name: "".into(),
            descriptor_template: "tr(@0/**)".into(),
            keys_info: vec!["[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U".into()],
            wallet_hmac: Cow::Owned([0u8; 32].into()),
        };

        let resp = handle_sign_psbt(req, &mut state).unwrap();

        assert_eq!(1, resp.partial_signatures.len());

        let sighash0 = hex!("75C96FB06A12DB4CD011D8C95A5995DB758A4F2837A22F30F0F579619A4466F3");
        let expected_pubkey0 = hex!("89904a6348d7ff9a44d49db8b6a807c622e868364c547da426f30b5a6213186a");

        assert_eq!(
            resp.partial_signatures[0].public_key.as_ref(),
            expected_pubkey0
        );

        let pk0 = EcfpPublicKey::from_slice(&hex!("0289904a6348d7ff9a44d49db8b6a807c622e868364c547da426f30b5a6213186a")).unwrap();
        
        assert!(pk0.schnorr_verify(&sighash0, &resp.partial_signatures[0].signature).is_ok());
    }

    #[test]
    fn test_sign_psbt_taproot_one_of_two_keypath() {
        let mut state = AppState::new();

        let psbt_b64 = "cHNidP8BAH0CAAAAARyD92fm9xaA9eCXnykMiMAsCvnIZcdKDpDf1xI8I5QgAAAAAAD9////AkBCDwAAAAAAFgAUbbB+O/G8egsod5XlpAY3nvu+TGyxU4kAAAAAACJRIBaRiwbPPzNW6pfUiY95PwtiIqrb2ODgM6QQ8cHMvuX/AAAAAAABASuAlpgAAAAAACJRIB4TMFcAuIn4KRwUfYSpWHix/oO7tHkcooxVtIy4l4IWIhXB8Ghhpn+RmWZVJHBLEV/D3FinYvLtIIaUH7Z8dciZ100jIAureFzNrWcyATWornuwSSrjQPYZni7QHg+jUrJRiVKErMAhFgureFzNrWcyATWornuwSSrjQPYZni7QHg+jUrJRiVKELQFp8Ywh1OxQTuAEQnoSHXbbu6UcDuDcDmHexTLcj5cmRG0MXisAAAAAAwAAACEW8Ghhpn+RmWZVJHBLEV/D3FinYvLtIIaUH7Z8dciZ100ZAPWswv3zAQCAAQAAgAAAAIAAAAAAAwAAAAEXIPBoYaZ/kZlmVSRwSxFfw9xYp2Ly7SCGlB+2fHXImddNARggafGMIdTsUE7gBEJ6Eh1227ulHA7g3A5h3sUy3I+XJkQAAAEFIB+dMYSodZntC8TH6dZOtrKVhF7npNxJLirsJEqaTXgFAQYlAMAiIDQ/28Tx2vaZxFcJGHT1r3zSMaw0Bl9fWsEWrJBO2jRXrCEHH50xhKh1me0LxMfp1k62spWEXuek3EkuKuwkSppNeAUZAPWswv3zAQCAAQAAgAAAAIABAAAAAAAAACEHND/bxPHa9pnEVwkYdPWvfNIxrDQGX19awRaskE7aNFctAaGJVSkyY1gng9xGPmbEK0OQAYYla4Fa7Q0PhKDn6uGebQxeKwEAAAAAAAAAAA==";
        let psbt = general_purpose::STANDARD.decode(psbt_b64).unwrap();

        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt),
            name: "Tapscript 1-of-2".into(),
            descriptor_template: "tr(@0/**,pk(@1/**))".into(),
            keys_info: vec!["[f5acc2fd/499'/1'/0']tpubDD863BuWFdsaCg6f1SGdwLxp9mDcm3YRm3HxxbppBrizxvU1MqhQ1WpMwhz4vrZHNT7NFbXQ35CquVG9xaLsWaUWfSMZamDESisvtKZ7veF".into(), "tpubDCgZq8booPEaCEE3SFUDV65wEJYeWySipSvZnLXwNYDy6tiGHrvfhXK4hxJHeSEBWt1yy7SY1hU9GFnUtjcnUEfjZBHmYQexj1i7VoEko6a".into()],
            wallet_hmac: Cow::Owned(DUMMY_HMAC.into()),
        };

        // correct hmac: a2aa3956ee01ff09862f0836120818d9b526fb7c94479d890517f6111a135979

        let resp = handle_sign_psbt(req, &mut state).unwrap();

        assert_eq!(1, resp.partial_signatures.len());

        let sighash0 = hex!("be2cef3778a39a6cc1ed44072279656f0e18a32061e7d4ac68f85c5ed24ffe3b");
        let expected_pubkey0 = hex!("1e13305700b889f8291c147d84a95878b1fe83bbb4791ca28c55b48cb8978216");

        assert_eq!(
            resp.partial_signatures[0].public_key.as_ref(),
            expected_pubkey0
        );

        let pk0 = EcfpPublicKey::from_slice(&hex!("021e13305700b889f8291c147d84a95878b1fe83bbb4791ca28c55b48cb8978216")).unwrap();

        assert!(pk0.schnorr_verify(&sighash0, &resp.partial_signatures[0].signature).is_ok());
    }

    #[test]
    fn test_sign_psbt_taproot_one_of_two_scriptpath() {
        let mut state = AppState::new();

        let psbt_b64 = "cHNidP8BAH0CAAAAAeBlTa1pssUA7CgCLgfd4OboYX92uYKzC3mc0Kd7G5g/AQAAAAD9////AkBCDwAAAAAAFgAUM7ZA3qe/76dyjkXUY91rjHyGT46xU4kAAAAAACJRIEUjFCPb+bIyA5ajhLXpUmVnevH/Cva3kF/nGEnnTU3UAAAAAAABASuAlpgAAAAAACJRICpH2ZLtvOaEXKucNkhSGQ4KXAKcuZdLv12HLiaCkaGqIhXAUUAi0WoVpbHdhlhDArD0YCKxsI4gH8OopKkvpJmNo0QjIPBoYaZ/kZlmVSRwSxFfw9xYp2Ly7SCGlB+2fHXImddNrMAhFlFAItFqFaWx3YZYQwKw9GAisbCOIB/DqKSpL6SZjaNEDQAGEsg4AAAAAAMAAAAhFvBoYaZ/kZlmVSRwSxFfw9xYp2Ly7SCGlB+2fHXImddNOQFNr+UKO/a0qUFBXpxRR8k8bNcc0xf06X/6ktl6j3hmDfWswv3zAQCAAQAAgAAAAIAAAAAAAwAAAAEXIFFAItFqFaWx3YZYQwKw9GAisbCOIB/DqKSpL6SZjaNEARggTa/lCjv2tKlBQV6cUUfJPGzXHNMX9Ol/+pLZeo94Zg0AAAEFILfHwWcz2lMQ+4BjBY+9BI8R0br59uVGNp7U6oOQGn2DAQYlAMAiIB+dMYSodZntC8TH6dZOtrKVhF7npNxJLirsJEqaTXgFrCEHH50xhKh1me0LxMfp1k62spWEXuek3EkuKuwkSppNeAU5AZenZqSVLNhaynTQlVY2EqPYnzBzBawAp+hu10OiRNQQ9azC/fMBAIABAACAAAAAgAEAAAAAAAAAIQe3x8FnM9pTEPuAYwWPvQSPEdG6+fblRjae1OqDkBp9gw0ABhLIOAEAAAAAAAAAAA==";
        let psbt = general_purpose::STANDARD.decode(psbt_b64).unwrap();

        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt),
            name: "Tapscript 1-of-2".into(),
            descriptor_template: "tr(@0/**,pk(@1/**))".into(),
            keys_info: vec!["tpubDD4GfCYs14EsPL4zKXxqfsaRmSHKVb2zVRNeYT6Dvf6qV7k9tDenuAkfu9hkJDmCfGdSdEY8AAN3ksM5vUf4BzQX4ZYzsJViB6PqDa88zJD".into(), "[f5acc2fd/499'/1'/0']tpubDD863BuWFdsaCg6f1SGdwLxp9mDcm3YRm3HxxbppBrizxvU1MqhQ1WpMwhz4vrZHNT7NFbXQ35CquVG9xaLsWaUWfSMZamDESisvtKZ7veF".into()],
            wallet_hmac: Cow::Owned(DUMMY_HMAC.into()),
        };

        // correct hmac: 39bc8b31d8dbdf7ca9def761f424415278b3979f0f02fe944390fc274d22a23c

        let resp = handle_sign_psbt(req, &mut state).unwrap();

        assert_eq!(1, resp.partial_signatures.len());

        let expected_pubkey0 = hex!("f06861a67f9199665524704b115fc3dc58a762f2ed2086941fb67c75c899d74d");
        assert_eq!(
            resp.partial_signatures[0].public_key.as_ref(),
            expected_pubkey0
        );

        assert_eq!(
            resp.partial_signatures[0].leaf_hash.as_ref(),
            hex!("4dafe50a3bf6b4a941415e9c5147c93c6cd71cd317f4e97ffa92d97a8f78660d")
        );

        let sighash0 = hex!("8de18c56cd1c46dc29580066e3110c96b34c12e11657f9b4715e9d8608afa5bf");
        let pk0 = EcfpPublicKey::from_slice(&hex!("02f06861a67f9199665524704b115fc3dc58a762f2ed2086941fb67c75c899d74d")).unwrap();
        assert!(pk0.schnorr_verify(&sighash0, &resp.partial_signatures[0].signature).is_ok());
    }

    #[test]
    fn test_sign_psbt_taproot_mixed_leaves() {
        let mut state = AppState::new();

        let psbt_b64 = "cHNidP8BAH0CAAAAAT/s+bFWC4qSdCgu8vBg0R3Is6F5V++DlzxfJW5iooA5AQAAAAD9////ArFTiQAAAAAAIlEgYSuRcVrAMItU1ZKLbM52s/Mldzv/NW1V1RFTwKaiOEtAQg8AAAAAABYAFD1rSF6Ut32Gl7uqITdK0dgjp0AjAAAAAAABASuAlpgAAAAAACJRIMsSsCReA4mYZcgXEFyweaQml7W2NubI28JFaUprJ23ZQhXBqMCJq89i2G1g5l1+2h2QXtUs2BWxLCjC1/AsvIlUelAU6uxZMl3c47bD6R2bctreuU58yURlmCDUCW4VtCPPA0cgjllRI6lh/yR/tvtlWJx8T1+ZjO7aT8CxxBYtEccvvzysfCDX8NE482/sEFPdWfIOiQmBEHfIKC5+VqJfX2k4oOmlnaybwEIVwajAiavPYthtYOZdftodkF7VLNgVsSwowtfwLLyJVHpQzEfVpJ5XzfEGJJl2MqubgZyzTb/+Okz26rqq9hBF2sxHIKCIZm4YKSGJj1/xqvCGUpl2ZSIfNc2V6irXLfFJa7xWrCDwaGGmf5GZZlUkcEsRX8PcWKdi8u0ghpQftnx1yJnXTbpRnMAhFo5ZUSOpYf8kf7b7ZVicfE9fmYzu2k/AscQWLRHHL788LQHMR9WknlfN8QYkmXYyq5uBnLNNv/46TPbquqr2EEXazHrQB5MAAAAAAwAAACEWoIhmbhgpIYmPX/Gq8IZSmXZlIh81zZXqKtct8UlrvFYtARTq7FkyXdzjtsPpHZty2t65TnzJRGWYINQJbhW0I88DHA1sHwAAAAADAAAAIRaowImrz2LYbWDmXX7aHZBe1SzYFbEsKMLX8Cy8iVR6UA0A6xNxJQAAAAADAAAAIRbX8NE482/sEFPdWfIOiQmBEHfIKC5+VqJfX2k4oOmlnS0BzEfVpJ5XzfEGJJl2MqubgZyzTb/+Okz26rqq9hBF2szT2HrVAAAAAAMAAAAhFvBoYaZ/kZlmVSRwSxFfw9xYp2Ly7SCGlB+2fHXImddNOQEU6uxZMl3c47bD6R2bctreuU58yURlmCDUCW4VtCPPA/Wswv3zAQCAAQAAgAAAAIAAAAAAAwAAAAEXIKjAiavPYthtYOZdftodkF7VLNgVsSwowtfwLLyJVHpQARggY4rj54n2Z6TO4klOVN9Kgv6NeB8L6utSoCwcSTpWAyQAAQUgfqC9jk3ICC0fdbfRF75U5dv+jdD4Qbr9TdEhKibYA4wBBpIBwEYgpL3cigfm7EOtnj/BqvkHtJV5SdwcGDNBRRC1iwoVQH+sfCBYgOVhZ1qi3FS+xZ0gYIsg9zTgzYWB5FFtVH4UlubcMqybAcBGIB+dMYSodZntC8TH6dZOtrKVhF7npNxJLirsJEqaTXgFrCBMGqLLsl79NuU6CLyrU8/a8J5Z5/R0zmPwCWK7Q2JQr7pRnCEHH50xhKh1me0LxMfp1k62spWEXuek3EkuKuwkSppNeAU5AeV0ozvJnbG/u6fNbexpRBrT3f+loDkin4I2sW71L3D99azC/fMBAIABAACAAAAAgAEAAAAAAAAAIQdMGqLLsl79NuU6CLyrU8/a8J5Z5/R0zmPwCWK7Q2JQry0B5XSjO8mdsb+7p81t7GlEGtPd/6WgOSKfgjaxbvUvcP0cDWwfAQAAAAAAAAAhB1iA5WFnWqLcVL7FnSBgiyD3NODNhYHkUW1UfhSW5twyLQHCMIvATlZBGefKCXTa/otZr6BB28tYknXccfHHwJtYJdPYetUBAAAAAAAAACEHfqC9jk3ICC0fdbfRF75U5dv+jdD4Qbr9TdEhKibYA4wNAOsTcSUBAAAAAAAAACEHpL3cigfm7EOtnj/BqvkHtJV5SdwcGDNBRRC1iwoVQH8tAcIwi8BOVkEZ58oJdNr+i1mvoEHby1iSddxx8cfAm1gletAHkwEAAAAAAAAAAAA=";
        let psbt = general_purpose::STANDARD.decode(psbt_b64).unwrap();

        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt),
            name: "Mixed tapminiscript and not".into(),
            descriptor_template: "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})".into(),
            keys_info: vec![
                "tpubDCYGWahE7aGXr9NLhJBwyE8CmLWDq3T6bEJTFN47jREEtKk5thyZhQwpTbDAXan6Ra1bSF63JjV4eiaHwVE2YzZ9N6myRRSCW2ZM3C4Udcg".into(),
                "[f5acc2fd/499'/1'/0']tpubDD863BuWFdsaCg6f1SGdwLxp9mDcm3YRm3HxxbppBrizxvU1MqhQ1WpMwhz4vrZHNT7NFbXQ35CquVG9xaLsWaUWfSMZamDESisvtKZ7veF".into(),
                "tpubDCTUEzaPKfWk4bSmVKY11FtbK3FZS3AdYPati8WTbH6Nzdaw7wEW8SeYbsqHbnH46bhnZaC45ua4pug4kzDbE29WXxZQ61LwjbeKqQ5dnQQ".into(),
                "tpubDCa4qupLAGRh3vXKS8hH1aJySQd4dKA4L8QsVLYXQZbcNYZqYvf1nJ57pZAVjzeV9D2wevL7UWkqdupWezBw1i3y3PpvmS2iZh5BiJCgYkq".into(),
                "tpubDDgFur3VTfVC4TD9wNBBXaJmfz6evDY6Hng6paUYCEUd6PHmBW8wtvTzus2HaCnbs7wq7TDnSkMchdKPteDVLGZnb19WiT3EcrEcXkeZVgk".into()
            ],
            wallet_hmac: Cow::Owned(DUMMY_HMAC.into()),
        };

        // correct hmac: 4c2f6e1f716bf889517379567aa53a8562bd731191b156509429bccd32f11cf0

        let resp = handle_sign_psbt(req, &mut state).unwrap();

        assert_eq!(1, resp.partial_signatures.len());

        let sighash0 = hex!("128fcd3ec58c3ebe44f604fccf692ab2c6917185d944854c2899c2d224fad479");
        let expected_pubkey0 = hex!("f06861a67f9199665524704b115fc3dc58a762f2ed2086941fb67c75c899d74d");

        assert_eq!(
            resp.partial_signatures[0].public_key.as_ref(),
            expected_pubkey0
        );

        assert_eq!(
            resp.partial_signatures[0].leaf_hash.as_ref(),
            hex!("14eaec59325ddce3b6c3e91d9b72dadeb94e7cc944659820d4096e15b423cf03")
        );

        let pk0 = EcfpPublicKey::from_slice(&hex!("02f06861a67f9199665524704b115fc3dc58a762f2ed2086941fb67c75c899d74d")).unwrap();
        assert!(pk0.schnorr_verify(&sighash0, &resp.partial_signatures[0].signature).is_ok());
    }

    #[test]
    fn test_sign_psbt_musig2_keypath() -> Result<()> {
        let mut state = AppState::new();

        let psbt_b64 = "cHNidP8BAIACAAAAAWbcwfJ78yV/+Jn0waX9pBWhDp2pZCm0GuTEXe2wXcP2AQAAAAD9////AQAAAAAAAAAARGpCVGhpcyBpbnB1dHMgaGFzIHR3byBwdWJrZXlzIGJ1dCB5b3Ugb25seSBzZWUgb25lLiAjbXBjZ2FuZyByZXZlbmdlAAAAAAABASuf/gQAAAAAACJRIPSL0RqGcuiQxWUrpyqc9CJwAk7i1Wk1p+YZWmGpB5tmIRbGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7Bxg0AAAAAAAAAAAADAAAAAAA=";
        let psbt_bin = general_purpose::STANDARD.decode(psbt_b64).unwrap();
        let mut psbt = Psbt::deserialize(&psbt_bin)?;
    
        assert_eq!(psbt.inputs.len(), 1);
        
        let cosigner_xpriv = bitcoin::bip32::Xpriv::from_str("tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf")?;
        let cosigner_xpub = bitcoin::bip32::Xpub::from_priv(&Secp256k1::new(), &cosigner_xpriv);
        let cosigner_privkey_scalar = Scalar::from_bytes(cosigner_xpriv.private_key.secret_bytes()).ok_or("Failed to deserialize privkey")?.non_zero().unwrap();
        let cosigner_keypair: schnorr_fun::fun::KeyPair = KeyPair::<Normal>::new(cosigner_privkey_scalar);
        
        assert_eq!(cosigner_xpub.to_string(), "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm");

        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt_bin),
            name: "Musig for my ears".into(),
            descriptor_template: "tr(musig(@0,@1)/**)".into(),
            keys_info: vec![
                "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".into(),
                cosigner_xpub.to_string().into()
            ],
            wallet_hmac: Cow::Owned(DUMMY_HMAC.into()),
        };

        let resp = handle_sign_psbt(req, &mut state)?;

        assert_eq!(1, resp.musig_public_nonces.len());

        for ret_nonce in resp.musig_public_nonces {
            assert_eq!(66, ret_nonce.pubnonce.len());

            let ppk = bitcoin::secp256k1::PublicKey::from_slice(&ret_nonce.participant_public_key)?;

            let xopk: XOnlyPublicKey = XOnlyPublicKey::from_slice(&ret_nonce.xonly_key)?;

            let psbt_pub_nonce_identifier = (
                ppk,
                xopk,
                if ret_nonce.leaf_hash.len() == 0 { None::<TapLeafHash> } else { Some(TapLeafHash::from_slice(&ret_nonce.leaf_hash).unwrap()) }
            );
            
            psbt.inputs[ret_nonce.input_index as usize].musig2_pub_nonces.insert(psbt_pub_nonce_identifier, ret_nonce.pubnonce.to_vec());
        }

        let device_xpub = Xpub::from_str("tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT")?;

        let musig: schnorr_fun::musig::MuSig<MySha256, schnorr_fun::nonce::Deterministic<MySha256>> = new_with_deterministic_nonces::<MySha256>();

        let mut agg_key = musig.new_agg_key(vec![
            Point::from_bytes(device_xpub.public_key.serialize()).ok_or("Error")?,
            Point::from_bytes(cosigner_xpub.public_key.serialize()).ok_or("Error")?,
        ]);

        let bip32_tweaks: Vec<[u8; 32]> = get_musig_bip32_tweaks(&agg_key, vec![0, 3])?;  // TODO: get change/addr_index from the PSBT instead

        for tweak in bip32_tweaks {
            let scalar: Scalar =
                Scalar::from_bytes(tweak).ok_or(AppError::new("Failed to create tweak"))?
                .non_zero().ok_or(AppError::new("Failed to create tweak"))?;

            agg_key = agg_key.tweak(scalar).ok_or(AppError::new("Failed to apply tweak"))?;
        }


        let mut agg_key_xonly = agg_key
            .clone()  // TODO: get rid of this clone()
            .into_xonly_key();

        let t = tagged_hash(
            BIP0341_TAPTWEAK_TAG, 
            &agg_key_xonly.agg_public_key().to_xonly_bytes(), 
            None);
        let taptweak_scalar: Scalar<Public, NonZero> = Scalar::from_bytes(t)
            .ok_or(AppError::new("Unexpected error"))?
            .non_zero()
            .ok_or(AppError::new("Unexpected zero scalar"))?;
        agg_key_xonly = agg_key_xonly.tweak(taptweak_scalar).unwrap();



        let session_id = b"musig-is-really-cool-1".as_slice();

        let cosigner_privkey = EcfpPrivateKey::new(CxCurve::Secp256k1, &cosigner_xpriv.private_key.secret_bytes());
        let cosigner_privkey_scalar = Scalar::from_bytes(*cosigner_privkey.as_bytes())
            .ok_or(AppError::new("Failed to create scalar from privkey"))?
            .non_zero().ok_or(AppError::new("Conversion to NonZero scalar failed"))?;

        let mut nonce_rng: ChaCha20Rng = musig.seed_nonce_rng(&agg_key, &cosigner_privkey_scalar, session_id);
        let cosigner_nonce = musig.gen_nonce(&mut nonce_rng);

        let cosigner_public_nonce = cosigner_nonce.public().to_bytes();

        let ppk = bitcoin::secp256k1::PublicKey::from_slice(&cosigner_xpub.public_key.serialize())?;

        let xopk = XOnlyPublicKey::from_slice(&agg_key_xonly.agg_public_key().to_xonly_bytes())?;


        let psbt_pub_nonce_identifier_cosigner = (
            ppk,
            xopk,
            None::<TapLeafHash>
        );

        psbt.inputs[0].musig2_pub_nonces.insert(psbt_pub_nonce_identifier_cosigner, cosigner_public_nonce.to_vec());

        
        let response_2 = handle_sign_psbt(RequestSignPsbt {
            psbt: Cow::Owned(psbt.serialize()),
            name: "Musig for my ears".into(),
            descriptor_template: "tr(musig(@0,@1)/**)".into(),
            keys_info: vec![
                "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".into(),
                cosigner_xpub.to_string().into()
            ],
            wallet_hmac: Cow::Owned(DUMMY_HMAC.into()),
        }, &mut state)?;

        assert_eq!(response_2.musig_partial_signatures.len(), 1);

        let mut nonces: Vec<Nonce> = vec![];
        for participant_key in agg_key.keys() {
            if let Some(nonce_bytes) = psbt.inputs[0].musig2_pub_nonces.get(&(
                bitcoin::secp256k1::PublicKey::from_slice(&participant_key.to_bytes())?,
                XOnlyPublicKey::from_slice(&agg_key_xonly.agg_public_key().to_xonly_bytes())?,
                None::<TapLeafHash>
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

        let sighash = TapSighash::from_slice(&hex!("f3f6d4ae955af42665667ccff4edc9244d9143ada53ba26aee036258e0ffeda9")).unwrap();
        let message = Message::<Public>::raw(sighash.as_byte_array());

        let session = musig.start_sign_session(&agg_key_xonly, nonces, message);

        let cosigner_partial_sig = musig.sign(&agg_key_xonly, &session, 1, &cosigner_keypair, cosigner_nonce);

        let device_partial_sig: Scalar<Public, schnorr_fun::fun::marker::Zero> = Scalar::from_slice(&response_2.musig_partial_signatures[0].signature).unwrap();

        let sig = musig.combine_partial_signatures(&agg_key_xonly, &session, [device_partial_sig, cosigner_partial_sig]);


        let result = musig
            .schnorr
            .verify(&agg_key_xonly.agg_public_key(), message, &sig);

        assert!(result);

        psbt.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature::from_slice(&sig.to_bytes())?);

        Ok(())
    }


    #[test]
    fn test_sign_psbt_musig2_scriptpath() -> Result<()> {
        let mut state = AppState::new();

        let psbt_b64 = "cHNidP8BAFoCAAAAAeyfHxrwzXffQqF9egw6KMS7RwCLP4rW95dxtXUKYJGFAQAAAAD9////AQAAAAAAAAAAHmocTXVzaWcyLiBOb3cgZXZlbiBpbiBTY3JpcHRzLgAAAAAAAQErOTAAAAAAAAAiUSDZqQIMWvfc0h2w2z6+0vTt0z1YoUHA6JHynopzSe3hgiIVwethFsEeXf/x51pIczoAIsj9RoVePIBTyk/rOMW8B6uIIyDGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7BxqzAIRbGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7Bxi0BkW61VIaT9Qaz/k0SzoZ1UBsjkrXzPqXQbCbBjbNZP/kAAAAAAAAAAAMAAAABFyDrYRbBHl3/8edaSHM6ACLI/UaFXjyAU8pP6zjFvAeriAEYIJFutVSGk/UGs/5NEs6GdVAbI5K18z6l0GwmwY2zWT/5AAA=";
        let psbt_bin = general_purpose::STANDARD.decode(psbt_b64).unwrap();
        let mut psbt = Psbt::deserialize(&psbt_bin)?;
    
        assert_eq!(psbt.inputs.len(), 1);
        
        let cosigner_xpriv = bitcoin::bip32::Xpriv::from_str("tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf")?;
        let cosigner_xpub = bitcoin::bip32::Xpub::from_priv(&Secp256k1::new(), &cosigner_xpriv);
        let cosigner_privkey_scalar = Scalar::from_bytes(cosigner_xpriv.private_key.secret_bytes()).ok_or("Failed to deserialize privkey")?.non_zero().unwrap();
        let cosigner_keypair: schnorr_fun::fun::KeyPair = KeyPair::<Normal>::new(cosigner_privkey_scalar);
        
        assert_eq!(cosigner_xpub.to_string(), "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm");

        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt_bin),
            name: "Musig2 in the scriptpath".into(),
            descriptor_template: "tr(@0/**,pk(musig(@1,@2)/**))".into(),
            keys_info: vec![
                "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN".into(),
                "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".into(),
                cosigner_xpub.to_string().into()
            ],
            wallet_hmac: Cow::Owned(DUMMY_HMAC.into()),
        };

        let wallet_policy = WalletPolicy::new(
            req.name.clone().into(),
            &req.descriptor_template.clone().into_owned(),
            req.keys_info
                .iter()
                .map(|s| s.as_ref())
                .collect::<Vec<&str>>(),
        )?;
        let tapleaf_desc = match wallet_policy.descriptor_template {
            DescriptorTemplate::Tr(_, Some(crate::wallet::TapTree::Script(leaf))) => *leaf,
            _ => panic!("Expecting a tr descriptor with a single script tapleaf in this test"),
        };

        let resp = handle_sign_psbt(req, &mut state)?;

        assert_eq!(1, resp.musig_public_nonces.len());

        for ret_nonce in resp.musig_public_nonces {
            assert_eq!(66, ret_nonce.pubnonce.len());

            let ppk = bitcoin::secp256k1::PublicKey::from_slice(&ret_nonce.participant_public_key)?;

            let xopk: XOnlyPublicKey = XOnlyPublicKey::from_slice(&ret_nonce.xonly_key)?;

            let psbt_pub_nonce_identifier = (
                ppk,
                xopk,
                if ret_nonce.leaf_hash.len() == 0 { None::<TapLeafHash> } else { Some(TapLeafHash::from_slice(&ret_nonce.leaf_hash).unwrap()) }
            );
            
            psbt.inputs[ret_nonce.input_index as usize].musig2_pub_nonces.insert(psbt_pub_nonce_identifier, ret_nonce.pubnonce.to_vec());
        }

        let device_xpub = Xpub::from_str("tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT")?;

        let musig: schnorr_fun::musig::MuSig<MySha256, schnorr_fun::nonce::Deterministic<MySha256>> = new_with_deterministic_nonces::<MySha256>();

        let mut agg_key = musig.new_agg_key(vec![
            Point::from_bytes(device_xpub.public_key.serialize()).ok_or("Error")?,
            Point::from_bytes(cosigner_xpub.public_key.serialize()).ok_or("Error")?,
        ]);

        let bip32_tweaks: Vec<[u8; 32]> = get_musig_bip32_tweaks(&agg_key, vec![0, 3])?;  // TODO: get change/addr_index from the PSBT instead

        for tweak in bip32_tweaks {
            let scalar: Scalar =
                Scalar::from_bytes(tweak).ok_or(AppError::new("Failed to create tweak"))?
                .non_zero().ok_or(AppError::new("Failed to create tweak"))?;

            agg_key = agg_key.tweak(scalar).ok_or(AppError::new("Failed to apply tweak"))?;
        }


        let agg_key_xonly = agg_key
            .clone()
            .into_xonly_key();

        // we don't apply the taptweak, since we're spending a script

        let session_id = b"musig-is-really-cool-1".as_slice();

        let cosigner_privkey = EcfpPrivateKey::new(CxCurve::Secp256k1, &cosigner_xpriv.private_key.secret_bytes());
        let cosigner_privkey_scalar = Scalar::from_bytes(*cosigner_privkey.as_bytes())
            .ok_or(AppError::new("Failed to create scalar from privkey"))?
            .non_zero().ok_or(AppError::new("Conversion to NonZero scalar failed"))?;

        let mut nonce_rng: ChaCha20Rng = musig.seed_nonce_rng(&agg_key, &cosigner_privkey_scalar, session_id);
        let cosigner_nonce = musig.gen_nonce(&mut nonce_rng);

        let cosigner_public_nonce = cosigner_nonce.public().to_bytes();

        let ppk = bitcoin::secp256k1::PublicKey::from_slice(&cosigner_xpub.public_key.serialize())?;

        let xopk = XOnlyPublicKey::from_slice(&agg_key_xonly.agg_public_key().to_xonly_bytes())?;

        let leaf_hash = tapleaf_desc.get_tapleaf_hash(&wallet_policy.key_information, false, 3)?;

        let psbt_pub_nonce_identifier_cosigner = (
            ppk,
            xopk,
            Some(TapLeafHash::from_byte_array(leaf_hash))
        );

        psbt.inputs[0].musig2_pub_nonces.insert(psbt_pub_nonce_identifier_cosigner, cosigner_public_nonce.to_vec());


        let response_2 = handle_sign_psbt(RequestSignPsbt {
            psbt: Cow::Owned(psbt.serialize()),
            name: "Musig2 in the scriptpath".into(),
            descriptor_template: "tr(@0/**,pk(musig(@1,@2)/**))".into(),
            keys_info: vec![
                "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN".into(),
                "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".into(),
                cosigner_xpub.to_string().into()
            ],
            wallet_hmac: Cow::Owned(DUMMY_HMAC.into()),
        }, &mut state)?;

        assert_eq!(response_2.musig_partial_signatures.len(), 1);

        let mut nonces: Vec<Nonce> = vec![];
        for participant_key in agg_key.keys() {
            if let Some(nonce_bytes) = psbt.inputs[0].musig2_pub_nonces.get(&(
                bitcoin::secp256k1::PublicKey::from_slice(&participant_key.to_bytes())?,
                XOnlyPublicKey::from_slice(&agg_key_xonly.agg_public_key().to_xonly_bytes())?,
                Some(TapLeafHash::from_byte_array(leaf_hash))
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

        let sighash = TapSighash::from_slice(&hex!("ba6d1d859dbc471999fff1fc5b8740fdacadd64a10c8d62de76e39a1c8dcd835")).unwrap();
        let message = Message::<Public>::raw(sighash.as_byte_array());

        let session = musig.start_sign_session(&agg_key_xonly, nonces, message);

        let cosigner_partial_sig = musig.sign(&agg_key_xonly, &session, 1, &cosigner_keypair, cosigner_nonce);

        let device_partial_sig: Scalar<Public, schnorr_fun::fun::marker::Zero> = Scalar::from_slice(&response_2.musig_partial_signatures[0].signature).unwrap();

        let sig = musig.combine_partial_signatures(&agg_key_xonly, &session, [device_partial_sig, cosigner_partial_sig]);


        let result = musig
            .schnorr
            .verify(&agg_key_xonly.agg_public_key(), message, &sig);

        assert!(result);

        psbt.inputs[0].tap_script_sigs.insert(
            (
                XOnlyPublicKey::from_slice(&agg_key_xonly.agg_public_key().to_xonly_bytes())?,
                TapLeafHash::from_byte_array(leaf_hash)
            ),
            bitcoin::taproot::Signature::from_slice(&sig.to_bytes()).unwrap()
        );

        Ok(())
    }
}