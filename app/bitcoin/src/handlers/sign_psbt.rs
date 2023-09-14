use alloc::{borrow::Cow, format, vec, vec::Vec};
use subtle::ConstantTimeEq;
use vanadium_sdk::crypto::{CxCurve, CxMd, EcfpPrivateKey, CX_RND_RFC6979};

use crate::{
    message::message::{PartialSignature, RequestSignPsbt, ResponseSignPsbt},
    wallet::{WalletPolicy, SegwitVersion, KeyOrigin, KeyPlaceholder, DescriptorTemplate}, taproot::TapTweak,
};

#[cfg(not(test))]
use vanadium_sdk::{
    glyphs::{ICON_CROSSMARK, ICON_EYE, ICON_VALIDATE},
    ux::{app_loading_stop, ux_validate, UxAction, UxItem},
};

use bitcoin::{psbt::Psbt, sighash::SighashCache, ScriptBuf, bip32::{Fingerprint, DerivationPath}, Transaction, TapSighashType, TxOut};

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

    let mut signature = privkey.ecdsa_sign(CX_RND_RFC6979 as i32, CxMd::Sha256, sighash.as_ref())?;
    signature.push(sighash_type.to_u32() as u8);

    Ok(PartialSignature {
        signature: Cow::Owned(signature),
        public_key: Cow::Owned(pubkey.to_compressed().to_vec()),
        leaf_hash: Cow::Owned(vec![]),
    })
}

fn sign_input_schnorr<'a>(psbt: &Psbt, input_index: usize, sighash_cache: &mut SighashCache<Transaction>, path: &[u32]) -> Result<PartialSignature<'a>> {
    // TODO: only BIP86 for now

    let sighash_type = TapSighashType::Default; // TODO: only DEFAULT is supported for now

    let prevouts = psbt.inputs.iter()
        .map(|input| input.witness_utxo.clone().ok_or(AppError::new("Missing witness utxo")))
        .collect::<Result<Vec<TxOut>>>()?;

    let sighash = sighash_cache.taproot_key_spend_signature_hash(
        input_index,
        &bitcoin::sighash::Prevouts::All(&prevouts),
        sighash_type
    ).map_err(|_| AppError::new("Error computing sighash"))?;

    let mut privkey = EcfpPrivateKey::from_path(CxCurve::Secp256k1, path)?;

    // BIP-86-compliant tweak
    privkey.taptweak(&[])?;

    let pubkey = privkey.pubkey()?;

    let mut signature = privkey.schnorr_sign(sighash.as_ref())?;
    
    if sighash_type != TapSighashType::Default {
        signature.push(sighash_type as u8)
    }

    Ok(PartialSignature {
        signature: Cow::Owned(signature),
        public_key: Cow::Owned(pubkey.to_compressed()[1..].to_vec()), // x-only pubkey
        leaf_hash: Cow::Owned(vec![]),
    })
}


fn find_change_and_addr_index(psbt: &Psbt, wallet_policy: &WalletPolicy, placeholder: &KeyPlaceholder, key_origin: &KeyOrigin, master_fpr: u32) -> Option<(bool, u32)> {
    for input in psbt.inputs.iter() {
        let keys_and_origins: Vec<&(Fingerprint, DerivationPath)> = if wallet_policy.get_segwit_version() == Ok(SegwitVersion::Taproot) {
            input.tap_key_origins.iter().map(|(_, (_, x))| x).collect()
        } else {
            input.bip32_derivation.iter().map(|(_, x)| x).collect()
        };

        for (fpr, der) in keys_and_origins {
            let fpr = u32::from_be_bytes(*fpr.as_bytes());
            let der: Vec<u32> = der.into_iter().map(|x| u32::from(*x)).collect();

            if fpr == master_fpr {
                // TODO: should rederive the key and check if the key actually matches

                // check if it matches
                let orig_len = key_origin.derivation_path.len();
                if der.len() == orig_len + 2 && key_origin.derivation_path == der[..orig_len] {
                    let change_step = der[orig_len];
                    let addr_index = der[orig_len + 1];

                    if placeholder.num1 == change_step {
                        return Some((false, addr_index));
                    } else if placeholder.num2 == change_step {
                        return Some((true, addr_index));
                    }
                }
            }
        }
    }

    None
}

pub fn handle_sign_psbt<'a>(req: RequestSignPsbt) -> Result<ResponseSignPsbt<'a>> {
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
    let psbt = Psbt::deserialize(&req.psbt)
        .map_err(|_| AppError::new("Error deserializing psbt"))?;

    let mut sighash_cache = SighashCache::new(psbt.unsigned_tx.clone());

    let master_fingerprint = vanadium_sdk::crypto::get_master_fingerprint()?;

    for placeholder in wallet_policy.descriptor_template.placeholders() {
        // TODO: check if key is internal; for now we just trust the fingerprint

        let key_info = wallet_policy.key_information[placeholder.key_index as usize].clone();
        if let Some(key_origin) = key_info.origin_info.as_ref().filter(|x| x.fingerprint == master_fingerprint) {
            // for each input, verify if we can match the derivation with the current placeholder
            if let Some((is_change, addr_index)) = find_change_and_addr_index(&psbt, &wallet_policy, &placeholder, &key_origin, master_fingerprint) {
    
                let mut path = key_info.origin_info.unwrap().derivation_path;
    
                path.push(if !is_change {
                    placeholder.num1
                } else {
                    placeholder.num2
                });
                path.push(addr_index);
    
                for (input_index, input) in psbt.inputs.iter().enumerate() {
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
                                if let DescriptorTemplate::Tr(_, tree) = &wallet_policy.descriptor_template {
                                    if tree.is_some() {
                                        return Err(AppError::new("Tapscripts are not implemented")); // TODO
                                    }
                                }
                                let partial_signature = sign_input_schnorr(&psbt, input_index, &mut sighash_cache, &path)?;
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
    }

    Ok(ResponseSignPsbt { partial_signatures })
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::{engine::general_purpose, Engine as _};
    use hex_literal::hex;
    use vanadium_sdk::crypto::EcfpPublicKey;

    #[test]
    fn test_sign_psbt_singlesig_pkh_1to1() {
        let psbt_b64 = "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA";
        let psbt = general_purpose::STANDARD.decode(psbt_b64).unwrap();

        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt),
            name: "".into(),
            descriptor_template: "pkh(@0/**)".into(),
            keys_info: vec!["[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".into()],
            wallet_hmac: Cow::Owned([0u8; 32].into()),
        };

        let resp = handle_sign_psbt(req).unwrap();

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
        let psbt_b64 = "cHNidP8BAHICAAAAAXT0yaTajRSLu1boaayjaQ3aDOOsvPgWCcyUbRtvFkrOAQAAAAD9////AlDUEgAAAAAAFgAUMxjgT65sEq/LAJxpzVflslBK5rT1cQgAAAAAABepFG1IUtrzpUCfdyFtu46j1ZIxLX7phwAAAAAAAQCMAgAAAAHQ47WR3EhO23HqtmoOmUcxAH/rfQgqUMdC8CPqCQFNHgEAAAAXFgAU4xDQRPiNqxtCdp5KhMrwg2P57MH9////AmDqAAAAAAAAGXapFEWIHtDTWHVQ95SEe3yLn6A+3Qo8iKx/ZhsAAAAAABepFPBGTZ+g6kLYDk1fFFeIOYLiO47shwAAAAABASB/ZhsAAAAAABepFPBGTZ+g6kLYDk1fFFeIOYLiO47shwEEFgAUyweAh+/0haqiJg6UpT19bRxd0VEiBgJLo7d9kz3p+j+VgzSMQPPKry7/rVtuJE7Oirv8xyRPZxj1rML9MQAAgAEAAIAAAACAAQAAAAAAAAAAAAEAFgAUTLRHxTu3NSNPKxOQ1F2dhksVdtMiAgOKsR70a0i1XwDFPv3fOM3f+dYzW8r1L6n5k4R/LM0vVxj1rML9MQAAgAEAAIAAAACAAQAAAAIAAAAA";
        let psbt = general_purpose::STANDARD.decode(psbt_b64).unwrap();
        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt),
            name: "".into(),
            descriptor_template: "sh(wpkh(@0/**))".into(),
            keys_info: vec!["[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3".into()],
            wallet_hmac: Cow::Owned([0u8; 32].into()),
        };

        let resp = handle_sign_psbt(req).unwrap();

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
        let psbt_b64 = "cHNidP8BAH0CAAAAAeFoYcDSl0n1LNLt3hDLzE9ZEhBxD2QOXY4UQM6F2W3GAQAAAAD9////Ao00lwAAAAAAIlEgC450hrwwagrvt6fACvBAVULbGs1z7syoJ3HM9f5etg+ghgEAAAAAABYAFBOZuKCYR6A5sDUvWNISwYC6sX93AAAAAAABASvfu5gAAAAAACJRIImQSmNI1/+aRNSduLaoB8Yi6Gg2TFR9pCbzC1piExhqIRbpxpsJXtBLVir8jUFpGTa6Vz629om8I2YAvk+jkm9kEhkA9azC/VYAAIABAACAAAAAgAEAAAADAAAAARcg6cabCV7QS1Yq/I1BaRk2ulc+tvaJvCNmAL5Po5JvZBIAAQUgApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwohBwKQgezlYWqhy5kxn8SHTv7kfwjOul9gBGNsjENAml8KGQD1rML9VgAAgAEAAIAAAACAAQAAAAIAAAAAAA==";
        let psbt = general_purpose::STANDARD.decode(psbt_b64).unwrap();

        let req = RequestSignPsbt {
            psbt: Cow::Owned(psbt),
            name: "".into(),
            descriptor_template: "tr(@0/**)".into(),
            keys_info: vec!["[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U".into()],
            wallet_hmac: Cow::Owned([0u8; 32].into()),
        };

        let resp = handle_sign_psbt(req).unwrap();

        assert_eq!(1, resp.partial_signatures.len());

        let sighash0 = hex!("75C96FB06A12DB4CD011D8C95A5995DB758A4F2837A22F30F0F579619A4466F3");
        let expected_pubkey0 = hex!("89904a6348d7ff9a44d49db8b6a807c622e868364c547da426f30b5a6213186a");

        assert_eq!(
            resp.partial_signatures[0].public_key.as_ref(),
            expected_pubkey0
        );

        let pk0 = EcfpPublicKey::new(CxCurve::Secp256k1, &hex!("0489904a6348d7ff9a44d49db8b6a807c622e868364c547da426f30b5a6213186ab0a271082b6c3740665acbd99a93b7b3a46b847d5293ecc3af50831a2b7a5f8a"));
        
        assert!(pk0.schnorr_verify(&sighash0, &resp.partial_signatures[0].signature).is_ok());
    }
}
