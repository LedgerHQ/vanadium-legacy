use core::str::FromStr;

use alloc::{borrow::Cow, format, vec, vec::Vec};
use subtle::ConstantTimeEq;
use vanadium_sdk::crypto::{CxCurve, CxMd, EcfpPrivateKey, CX_RND_RFC6979};

use crate::{
    message::message::{PartialSignature, RequestSignPsbt, ResponseSignPsbt},
    wallet::{self, DescriptorTemplate, WalletPolicy},
};

#[cfg(not(test))]
use vanadium_sdk::{
    glyphs::{ICON_CROSSMARK, ICON_EYE, ICON_VALIDATE},
    ux::{app_loading_stop, ux_validate, UxAction, UxItem},
};

use bitcoin::{psbt::PartiallySignedTransaction, sighash::SighashCache};

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

pub fn handle_sign_psbt<'a>(req: RequestSignPsbt) -> Result<ResponseSignPsbt<'a>> {
    // compare the hmac to 0 in constant time
    let mut hmac_or: u8 = 0;
    for &byte in req.wallet_hmac.iter() {
        hmac_or |= byte;
    }

    let is_wallet_canonical = hmac_or == 0;
    if !is_wallet_canonical {
        // verify hmac
        // IMPORTANT: we use a constant time comparison
        if req.wallet_hmac.ct_eq(&DUMMY_HMAC).unwrap_u8() == 0 {
            return Err(AppError::new("Invalid hmac"));
        }
    }

    let wallet_policy = WalletPolicy::new(
        req.name.into(),
        &req.descriptor_template.clone().into_owned(),
        req.keys_info
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<&str>>(),
    )
    .map_err(|err| AppError::new(&format!("Invalid wallet policy: {}", err)))?;

    if is_wallet_canonical {
        // TODO: check that the policy is indeed canonical
    }

    // steps:

    // TODO: inputs/outputs verification

    // TODO: confirm transaction amounts

    // for each placeholder, for each input, sign if internal
    let mut partial_signatures: Vec<PartialSignature> = vec![];
    let psbt = PartiallySignedTransaction::deserialize(&req.psbt)
        .map_err(|_| AppError::new("Error deserializing psbt"))?;

    let mut sighash_cache = SighashCache::new(psbt.unsigned_tx.clone());

    let master_fingerprint = vanadium_sdk::crypto::get_master_fingerprint()?;

    for placeholder in wallet_policy.descriptor_template.placeholders() {
        // todo: check if key is internal
        // for now we just trust the fingerprint
        let key_info = wallet_policy.key_information[placeholder.key_index as usize].clone();
        if key_info
            .origin_info
            .as_ref()
            .map(|x| x.fingerprint == master_fingerprint)
            .unwrap_or(false)
        {
            let mut path = key_info.origin_info.unwrap().derivation_path;

            // todo: figure out if this input is change
            let is_change = false;
            let addr_index = 0;

            path.push(if !is_change {
                placeholder.num1
            } else {
                placeholder.num2
            });
            path.push(addr_index);

            for (input_index, input) in psbt.inputs.iter().enumerate() {
                if input.witness_utxo.is_none() {
                    // sign as legacy p2pkh or p2sh
                    let (sighash, sighash_type) = psbt
                        .sighash_ecdsa(input_index, &mut sighash_cache)
                        .map_err(|_| AppError::new("Error computing sighash"))?;

                    let privkey = EcfpPrivateKey::from_path(CxCurve::Secp256k1, &path)?;
                    let pubkey = privkey.pubkey()?;

                    let mut signature =
                        privkey.sign(CX_RND_RFC6979, CxMd::Sha256, sighash.as_ref())?;
                    signature.push(sighash_type.to_u32() as u8);

                    partial_signatures.push(PartialSignature {
                        signature: Cow::Owned(signature),
                        public_key: Cow::Owned(pubkey.to_compressed().to_vec()),
                        leaf_hash: Cow::Owned(vec![]),
                    });
                } else {
                    // sign all segwit types (including wrapped)
                    let script = if input.redeem_script.is_some() {
                        todo!()
                    } else {
                        todo!()
                    };
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

    #[test]
    fn test_sign_psbt() {
        let psbt_b64 = "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA";
        let psbt = general_purpose::STANDARD_NO_PAD.decode(psbt_b64).unwrap();

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
}
