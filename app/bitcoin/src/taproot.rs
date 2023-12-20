use bitcoin::{VarInt, consensus::encode};
use vanadium_sdk::crypto::{EcfpPrivateKey, CtxSha256, EcfpPublicKey, secp256k1_point};

use crate::{error::AppError, wallet::{TapTree, script::{ToScriptWithKeyInfo, ScriptContext}, KeyInformation, DescriptorTemplate}};

pub const BIP0341_TAPTWEAK_TAG: &[u8; 8] = b"TapTweak";
pub const BIP0341_TAPBRANCH_TAG: &[u8; 9] = b"TapBranch";
pub const BIP0341_TAPLEAF_TAG: &[u8; 7] = b"TapLeaf";

fn new_tagged_hash(tag: &[u8]) -> CtxSha256 {    
    let hashtag = CtxSha256::new().update(tag).r#final();

    let mut hash_context = CtxSha256::new();

    hash_context.update(&hashtag);
    hash_context.update(&hashtag);

    hash_context
}

pub fn tagged_hash(tag: &[u8], data: &[u8], data2: Option<&[u8]>) -> [u8; 32] {
    let mut hash_context = new_tagged_hash(tag);
    let mut out: [u8; 32] = [0; 32];
    
    hash_context.update(data);

    if let Some(data2) = data2 {
        hash_context.update(data2);
    }

    out.copy_from_slice(&hash_context.r#final());

    out
}


pub trait TapTweak {
    fn taptweak(&mut self, h: &[u8]) -> Result<(), AppError>;
}

impl TapTweak for EcfpPrivateKey {
    fn taptweak(&mut self, h: &[u8]) -> Result<(), AppError> {
        let pk = self.secp256k1_point()?;

        let t = tagged_hash(BIP0341_TAPTWEAK_TAG, &pk.as_bytes_xonly(), Some(h));
        self.add_tweak(&t)?;

        Ok(())
    }
}

impl TapTweak for EcfpPublicKey {
    fn taptweak(&mut self, h: &[u8]) -> Result<(), AppError> {
        // TODO: should this fail if it has odd y? Or coerce to even y automatically?

        let t = tagged_hash(BIP0341_TAPTWEAK_TAG, &self.as_bytes_xonly(), Some(h));

        self.add_exp_tweak(&t)?;

        Ok(())
    }
}

pub trait GetTapTreeHash {
    fn get_taptree_hash(&self, key_information: &[KeyInformation], is_change: bool, address_index: u32) -> Result<[u8; 32], AppError>;
}

impl GetTapTreeHash for TapTree {
    fn get_taptree_hash(&self, key_information: &[KeyInformation], is_change: bool, address_index: u32) -> Result<[u8; 32], AppError> {
        match self {
            TapTree::Script(leaf_desc) => leaf_desc.get_tapleaf_hash(key_information, is_change, address_index),
            TapTree::Branch(l, r) => {
                let hash_left = l.get_taptree_hash(key_information, is_change, address_index)?;
                let hash_right = r.get_taptree_hash(key_information, is_change, address_index)?;
                if hash_left <= hash_right {
                    Ok(tagged_hash(BIP0341_TAPBRANCH_TAG, &hash_left, Some(&hash_right)))
                } else {
                    Ok(tagged_hash(BIP0341_TAPBRANCH_TAG, &hash_right, Some(&hash_left)))
                }
            },
        }
    }
}

pub trait GetTapLeafHash {
    fn get_tapleaf_hash(&self, key_information: &[KeyInformation], is_change: bool, address_index: u32) -> Result<[u8; 32], AppError>;
}

impl GetTapLeafHash for DescriptorTemplate {
    fn get_tapleaf_hash(&self, key_information: &[KeyInformation], is_change: bool, address_index: u32) -> Result<[u8; 32], AppError> {
        let mut ctx = new_tagged_hash(BIP0341_TAPLEAF_TAG);
        ctx.update(&[0xC0u8]); // leaf version
        let leaf_script = self.to_script(key_information, is_change, address_index, ScriptContext::Tr)?;
        ctx.update(&encode::serialize(&VarInt(leaf_script.len() as u64)));
        ctx.update(&leaf_script.to_bytes());
        Ok(ctx.r#final())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use vanadium_sdk::crypto::CxCurve;

    #[test]
    fn test_seckey_taptweak() {
        let key_raw = hex!("109564EB7DEDAB87624BF52CBEBC47BB336B083D13822A6FEA768ADB076EE973");
        let mut privkey = EcfpPrivateKey::new(CxCurve::Secp256k1, &key_raw);
        privkey.taptweak(&[]).unwrap();

        let key_tweaked = hex!("8144C2892D079BC380AAD02201F81A3D51BE9D40B5A308A7C34204CDE2A3127D");
        let privkey_expected = EcfpPrivateKey::new(CxCurve::Secp256k1, &key_tweaked);

        assert_eq!(privkey, privkey_expected)
    }

}