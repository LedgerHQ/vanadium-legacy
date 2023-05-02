use core::str::FromStr;

use alloc::{boxed::Box, vec};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{ScriptBuf, PubkeyHash};
use bitcoin::bip32::{ExtendedPubKey, ChildNumber};

use crate::crypto::hash160;

use super::wallet::{WalletPolicy, DescriptorTemplate, KeyPlaceholder, KeyInformation};


pub trait ToScript {
    fn to_script(
        &self,
        is_change: bool,
        address_index: u32,
    ) -> Result<Box<ScriptBuf>, &'static str>;
}


pub trait ToScriptWithKeyInfo {
    fn to_script(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<Box<ScriptBuf>, &'static str>;
}


impl ToScriptWithKeyInfo for DescriptorTemplate {
    fn to_script(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<Box<ScriptBuf>, &'static str> {
        let secp = Secp256k1::new();

        let derive = |kp: &KeyPlaceholder| -> Result<ExtendedPubKey, &'static str> {
            let change_step = if is_change { kp.num2 } else { kp.num1 };

            let key_info = key_information
                .get(kp.key_index as usize)
                .ok_or("Invalid key index")?;

            let root_pubkey = ExtendedPubKey::from_str(&key_info.pubkey).map_err(|_| "Invalid pubkey")?;

            let change_step = ChildNumber::from_normal_idx(change_step).map_err(|_| "Invalid change derivation step")?;
            let addr_index_step = ChildNumber::from_normal_idx(address_index).map_err(|_| "Invalid address index derivation step")?;

            root_pubkey
                .derive_pub(&secp, &vec![change_step, addr_index_step])
                .map_err(|_| "Failed to produce derived key")
        };
        
        let result: ScriptBuf = match self {
            DescriptorTemplate::Sh(_) => todo!(),
            DescriptorTemplate::Wsh(_) => todo!(),
            DescriptorTemplate::Pkh(kp) => {
                let pubkey = derive(kp)?.to_pub().to_bytes();
                let pubkey_hash = PubkeyHash::from_byte_array(hash160(&pubkey));
                ScriptBuf::new_p2pkh(&pubkey_hash)
            },
            DescriptorTemplate::Wpkh(_) => todo!(),
            DescriptorTemplate::Sortedmulti(_, _) => todo!(),
            DescriptorTemplate::Sortedmulti_a(_, _) => todo!(),
            DescriptorTemplate::Tr(_, _) => todo!(),
            DescriptorTemplate::Zero => todo!(),
            DescriptorTemplate::One => todo!(),
            DescriptorTemplate::Pk_k(_) => todo!(),
            DescriptorTemplate::Pk_h(_) => todo!(),
            DescriptorTemplate::Older(_) => todo!(),
            DescriptorTemplate::After(_) => todo!(),
            DescriptorTemplate::Sha256(_) => todo!(),
            DescriptorTemplate::Ripemd160(_) => todo!(),
            DescriptorTemplate::Hash256(_) => todo!(),
            DescriptorTemplate::Hash160(_) => todo!(),
            DescriptorTemplate::Andor(_, _, _) => todo!(),
            DescriptorTemplate::And_v(_, _) => todo!(),
            DescriptorTemplate::And_b(_, _) => todo!(),
            DescriptorTemplate::Or_b(_, _) => todo!(),
            DescriptorTemplate::Or_c(_, _) => todo!(),
            DescriptorTemplate::Or_d(_, _) => todo!(),
            DescriptorTemplate::Or_i(_, _) => todo!(),
            DescriptorTemplate::Thresh(_, _) => todo!(),
            DescriptorTemplate::Multi(_, _) => todo!(),
            DescriptorTemplate::Multi_a(_, _) => todo!(),
        };

        Ok(Box::new(result))
    }
}


impl ToScript for WalletPolicy {
    fn to_script(
        &self,
        is_change: bool,
        address_index: u32,
    ) -> Result<Box<ScriptBuf>, &'static str> {
        self.descriptor_template.to_script(&self.key_information, is_change, address_index)
    }
}
