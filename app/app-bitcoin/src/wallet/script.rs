use core::convert::TryInto;
use core::str::FromStr;

use alloc::{boxed::Box, vec, vec::Vec};


use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::*;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{ScriptBuf, PubkeyHash, WPubkeyHash, ScriptHash, WScriptHash, PublicKey, Script};
use bitcoin::bip32::{ExtendedPubKey, ChildNumber};

use crate::crypto::{hash160, sha256};

use super::wallet::{WalletPolicy, DescriptorTemplate, KeyPlaceholder, KeyInformation};

const MAX_PUBKEYS_PER_MULTISIG: u8 = 16;

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


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ScriptContextType { None, Wsh, Tr }

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct ScriptContext {
    context_type: ScriptContextType,
    v: bool,
}

impl ScriptContext {
    fn new() -> ScriptContext {
        ScriptContext {
            context_type: ScriptContextType::None,
            v: false,
        }
    }
    fn with_v(&self) -> ScriptContext {
        ScriptContext {
            context_type: self.context_type,
            v: true,
        }
    }
}

trait ToScriptWithKeyInfoInner {
    fn to_script_inner(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext
    ) -> Result<Box<ScriptBuf>, &'static str>;
}


impl ToScriptWithKeyInfoInner for DescriptorTemplate {
    fn to_script_inner(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext
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
            DescriptorTemplate::Sh(inner) => {
                let inner_script = inner.to_script(key_information, is_change, address_index)?;
                let script_hash = ScriptHash::from_byte_array(hash160(&inner_script.as_bytes()));
                ScriptBuf::new_p2sh(&script_hash)
            },
            DescriptorTemplate::Wsh(inner) => {
                let inner_script = inner.to_script(key_information, is_change, address_index)?;
                let script_hash = WScriptHash::from_byte_array(sha256(&inner_script.as_bytes()));
                ScriptBuf::new_v0_p2wsh(&script_hash)
            },
            DescriptorTemplate::Pkh(kp) => {
                let pubkey = derive(kp)?.to_pub();
                let pubkey_hash = PubkeyHash::from_byte_array(hash160(&pubkey.to_bytes()));
                ScriptBuf::new_p2pkh(&pubkey_hash)
            },
            DescriptorTemplate::Wpkh(kp) => {
                let pubkey = derive(kp)?.to_pub();
                let pubkey_hash = WPubkeyHash::from_byte_array(hash160(&pubkey.to_bytes()));
                ScriptBuf::new_v0_p2wpkh(&pubkey_hash)
            },
            DescriptorTemplate::Sortedmulti(k, kps) => {
                if ctx.context_type == ScriptContextType::Tr {
                    return Err("sortedmulti is not valid on taproot");
                }

                let mut res = ScriptBuf::new();

                if kps.len() > (MAX_PUBKEYS_PER_MULTISIG as usize) {
                    return Err("Too many keys for multisig")
                }
                if *k == 0 || (*k as usize) > kps.len() {
                    return Err("Invalig multisig quorum")
                }

                res.push_opcode(((*k as u8) + 0x50u8).into()); // TODO: check if correct

                let mut keys = kps
                    .iter()
                    .map(|kp| derive(kp))
                    .map(|derived_key_result| {
                        derived_key_result.map(|extended_pub_key| extended_pub_key.to_pub())
                    })
                    .collect::<Result<Vec<PublicKey>, &'static str>>()?;

                keys.sort();

                for key in keys {
                    let key_arr: [u8; 33] = key.to_bytes().as_slice().try_into().map_err(|_| "Wrong key length")?;
                    res.push_slice(&key_arr);
                }

                res.push_opcode(((kps.len() as u8) + 0x50u8).into()); // TODO: check if correct

                res.push_opcode(OP_CHECKMULTISIG); // TODO: handle :v case

                res
            },
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

impl ToScriptWithKeyInfo for DescriptorTemplate {
    fn to_script(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<Box<ScriptBuf>, &'static str> {
        self.to_script_inner(key_information, is_change, address_index, ScriptContext::new())
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
