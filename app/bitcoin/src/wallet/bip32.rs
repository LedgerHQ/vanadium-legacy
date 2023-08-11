
use alloc::vec::Vec;
use core::fmt;
use core::{convert::TryInto, ptr};
use core::str::FromStr;

use vanadium_sdk::crypto::{EcfpPublicKey, CxCurve};

use crate::crypto::hash160;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct ExtendedPubKey {
    pub network: u32,
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub public_key: EcfpPublicKey,
    pub chain_code: [u8; 32],
}

impl ExtendedPubKey {
    pub fn fingerprint(&self) -> [u8; 4] {
        hash160(&self.public_key.to_compressed())[0..4].try_into().expect("Cannot fail")
    }

    pub fn ckd_pub(&self, i: u32) -> Result<ExtendedPubKey, Error> {
        if i >= 0x80000000u32 {
            return Err(Error::InvalidChildNumber(i));
        }

        let mut hmac_data: Vec<u8> = Vec::new();
        hmac_data.extend_from_slice(&self.public_key.to_compressed()[..]);
        hmac_data.extend_from_slice(&i.to_be_bytes());

        let hmac_result: [u8; 64] = vanadium_sdk::crypto::hmac_sha512(&self.chain_code[..], &hmac_data);

        let sk: [u8; 32] = hmac_result[0..32].try_into().expect("Cannot fail");
        let chain_code: [u8; 32] = hmac_result[32..].try_into().expect("Cannot fail");

        let mut pk_uncompressed = self.public_key.as_bytes().clone();
        if vanadium_sdk::secp256k1::secp256k1_ec_pubkey_tweak_add(
            ptr::null(),
            &mut pk_uncompressed,
            sk.as_ptr(),
        ) == 1
        {
            Ok(ExtendedPubKey {
                network: self.network,
                depth: self.depth + 1,
                parent_fingerprint: self.fingerprint(),
                child_number: i,
                public_key: EcfpPublicKey::new(CxCurve::Secp256k1, &pk_uncompressed),
                chain_code,
            })    
        } else {
            Err(Error::InvalidTweak)
        }
    }

    pub fn derive_pub(&self, path: &[u32]) -> Result<ExtendedPubKey, Error> {
        let mut pk: ExtendedPubKey = *self;
        for cnum in path {
            pk = pk.ckd_pub(*cnum)?
        }
        Ok(pk)
    }

    // adapted from rust-bitcoin
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&self.network.to_be_bytes());
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.to_compressed()[..]);
        ret
    }

    /// Decoding extended private key from binary data according to BIP 32
    // adapted from rust-bitcoin
    pub fn decode(data: &[u8]) -> Result<ExtendedPubKey, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        Ok(ExtendedPubKey {
            network: u32::from_be_bytes(data[0..4].try_into().expect("Cannot fail")),
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            public_key: EcfpPublicKey::from_slice(&data[45..78])
                .map_err(|_| Error::InvalidPubkey)?,
        })
    }
}

impl fmt::Display for ExtendedPubKey {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        bitcoin::base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for ExtendedPubKey {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ExtendedPubKey, Error> {
        let data = bitcoin::base58::decode_check(inp)
            .map_err(|_| Error::Base58Error)?;

        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        ExtendedPubKey::decode(&data)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    Base58Error,
    InvalidChildNumber(u32),
    InvalidPubkey,
    InvalidTweak,
    WrongExtendedKeyLength(usize),
}


// TODO: add more tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip32_pubkey_derivation() {
        let tpub = "tpubDAenfwNu5GyCJWv8oqRAckdKMSUoZjgVF5p8WvQwHQeXjDhAHmGrPa4a4y2Fn7HF2nfCLefJanHV3ny1UY25MRVogizB2zRUdAo7Tr9XAjm";
        let tpub_child42 = "tpubDDncfYBHLyEZu5Ttd6Far87HH7gZZvzZ2pCu2qmhfM4iuZ4zJcLqvHK6A4A1oPq7fFVjkqJBmDm6EzhQRwc19qr4at2FozTRnYi7rU6TAGt";
 
        let pk = ExtendedPubKey::from_str(tpub).unwrap();
        let pk_child42 = pk.derive_pub(&vec![42]).unwrap();

        assert_eq!(pk_child42.to_string(), tpub_child42);
    }
}
