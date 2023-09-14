use vanadium_sdk::crypto::{EcfpPrivateKey, CtxSha256};

use crate::error::AppError;

pub const BIP0341_TAPTWEAK_TAG: [u8; 8] = [b'T', b'a', b'p', b'T', b'w', b'e', b'a', b'k'];
pub const BIP0341_TAPBRANCH_TAG: [u8; 9] = [b'T', b'a', b'p', b'B', b'r', b'a', b'n', b'c', b'h'];
pub const BIP0341_TAPLEAF_TAG: [u8; 7] = [b'T', b'a', b'p', b'L', b'e', b'a', b'f'];


fn new_tagged_hash(tag: &[u8]) -> CtxSha256 {    
    let hashtag = CtxSha256::new().update(tag).r#final();

    let mut hash_context = CtxSha256::new();

    hash_context.update(&hashtag);
    hash_context.update(&hashtag);

    hash_context
}

fn tagged_hash(tag: &[u8], data: &[u8], data2: Option<&[u8]>) -> [u8; 32] {
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

        let t = tagged_hash(&BIP0341_TAPTWEAK_TAG, &pk.as_bytes_xonly(), Some(h));
        self.add_tweak(&t)?;

        Ok(())
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