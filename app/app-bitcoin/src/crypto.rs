extern crate bitcoin;

use vanadium_sdk::crypto::{EcfpPublicKey, CtxSha256, CtxRipeMd160, CxCurve};

use byteorder::{BigEndian, ByteOrder};

#[cfg(test)]
use hex_literal::hex;


pub fn get_checksum(data: &[u8]) -> u32 {
    let sha256 = CtxSha256::new().update(&data).r#final();
    let sha256d = CtxSha256::new().update(&sha256).r#final();

    BigEndian::read_u32(&sha256d)
}

pub fn get_compressed_pubkey(key: &EcfpPublicKey) -> [u8; 33] {
    let w = *key.as_bytes();

    let mut compressed_pubkey = [0; 33];

    // Set the first byte based on parity of the Y-coordinate
    compressed_pubkey[0] = if (w[64] as u8) & 1 == 1 {
        b'\x03'
    } else {
        b'\x02'
    };

    // Clone the X-coordinate from w
    compressed_pubkey[1..].clone_from_slice(&w[1..33]);

    compressed_pubkey
}


pub fn get_key_fingerprint(key: &EcfpPublicKey) -> u32 {
    let compressed_pubkey = get_compressed_pubkey(key);

    let sha256 = CtxSha256::new().update(&compressed_pubkey).r#final();
    let rip = CtxRipeMd160::new().update(&sha256).r#final();

    BigEndian::read_u32(&rip)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_checksum() {
        assert_eq!(
            get_checksum(&hex!(
                "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
            )),
            0xab473b21
        );
    }
    
    
    #[test]
    fn test_get_compressed_pubkey() {
        let key_even_y = EcfpPublicKey::new(CxCurve::Secp256k1, &hex!("0452972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab288742f4dc97d9edb6fd946babc002fdfb06f26caf117b9405ed79275763fdb1c"));
    
        assert_eq!(
            get_compressed_pubkey(&key_even_y),
            hex!("0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2")
        );
    
        let key_odd_y = EcfpPublicKey::new(CxCurve::Secp256k1, &hex!("0418ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f504c220d01e1ca419cb1ba4b3393b615e99dd20aa6bf071078f70fd949008e7411"));
        assert_eq!(
            get_compressed_pubkey(&key_odd_y),
            hex!("0318ed2e1ec629e2d3dae7be1103d4f911c24e0c80e70038f5eb5548245c475f50")
        );
    }
    
    
    #[test]
    fn test_get_key_fingerprint() {
        let key = EcfpPublicKey::new(CxCurve::Secp256k1, &hex!("0452972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab288742f4dc97d9edb6fd946babc002fdfb06f26caf117b9405ed79275763fdb1c"));
    
        assert_eq!(
            get_key_fingerprint(&key),
            0x40cbbf6fu32
        );
    }
}
