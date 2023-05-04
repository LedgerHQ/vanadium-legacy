extern crate bitcoin;

use vanadium_sdk::crypto::{EcfpPublicKey, CtxSha256, CtxRipeMd160};

use byteorder::{BigEndian, ByteOrder};


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


pub fn sha256(data: &[u8]) -> [u8; 32] {
    CtxSha256::new().update(&data).r#final()
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    CtxRipeMd160::new().update(&data).r#final()
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(&data))
}

pub fn hash256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(&data))
}

pub fn get_key_fingerprint(key: &EcfpPublicKey) -> u32 {
    let compressed_pubkey = get_compressed_pubkey(key);

    let rip = hash160(&compressed_pubkey);

    BigEndian::read_u32(&rip)
}


#[cfg(test)]
mod tests {
    use super::*;

    use vanadium_sdk::crypto::{CxCurve};
    use hex_literal::hex;

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
    fn test_hash160() {
        let input: [u8; 65] = [
            0x04, 0xa1, 0x49, 0xd7, 0x6c, 0x5d, 0xe2, 0x7a, 0x2d,
            0xdb, 0xfa, 0xa1, 0x24, 0x6c, 0x4a, 0xdc, 0xd2, 0xb6,
            0xf7, 0xaa, 0x29, 0x54, 0xc2, 0xe2, 0x53, 0x03, 0xf5,
            0x51, 0x54, 0xca, 0xad, 0x91, 0x52, 0xe4, 0xf7, 0xe4,
            0xb8, 0x5d, 0xf1, 0x69, 0xc1, 0x8a, 0x3c, 0x69, 0x7f,
            0xbb, 0x2d, 0xc4, 0xec, 0xef, 0x94, 0xac, 0x55, 0xfe,
            0x81, 0x64, 0xcc, 0xf9, 0x82, 0xa1, 0x38, 0x69, 0x1a,
            0x55, 0x19,
        ];
        let output: [u8; 20] =  [
            0xda, 0x0b, 0x34, 0x52, 0xb0, 0x6f, 0xe3, 0x41,
            0x62, 0x6a, 0xd0, 0x94, 0x9c, 0x18, 0x3f, 0xbd,
            0xa5, 0x67, 0x68, 0x26,
        ];

        assert_eq!(
            hash160(&input),
            output
        );
    }

    // TODO: add test for other hash functions

    #[test]
    fn test_get_key_fingerprint() {
        let key = EcfpPublicKey::new(CxCurve::Secp256k1, &hex!("0452972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab288742f4dc97d9edb6fd946babc002fdfb06f26caf117b9405ed79275763fdb1c"));
    
        assert_eq!(
            get_key_fingerprint(&key),
            0x40cbbf6fu32
        );
    }
}
