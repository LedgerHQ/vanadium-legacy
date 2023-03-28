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


pub fn get_key_fingerprint(key: &EcfpPublicKey) -> u32 {
    let compressed_pubkey = get_compressed_pubkey(key);

    let sha256 = CtxSha256::new().update(&compressed_pubkey).r#final();
    let rip = CtxRipeMd160::new().update(&sha256).r#final();

    BigEndian::read_u32(&rip)
}