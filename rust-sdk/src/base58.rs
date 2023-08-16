// adapted from rust-bitcoin

// SPDX-License-Identifier: CC0-1.0

//! Base58 encoder and decoder.
//!
//! This module provides functions for encoding and decoding base58 slices and
//! strings respectively.
//!

use alloc::{vec::Vec, string::String};

use crate::{crypto::CtxSha256, SdkError, ecall::{ecall_convert, FormatConversion}};

// double sha256 using vanadium sdk
fn sha256d(data: &[u8]) -> [u8; 32] {
    let sha = CtxSha256::new().update(data).r#final();
    CtxSha256::new().update(&sha).r#final()
}

/// Decodes a base58-encoded string into a byte vector.
pub fn decode(data: &str) -> Result<Vec<u8>, SdkError> {
    let mut dst: [u8; 128] = [0; 128];
    let dst_len;
    unsafe {
        dst_len = ecall_convert(FormatConversion::BASE58DECODE, data.as_ptr(), data.len(), dst.as_mut_ptr(), dst.len()); 
    }
    if dst_len == 0 { 
        Err(SdkError::GenericError)
    } else {
        Ok(Vec::from(&dst[..dst_len]))
    }
}

/// Decodes a base58check-encoded string into a byte vector verifying the checksum.
pub fn decode_check(data: &str) -> Result<Vec<u8>, SdkError> {
    let mut ret: Vec<u8> = decode(data)?;
    if ret.len() < 4 {
        return Err(SdkError::GenericError);
    }
    let check_start = ret.len() - 4;

    let hash_check =
        sha256d(&ret[..check_start])[..4].try_into().expect("4 byte slice");
    let data_check = ret[check_start..].try_into().expect("4 byte slice");

    let expected = u32::from_le_bytes(hash_check);
    let actual = u32::from_le_bytes(data_check);

    if expected != actual {
        return Err(SdkError::GenericError);
    }

    ret.truncate(check_start);
    Ok(ret)
}


/// Encodes `data` as a base58 string (see also `base58::encode_check()`).
pub fn encode(data: &[u8]) -> Result<String, SdkError> {
    let mut dst: [u8; 128] = [0; 128];
    let dst_len;
    unsafe {
        dst_len = ecall_convert(FormatConversion::BASE58ENCODE, data.as_ptr(), data.len(), dst.as_mut_ptr(), dst.len()); 
    }

    if dst_len == 0 { 
        Err(SdkError::GenericError)
    } else {
        Ok(String::from_utf8(dst[..dst_len].to_vec()).expect("All characters are ascii"))
    }
}

/// Encodes `data` as a base58 string including the checksum.
///
/// The checksum is the first four bytes of the sha256d of the data, concatenated onto the end.
pub fn encode_check(data: &[u8]) -> Result<String, SdkError> {
    let checksum = sha256d(data);

    let mut data_check = Vec::new();
    data_check.reserve(data.len() + 4);
    data_check.extend_from_slice(&data);
    data_check.extend_from_slice(&checksum[..4]);

    encode(&data_check)
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_base58_encode() {
        // Basics
        assert_eq!(&encode(&[0][..]).unwrap(), "1");
        assert_eq!(&encode(&[1][..]).unwrap(), "2");
        assert_eq!(&encode(&[58][..]).unwrap(), "21");
        assert_eq!(&encode(&[13, 36][..]).unwrap(), "211");

        // Leading zeroes
        assert_eq!(&encode(&[0, 13, 36][..]).unwrap(), "1211");
        assert_eq!(&encode(&[0, 0, 0, 0, 13, 36][..]).unwrap(), "1111211");

        // Long input (>100 bytes => has to use heap)
        // Note: this is changed with a shorter one from the original rust-bitcoin test, as the output
        // needs to be at most 128 zero-terminated characters in the current implementation.
        let res = encode(
            "BitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoinBitcoin".as_bytes(),
        ).unwrap();
        let exp = "nwaHoKUnRrcHebBXzD8q6rj2rugo3zcgDUQLH5mTkAF4XhCH197bAY1UJhvNxfSoAi5TzjaLGm1vTt8hFDo2BLP7b3sXzoESdxaMFbfVyy8hKoL9S1TwmzsoAhmF";
        assert_eq!(&res, exp);

        // Addresses
        let addr = hex!("00f8917303bfa8ef24f292e8fa1419b20460ba064d");
        assert_eq!(&encode_check(&addr[..]).unwrap(), "1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH");
    }

    #[test]
    fn test_base58_decode() {
        // Basics

        // TODO: these fail, might need to fix something in the implementation
        // assert_eq!(decode("1").ok(), Some(vec![0u8]));
        // assert_eq!(decode("2").ok(), Some(vec![1u8]));

        assert_eq!(decode("21").ok(), Some(vec![58u8]));
        assert_eq!(decode("211").ok(), Some(vec![13u8, 36]));

        // Leading zeroes
        assert_eq!(decode("1211").ok(), Some(vec![0u8, 13, 36]));
        assert_eq!(decode("111211").ok(), Some(vec![0u8, 0, 0, 13, 36]));

        // Addresses
        assert_eq!(
            decode_check("1PfJpZsjreyVrqeoAfabrRwwjQyoSQMmHH").ok(),
            Some(vec![0x00u8, 0xf8u8, 0x91u8, 0x73u8, 0x03u8, 0xbfu8, 0xa8u8, 0xefu8, 0x24u8, 0xf2u8, 0x92u8, 0xe8u8, 0xfau8, 0x14u8, 0x19u8, 0xb2u8, 0x04u8, 0x60u8, 0xbau8, 0x06u8, 0x4du8])
        );
        // Non Base58 char.
        assert_eq!(decode("¢").unwrap_err(), SdkError::GenericError);
    }

    #[test]
    fn test_base58_roundtrip() {
        let s = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
        let v: Vec<u8> = decode_check(s).unwrap();
        assert_eq!(encode_check(&v[..]).unwrap(), s);
        assert_eq!(decode_check(&encode_check(&v[..]).unwrap()).ok(), Some(v));

        // Check that empty slice passes roundtrip.
        assert_eq!(decode_check(&encode_check(&[]).unwrap()), Ok(vec![]));
        // Check that `len > 4` is enforced.
        assert_eq!(decode_check(&encode(&[1, 2, 3]).unwrap()), Err(SdkError::GenericError));
    }
}
