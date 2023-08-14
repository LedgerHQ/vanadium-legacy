// encoder for segwit addresses

use alloc::string::String;

use crate::{SdkError, ecall::{ecall_convert, FormatConversion}};

/// Decodes a base58-encoded string into a byte vector.
pub fn segwit_addr_encode(script_pub_key: &[u8]) -> Result<String, SdkError> {
    let mut dst: [u8; 76] = [0; 76]; // segwit addresses are at most 74 bytes long
    let dst_len;
    unsafe {
        // TODO: support mainnet
        dst_len = ecall_convert(FormatConversion::SEGWITADDRTESTNET, script_pub_key.as_ptr(), script_pub_key.len(), dst.as_mut_ptr(), dst.len()); 
    }
    if dst_len == 0 { 
        Err(SdkError::GenericError)
    } else {
        Ok(String::from_utf8(dst[..dst_len].to_vec()).expect("All characters are ascii"))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_segwit_addr_encode() {
        assert_eq!(
            segwit_addr_encode(&hex!("0014820d4a343a44e915c36494995c2899abe3741893")).unwrap(),
            String::from("tb1qsgx55dp6gn53tsmyjjv4c2ye403hgxynxs0dnm"),
        );

        assert_eq!(
            segwit_addr_encode(&hex!("002028294e1a4ef2f350ad2dea4e82abaca6292258c54aa0a8bb1e06d2bbaf8e14ac")).unwrap(),
            String::from("tb1q9q55uxjw7te4ptfdaf8g92av5c5jykx9f2s23wc7qmfthtuwzjkq3s6rhs"),
        );

        assert_eq!(
            segwit_addr_encode(&hex!("51202ca4329c0db76deafb627bcb6dad72b1e0adc50e291dc46f59a0cc66b77b9be5")).unwrap(),
            String::from("tb1p9jjr98qdkak747mz009kmttjk8s2m3gw9ywugm6e5rxxddmmn0jswycj3r"),
        );
    }
}
