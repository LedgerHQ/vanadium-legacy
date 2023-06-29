use crate::message::message::ResponseGetMasterFingerprint;

use error::*;

pub fn handle_get_master_fingerprint() -> Result<ResponseGetMasterFingerprint> {
    Ok(ResponseGetMasterFingerprint {
        fingerprint: vanadium_sdk::crypto::get_master_fingerprint()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_get_master_fingerprint() {
        let resp = handle_get_master_fingerprint().unwrap();

        assert_eq!(resp.fingerprint, 0xf5acc2fdu32);
    }
}
