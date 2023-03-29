use crate::message::message::ResponseGetMasterFingerprint;

use error::*;

pub fn handle_get_master_fingerprint() -> Result<ResponseGetMasterFingerprint> {
    Ok(ResponseGetMasterFingerprint {
        fingerprint: vanadium_sdk::crypto::get_master_fingerprint()?,
    })
}
