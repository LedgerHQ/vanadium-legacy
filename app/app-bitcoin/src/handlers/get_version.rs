use alloc::borrow::Cow;

use crate::message::message::ResponseGetVersion;

use error::*;

pub fn handle_get_version<'a>() -> Result<ResponseGetVersion<'a>> {
    Ok(ResponseGetVersion {
        version: Cow::Borrowed("0.0.1"),
    })
}
