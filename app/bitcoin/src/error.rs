use alloc::string::{String, ToString};
use alloc::{fmt, format};

use vanadium_sdk::{SdkError, secp256k1};

#[derive(Debug)]
pub struct AppError {
    details: String,
}

impl AppError {
    pub fn new(msg: &str) -> Self {
        Self {
            details: msg.to_string(),
        }
    }
}

impl From<&str> for AppError {
    fn from(err: &str) -> Self {
        AppError::new(&err.to_string())
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl From<quick_protobuf::Error> for AppError {
    fn from(err: quick_protobuf::Error) -> Self {
        AppError::new(&err.to_string())
    }
}

impl From<bitcoin::psbt::Error> for AppError {
    fn from(err: bitcoin::psbt::Error) -> Self {
        AppError::new(&err.to_string())
    }
}

impl From<bitcoin::bip32::Error> for AppError {
    fn from(err: bitcoin::bip32::Error) -> Self {
        AppError::new(&err.to_string())
    }
}

impl From<bitcoin::key::Error> for AppError {
    fn from(err: bitcoin::key::Error) -> Self {
        AppError::new(&err.to_string())
    }
}

impl From<bitcoin::secp256k1::Error> for AppError {
    fn from(err: bitcoin::secp256k1::Error) -> Self {
        AppError::new(&err.to_string())
    }
}

impl From<bitcoin::taproot::SigFromSliceError> for AppError {
    fn from(err: bitcoin::taproot::SigFromSliceError) -> Self {
        AppError::new(&err.to_string())
    }
}

impl From<SdkError> for AppError {
    fn from(err: SdkError) -> Self {
        AppError::new(&format!("sdk error: {}", err))
    }
}

pub type Result<T> = core::result::Result<T, AppError>;
