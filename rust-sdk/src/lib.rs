#![cfg_attr(target_arch = "riscv32", no_main, no_std)]

#![allow(dead_code)] // XXX

extern crate alloc;

mod allocator;
pub mod base58;
pub mod crypto;
mod ecall;
pub mod glyphs;
pub mod segwit_addr;
pub mod ux;

pub mod secp256k1;

use alloc::vec::Vec;
use alloc::{fmt, vec};

use self::ecall::*;

#[global_allocator]
static ALLOCATOR: allocator::CAlloc = allocator::CAlloc;


#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SdkError {
    KeyGeneration,
    InvalidPublicKey,
    PathDerivation,
    Signature,
    SignatureVerification,
    GenericError,
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SdkError::KeyGeneration => write!(f, "key generation"),
            SdkError::InvalidPublicKey => write!(f, "invalid public key"),
            SdkError::PathDerivation => write!(f, "path derivation"),
            SdkError::Signature => write!(f, "signature"),
            SdkError::SignatureVerification => write!(f, "signature verification"),
            SdkError::GenericError => write!(f, "generic error"),
        }
    }
}

pub type Result<T> = core::result::Result<T, SdkError>;

pub fn fatal(msg: &str) {
    let buf = msg.as_bytes().to_vec();
    unsafe {
        ecall_fatal(buf.as_ptr(), msg.len());
    }
}

pub fn xrecv(size: usize) -> Vec<u8> {
    let mut buffer = vec![0; size];
    let recv_size = unsafe { ecall_xrecv(buffer.as_mut_ptr(), buffer.len()) };
    buffer[0..recv_size].to_vec()
}

pub fn xsend(buffer: &[u8]) {
    unsafe { ecall_xsend(buffer.as_ptr(), buffer.len() as usize) }
}
