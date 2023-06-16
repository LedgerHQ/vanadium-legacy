#![feature(start)]
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;
extern crate bitcoin;
extern crate byteorder;
extern crate hex;
extern crate hex_literal;
extern crate nom;
extern crate quick_protobuf;
extern crate subtle;
extern crate vanadium_sdk;

#[cfg(not(target_arch = "riscv32"))]
extern crate core;

mod crypto;
mod error;
mod handlers;
mod message;
mod ui;
mod version;
mod wallet;

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use quick_protobuf::{BytesReader, BytesWriter, MessageRead, MessageWrite, Writer};

use error::*;
use message::message::mod_Request::OneOfrequest;
use message::message::mod_Response::OneOfresponse;
use message::message::*;

#[cfg(target_arch = "riscv32")]
use vanadium_sdk::fatal;

use handlers::*;

fn set_error(msg: &'_ str) -> ResponseError {
    ResponseError {
        error_msg: Cow::Borrowed(msg),
    }
}

impl From<&'static str> for ResponseError<'_> {
    fn from(msg: &'static str) -> Self {
        ResponseError {
            error_msg: Cow::Borrowed(msg),
        }
    }
}

fn handle_req_(buffer: &[u8]) -> Result<Response> {
    let pb_bytes = buffer.to_vec();
    let mut reader = BytesReader::from_bytes(&pb_bytes);
    let request: Request = Request::from_reader(&mut reader, &pb_bytes)?;

    let response = Response {
        response: match request.request {
            OneOfrequest::get_version(_) => OneOfresponse::get_version(handle_get_version()?),
            OneOfrequest::get_master_fingerprint(_) => {
                OneOfresponse::get_master_fingerprint(handle_get_master_fingerprint()?)
            }
            OneOfrequest::get_extended_pubkey(req) => {
                OneOfresponse::get_extended_pubkey(handle_get_extended_pubkey(req)?)
            }
            OneOfrequest::register_wallet(req) => {
                OneOfresponse::register_wallet(handle_register_wallet(req)?)
            }
            OneOfrequest::get_wallet_address(req) => {
                OneOfresponse::get_wallet_address(handle_get_wallet_address(req)?)
            }
            OneOfrequest::sign_psbt(req) => OneOfresponse::sign_psbt(handle_sign_psbt(req)?),
            OneOfrequest::None => OneOfresponse::error("request unset".into()),
        },
    };

    Ok(response)
}

fn handle_req(buffer: &[u8]) -> Vec<u8> {
    let error_msg: String;

    let response = match handle_req_(buffer) {
        Ok(response) => response,
        Err(error) => {
            error_msg = error.to_string();
            Response {
                response: OneOfresponse::error(set_error(&error_msg)),
            }
        }
    };

    let mut out = vec![0; response.get_size()];
    let mut writer = Writer::new(BytesWriter::new(&mut out));
    response.write_message(&mut writer).unwrap();

    out.to_vec()
}

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn my_panic(_info: &core::panic::PanicInfo) -> ! {
    fatal("panic");
    loop {}
}

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub fn atexit(_f: *const u8) {
    /* required by libcrypto */
    fatal("atexit");
    panic!("atexit called");
}

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub fn _start(_argc: isize, _argv: *const *const u8) -> isize {
    main(_argc, _argv)
}

#[start]
pub fn main(_: isize, _: *const *const u8) -> isize {
    version::setup_app();

    vanadium_sdk::ux::ux_idle();
    loop {
        // TODO: xrecv currently allocates up to the specified size; we would like to adjust dynamically
        let buffer = vanadium_sdk::xrecv(2048);

        vanadium_sdk::ux::app_loading_start("Handling request...\x00");

        let result = handle_req(&buffer);

        vanadium_sdk::ux::app_loading_stop();
        vanadium_sdk::ux::ux_idle();

        vanadium_sdk::xsend(&result);
    }
}
