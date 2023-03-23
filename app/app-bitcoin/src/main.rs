#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;
extern crate bitcoin;
extern crate quick_protobuf;
extern crate vanadium_sdk;


#[cfg(not(target_arch = "riscv32"))]
extern crate core;

mod error;
mod message;
mod ui;
mod version;

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use quick_protobuf::{BytesReader, BytesWriter, MessageRead, MessageWrite, Writer};

use error::*;
use message::message::mod_Request::OneOfrequest;
use message::message::mod_Response::OneOfresponse;
use message::message::*;

use vanadium_sdk::fatal;

fn handle_get_version<'a>() -> Result<ResponseGetVersion<'a>> {
    Ok(ResponseGetVersion {
        version: Cow::Borrowed("0.0.1"),
    })
}

fn handle_get_master_fingerprint() -> Result<ResponseGetMasterFingerprint> {
    Ok(ResponseGetMasterFingerprint {
        fingerprint: vanadium_sdk::crypto::get_master_fingerprint()?,
    })
}

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
            OneOfrequest::get_master_fingerprint(_) => OneOfresponse::get_master_fingerprint(handle_get_master_fingerprint()?),
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
    main();
    0
}


#[no_mangle]
pub extern "C" fn main() {
    version::setup_app();

    vanadium_sdk::ux::ux_idle();
    loop {
        let buffer = vanadium_sdk::xrecv(512);

        vanadium_sdk::ux::app_loading_start("Handling request...\x00");

        let result = handle_req(&buffer);

        vanadium_sdk::ux::app_loading_stop();
        vanadium_sdk::ux::ux_idle();

        vanadium_sdk::xsend(&result);
    }
}
