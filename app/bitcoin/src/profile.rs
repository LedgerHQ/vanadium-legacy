use alloc::borrow::Cow;

use alloc::vec;
use quick_protobuf::{BytesReader, BytesWriter, MessageRead, MessageWrite, Writer};

use vanadium_sdk;

use message::message::mod_Request::OneOfrequest;
use message::message::mod_Response::OneOfresponse;
use message::message::*;

pub fn profile_checkpoint(file: &str, line: u32, message: Option<&str>) -> () {
    let resp = Response {
        response: OneOfresponse::profiling_event(ResponseProfilingEvent {
            file: Cow::Borrowed(file),
            line,
            message: Cow::Borrowed(message.unwrap_or_default())
        })
    };

    let mut out = vec![0; resp.get_size()];
    let mut writer = Writer::new(BytesWriter::new(&mut out));
    resp.write_message(&mut writer).unwrap();

    vanadium_sdk::xsend(&out);

    let buffer = vanadium_sdk::xrecv(256);

    let pb_bytes = buffer.to_vec();
    let mut reader = BytesReader::from_bytes(&pb_bytes);
    let request: Request = Request::from_reader(&mut reader, &pb_bytes).unwrap(); // TODO

    match request.request {
        OneOfrequest::continue_interrupted(_) => (),
        _ => panic!("Invalid request, expected: continue_interrupted") // TODO: proper error handling
    }
}
