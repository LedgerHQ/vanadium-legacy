// Automatically generated rust module for 'message.proto' file

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![cfg_attr(rustfmt, rustfmt_skip)]


use alloc::vec::Vec;
use alloc::borrow::Cow;
use quick_protobuf::{MessageInfo, MessageRead, MessageWrite, BytesReader, Writer, WriterBackend, Result};
use quick_protobuf::sizeofs::*;
use super::*;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct RequestGetVersion { }

impl<'a> MessageRead<'a> for RequestGetVersion {
    fn from_reader(r: &mut BytesReader, _: &[u8]) -> Result<Self> {
        r.read_to_end();
        Ok(Self::default())
    }
}

impl MessageWrite for RequestGetVersion { }

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseGetVersion<'a> {
    pub version: Cow<'a, str>,
}

impl<'a> MessageRead<'a> for ResponseGetVersion<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.version = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for ResponseGetVersion<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.version == "" { 0 } else { 1 + sizeof_len((&self.version).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.version != "" { w.write_with_tag(10, |w| w.write_string(&**&self.version))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct RequestGetMasterFingerprint { }

impl<'a> MessageRead<'a> for RequestGetMasterFingerprint {
    fn from_reader(r: &mut BytesReader, _: &[u8]) -> Result<Self> {
        r.read_to_end();
        Ok(Self::default())
    }
}

impl MessageWrite for RequestGetMasterFingerprint { }

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseGetMasterFingerprint {
    pub fingerprint: u32,
}

impl<'a> MessageRead<'a> for ResponseGetMasterFingerprint {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.fingerprint = r.read_uint32(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for ResponseGetMasterFingerprint {
    fn get_size(&self) -> usize {
        0
        + if self.fingerprint == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.fingerprint) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.fingerprint != 0u32 { w.write_with_tag(8, |w| w.write_uint32(*&self.fingerprint))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseError<'a> {
    pub error_msg: Cow<'a, str>,
}

impl<'a> MessageRead<'a> for ResponseError<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.error_msg = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for ResponseError<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.error_msg == "" { 0 } else { 1 + sizeof_len((&self.error_msg).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.error_msg != "" { w.write_with_tag(10, |w| w.write_string(&**&self.error_msg))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Request {
    pub request: mod_Request::OneOfrequest,
}

impl<'a> MessageRead<'a> for Request {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.request = mod_Request::OneOfrequest::get_version(r.read_message::<RequestGetVersion>(bytes)?),
                Ok(18) => msg.request = mod_Request::OneOfrequest::get_master_fingerprint(r.read_message::<RequestGetMasterFingerprint>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Request {
    fn get_size(&self) -> usize {
        0
        + match self.request {
            mod_Request::OneOfrequest::get_version(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Request::OneOfrequest::get_master_fingerprint(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Request::OneOfrequest::None => 0,
    }    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        match self.request {            mod_Request::OneOfrequest::get_version(ref m) => { w.write_with_tag(10, |w| w.write_message(m))? },
            mod_Request::OneOfrequest::get_master_fingerprint(ref m) => { w.write_with_tag(18, |w| w.write_message(m))? },
            mod_Request::OneOfrequest::None => {},
    }        Ok(())
    }
}

pub mod mod_Request {

use alloc::vec::Vec;
use super::*;

#[derive(Debug, PartialEq, Clone)]
pub enum OneOfrequest {
    get_version(RequestGetVersion),
    get_master_fingerprint(RequestGetMasterFingerprint),
    None,
}

impl Default for OneOfrequest {
    fn default() -> Self {
        OneOfrequest::None
    }
}

}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Response<'a> {
    pub response: mod_Response::OneOfresponse<'a>,
}

impl<'a> MessageRead<'a> for Response<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.response = mod_Response::OneOfresponse::get_version(r.read_message::<ResponseGetVersion>(bytes)?),
                Ok(18) => msg.response = mod_Response::OneOfresponse::get_master_fingerprint(r.read_message::<ResponseGetMasterFingerprint>(bytes)?),
                Ok(26) => msg.response = mod_Response::OneOfresponse::error(r.read_message::<ResponseError>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for Response<'a> {
    fn get_size(&self) -> usize {
        0
        + match self.response {
            mod_Response::OneOfresponse::get_version(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::get_master_fingerprint(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::error(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::None => 0,
    }    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        match self.response {            mod_Response::OneOfresponse::get_version(ref m) => { w.write_with_tag(10, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::get_master_fingerprint(ref m) => { w.write_with_tag(18, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::error(ref m) => { w.write_with_tag(26, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::None => {},
    }        Ok(())
    }
}

pub mod mod_Response {

use alloc::vec::Vec;
use super::*;

#[derive(Debug, PartialEq, Clone)]
pub enum OneOfresponse<'a> {
    get_version(ResponseGetVersion<'a>),
    get_master_fingerprint(ResponseGetMasterFingerprint),
    error(ResponseError<'a>),
    None,
}

impl<'a> Default for OneOfresponse<'a> {
    fn default() -> Self {
        OneOfresponse::None
    }
}

}

