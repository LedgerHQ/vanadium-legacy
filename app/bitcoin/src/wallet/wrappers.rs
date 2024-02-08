use digest::{crypto_common::BlockSizeUser, typenum::{U32, U64}, FixedOutput, OutputSizeUser, Update, HashMarker};
use vanadium_sdk::crypto::CtxSha256;

// wrapper to CtxSha256 to implement external traits that it's not possible to implement for CtxSha256
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct MySha256(CtxSha256);

impl Default for MySha256 {
    fn default() -> Self {
        Self(CtxSha256::new())
    }
}

impl BlockSizeUser for MySha256 {
    type BlockSize = U64;
}

impl OutputSizeUser for MySha256 {
    type OutputSize = U32;
}

impl Update for MySha256 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl FixedOutput for MySha256 {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let mut copy = self;
        let result = copy.0.r#final();
        out.copy_from_slice(&result);
    }
}

impl HashMarker for MySha256 {}
