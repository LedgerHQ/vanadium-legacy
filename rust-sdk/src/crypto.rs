use alloc::vec::Vec;

use crate::{
    ecall::{
        ecall_cx_ecfp_generate_pair, ecall_derive_node_bip32, ecall_ecdsa_sign, ecall_ecdsa_verify,
        ecall_get_master_fingerprint, ecall_get_random_bytes, ecall_hash_final,
    },
    ecall_hash_update, fatal, SdkError,
};

#[repr(C)]
pub struct CtxSha256 {
    initialized: bool,
    counter: u32,
    blen: usize,
    block: [u8; 64],
    acc: [u8; 8 * 4],
}

#[repr(C)]
pub struct CtxSha3 {
    initialized: bool,
    counter: u32,
    blen: usize,
    block: [u8; 200],
    acc: [u64; 25],
}

#[repr(C)]
pub struct CtxSha512 {
    initialized: bool,
    counter: u32,
    blen: usize,
    block: [u8; 128],
    acc: [u8; 8 * 8],
}

#[repr(C)]
pub struct CtxRipeMd160 {
    initialized: bool,
    counter: u32,
    blen: usize,
    block: [u8; 64],
    acc: [u8; 5 * 4],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub enum CxCurve {
    Secp256k1 = 0x21,
    Secp256r1 = 0x22,
}

#[repr(C)]
pub struct EcfpPublicKey {
    curve: CxCurve,
    w_len: usize,
    w: [u8; 65],
}

#[repr(C)]
pub struct EcfpPrivateKey {
    curve: CxCurve,
    d_len: usize,
    d: [u8; 32],
}

#[repr(C)]
pub union CtxHashGuest {
    ripemd160: *mut CtxRipeMd160,
    sha3: *mut CtxSha3,
    sha256: *mut CtxSha256,
    sha512: *mut CtxSha512,
}

#[repr(C)]
pub enum CxHashId {
    HashIdRipeMd160,
    HashIdSha3_256,
    HashIdSha256,
    HashIdSha512,
}

#[repr(C)]
pub enum CxMd {
    None = 0,
    RipeMd160 = 1,
    Sha224 = 2,
    Sha256 = 3,
    Sha384 = 4,
    Sha512 = 5,
    Keccak = 6,
    Sha3 = 7,
    Groestl = 8,
    Blake2b = 9,
    Shake128 = 10,
    Shake256 = 11,
    Sha3_256 = 12,
    Sha3_512 = 13,
}

pub const CX_RND_RFC6979: i32 = 3 << 9;

impl CtxSha256 {
    pub fn new() -> Self {
        CtxSha256 {
            initialized: false,
            counter: 0,
            blen: 0,
            block: [0; 64],
            acc: [0; 8 * 4],
        }
    }

    pub fn update(&mut self, buffer: &[u8]) -> &mut Self {
        let hash_ctx = CtxHashGuest { sha256: &mut *self };
        if !unsafe {
            ecall_hash_update(
                CxHashId::HashIdSha256,
                hash_ctx,
                buffer.as_ptr(),
                buffer.len(),
            )
        } {
            fatal("sha256_update");
        }
        self
    }

    pub fn r#final(&mut self) -> [u8; 32] {
        let mut digest = [0u8; 32];
        let hash_ctx = CtxHashGuest { sha256: &mut *self };
        if !unsafe { ecall_hash_final(CxHashId::HashIdSha256, hash_ctx, digest.as_mut_ptr()) } {
            fatal("sha256_final");
        }

        digest
    }
}

impl CtxRipeMd160 {
    pub fn new() -> Self {
        CtxRipeMd160 {
            initialized: false,
            counter: 0,
            blen: 0,
            block: [0; 64],
            acc: [0; 5 * 4],
        }
    }

    pub fn update(&mut self, buffer: &[u8]) -> &mut Self {
        let hash_ctx = CtxHashGuest {
            ripemd160: &mut *self,
        };
        if !unsafe {
            ecall_hash_update(
                CxHashId::HashIdRipeMd160,
                hash_ctx,
                buffer.as_ptr(),
                buffer.len(),
            )
        } {
            fatal("ripemd160_update");
        }
        self
    }

    pub fn r#final(&mut self) -> [u8; 20] {
        let mut digest = [0u8; 20];
        let hash_ctx = CtxHashGuest {
            ripemd160: &mut *self,
        };
        if !unsafe { ecall_hash_final(CxHashId::HashIdRipeMd160, hash_ctx, digest.as_mut_ptr()) } {
            fatal("ripemd160_final");
        }

        digest
    }
}

impl CtxSha3 {
    pub fn new() -> Self {
        CtxSha3 {
            initialized: false,
            counter: 0,
            blen: 0,
            block: [0; 200],
            acc: [0; 25],
        }
    }

    pub fn update(&mut self, buffer: &[u8]) -> &mut Self {
        let hash_ctx = CtxHashGuest { sha3: &mut *self };
        if !unsafe {
            ecall_hash_update(
                CxHashId::HashIdSha3_256,
                hash_ctx,
                buffer.as_ptr(),
                buffer.len(),
            )
        } {
            fatal("sha3_update");
        }
        self
    }

    pub fn r#final(&mut self) -> [u8; 32] {
        let mut digest = [0u8; 32];
        let hash_ctx = CtxHashGuest { sha3: &mut *self };
        if !unsafe { ecall_hash_final(CxHashId::HashIdSha3_256, hash_ctx, digest.as_mut_ptr()) } {
            fatal("sha3_final");
        }

        digest
    }
}

impl CtxSha512 {
    pub fn new() -> Self {
        CtxSha512 {
            initialized: false,
            counter: 0,
            blen: 0,
            block: [0; 128],
            acc: [0; 8 * 8],
        }
    }

    pub fn update(&mut self, buffer: &[u8]) -> &mut Self {
        let hash_ctx = CtxHashGuest { sha512: &mut *self };
        if !unsafe {
            ecall_hash_update(
                CxHashId::HashIdSha512,
                hash_ctx,
                buffer.as_ptr(),
                buffer.len(),
            )
        } {
            fatal("sha512_update");
        }
        self
    }

    pub fn r#final(&mut self) -> [u8; 64] {
        let mut digest = [0u8; 64];
        let hash_ctx = CtxHashGuest { sha512: &mut *self };
        if !unsafe { ecall_hash_final(CxHashId::HashIdSha512, hash_ctx, digest.as_mut_ptr()) } {
            fatal("sha512_final");
        }

        digest
    }
}

pub fn derive_node_bip32(
    curve: CxCurve,
    path: &[u32],
    privkey_data: Option<&mut [u8]>,
    chain_code: Option<&mut [u8]>,
) -> Result<(), SdkError> {
    let privkey_data = if let Some(p) = privkey_data {
        p.as_mut_ptr()
    } else {
        core::ptr::null_mut()
    };
    let chain_code = if let Some(p) = chain_code {
        p.as_mut_ptr()
    } else {
        core::ptr::null_mut()
    };
    if !unsafe {
        ecall_derive_node_bip32(curve, path.as_ptr(), path.len(), privkey_data, chain_code)
    } {
        Err(SdkError::PathDerivation)
    } else {
        Ok(())
    }
}

pub fn ecfp_generate_keypair(
    curve: CxCurve,
    pubkey: &mut EcfpPublicKey,
    privkey: &mut EcfpPrivateKey,
    keep_privkey: bool,
) -> Result<(), SdkError> {
    if !unsafe { ecall_cx_ecfp_generate_pair(curve, pubkey, privkey, keep_privkey) } {
        Err(SdkError::KeyGeneration)
    } else {
        Ok(())
    }
}

pub fn get_random_bytes(buffer: &mut [u8]) {
    unsafe {
        ecall_get_random_bytes(buffer.as_mut_ptr(), buffer.len());
    }
}

pub fn get_master_fingerprint() -> Result<u32, SdkError> {
    let mut out: [u8; 4] = [0; 4];
    if !unsafe { ecall_get_master_fingerprint(&mut out) } {
        Err(SdkError::KeyGeneration)
    } else {
        Ok(u32::from_be_bytes(out))
    }
}

impl EcfpPublicKey {
    pub fn new(curve: CxCurve, bytes: &[u8; 65]) -> Self {
        Self {
            curve,
            w_len: 65,
            w: *bytes,
        }
    }

    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.w
    }

    pub fn to_compressed(&self) -> [u8; 33] {
        let mut compressed_pubkey: [u8; 33] = [0; 33];
        compressed_pubkey[0] = if self.w[64] % 2 == 0 { 0x02 } else { 0x03 };
        compressed_pubkey[1..].copy_from_slice(&self.w[1..33]);

        compressed_pubkey
    }

    pub fn verify(&self, hash: &[u8; 32], sig: &[u8]) -> Result<(), SdkError> {
        if !unsafe { ecall_ecdsa_verify(self, hash.as_ptr(), sig.as_ptr(), sig.len()) } {
            Err(SdkError::SignatureVerification)
        } else {
            Ok(())
        }
    }

    pub fn from_path(curve: CxCurve, path: &[u32]) -> Result<EcfpPublicKey, SdkError> {
        let mut privkey = EcfpPrivateKey::from_path(curve, path)?;
        let mut pubkey = EcfpPublicKey {
            curve,
            w_len: 65,
            w: [0u8; 65],
        };
        ecfp_generate_keypair(curve, &mut pubkey, &mut privkey, true)?;
        Ok(pubkey)
    }
}

impl EcfpPrivateKey {
    pub fn new(curve: CxCurve, bytes: &[u8; 32]) -> Self {
        Self {
            curve,
            d_len: 32,
            d: *bytes,
        }
    }

    pub fn from_path(curve: CxCurve, path: &[u32]) -> Result<EcfpPrivateKey, SdkError> {
        let mut privkey = Self::new(curve, &[0; 32]);
        derive_node_bip32(curve, path, Some(&mut privkey.d), None)?;
        Ok(privkey)
    }

    pub fn pubkey(&self) -> Result<EcfpPublicKey, SdkError> {
        let mut privkey = Self {
            curve: self.curve,
            d_len: self.d_len,
            d: self.d,
        };
        let mut pubkey = EcfpPublicKey {
            curve: self.curve,
            w_len: 65,
            w: [0u8; 65],
        };
        ecfp_generate_keypair(self.curve, &mut pubkey, &mut privkey, true)?;
        Ok(pubkey)
    }

    // todo: the interface of this is too bolos-specific; e.g.: can we get rid of the "mode" argument?
    pub fn sign(&self, mode: i32, hash_id: CxMd, hash: &[u8; 32]) -> Result<Vec<u8>, SdkError> {
        let mut sig = [0u8; 80];
        let sig_len: usize;

        if !unsafe {
            let mut parity: i32 = 0;
            sig_len = ecall_ecdsa_sign(
                self,
                mode,
                hash_id,
                hash.as_ptr(),
                sig.as_mut_ptr(),
                80,
                &mut parity,
            );

            // TODO: is there any error condition to test?

            true
        } {
            Err(SdkError::Signature)
        } else {
            Ok(sig[0..sig_len].to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_ripemd160() {
        let buffer = hex!("616263");

        let digest = CtxRipeMd160::new().update(&buffer).r#final();

        assert_eq!(digest, hex!("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
    }

    #[test]
    fn test_sha256() {
        let buffer = hex!("616263");

        let digest = CtxSha256::new().update(&buffer).r#final();

        assert_eq!(
            digest,
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn test_sha3() {
        assert_eq!(
            CtxSha3::new().update(&hex!("")).r#final(),
            hex!("C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470")
        );
        assert_eq!(
            CtxSha3::new().update(&hex!("41FB")).r#final(),
            hex!("A8EACEDA4D47B3281A795AD9E1EA2122B407BAF9AABCB9E18B5717B7873537D2")
        );
        assert_eq!(
            CtxSha3::new().update(b"Hello").r#final(),
            hex!("06b3dfaec148fb1bb2b066f10ec285e7c9bf402ab32aa78a5d38e34566810cd2")
        );
        let data = &hex!("836b35a026743e823a90a0ee3b91bf615c6a757e2b60b9e1dc1826fd0dd16106f7bc1e8179f665015f43c6c81f39062fc2086ed849625c06e04697698b21855e");
        assert_eq!(
            CtxSha3::new().update(data).r#final(),
            hex!("72f15d6555488541650ce62c0bed7abd61247635c1973eb38474a2516ed1d884")
        );
    }

    #[test]
    fn test_sha512() {
        assert_eq!(
            CtxSha512::new().update(&hex!("")).r#final(),
            hex!("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
        );
        assert_eq!(
            CtxSha512::new().update(b"Hello").r#final(),
            hex!("3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315")
        );
    }

    #[test]
    fn test_handle_get_master_fingerprint() {
        assert_eq!(get_master_fingerprint().unwrap(), 0xf5acc2fdu32);
    }

    // TODO: add more tests for ecdsa; probably, move ecdsa to a submodule
    #[test]
    fn test_ecdsa_sign_verify() {
        let key_raw = [42u8; 32];
        let mut privkey = EcfpPrivateKey::new(CxCurve::Secp256k1, &key_raw);
        let mut pubkey = EcfpPublicKey::new(CxCurve::Secp256k1, &[0u8; 65]);
        ecfp_generate_keypair(CxCurve::Secp256k1, &mut pubkey, &mut privkey, true).unwrap();

        let msg = "If you don't believe me or don't get it, I don't have time to try to convince you, sorry.";
        let msg_hash = CtxSha256::new().update(msg.as_bytes()).r#final();

        let sig = privkey
            .sign(CX_RND_RFC6979, CxMd::Sha256, &msg_hash)
            .unwrap();

        assert_eq!(pubkey.verify(&msg_hash, &sig).is_ok(), true)
    }
}
