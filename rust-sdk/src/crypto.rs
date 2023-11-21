use alloc::vec::Vec;

use crate::{
    ecall::{
        ecall_cx_ecfp_generate_pair, ecall_derive_node_bip32,
        ecall_ecdsa_sign, ecall_ecdsa_verify, ecall_schnorr_sign, ecall_schnorr_verify,
        ecall_get_master_fingerprint, ecall_get_random_bytes, ecall_hash_final,
        ecall_multm, ecall_powm, ecall_subm, ecall_addm, ecall_cx_ecfp_scalar_mult, ecall_cx_ecfp_add_point
    },
    ecall_hash_update, fatal, SdkError,
};


const SECP256K1_GENERATOR: [u8; 65] = [
    0x04,
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
];

// Modulo for secp256k1
pub const SECP256K1_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f
];

// Curve order for secp256k1
pub const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
];

// (p + 1)/4, used to calculate square roots in secp256k1
pub const SECP256K1_SQR_EXPONENT: [u8; 32] = [
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c
];


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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub enum CxCurve {
    Secp256k1 = 0x21,
    Secp256r1 = 0x22,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct EcfpPublicKey {
    curve: CxCurve,
    w_len: usize,
    w: [u8; 65],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct EcfpPrivateKey {
    curve: CxCurve,
    d_len: usize,
    d: [u8; 32],
    /// chain code len 
    cc_len: usize,
    /// chain code
    cc: [u8; 32] 
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union CtxHashGuest {
    ripemd160: *mut CtxRipeMd160,
    sha3: *mut CtxSha3,
    sha256: *mut CtxSha256,
    sha512: *mut CtxSha512,
}

#[derive(Clone, Copy)]
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

pub const CX_RND_TRNG: u32 = 2 << 9;
pub const CX_RND_RFC6979: u32 = 3 << 9;
pub const CX_LAST: i32 = 1 << 0;

pub const CX_ECSCHNORR_BIP0340: u32 = 0 << 12;


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

    pub fn hash(input: &[u8]) -> [u8; 64] {
        let mut h = Self::new();
        h.update(input);
        h.r#final()
    }
}

// adapted from https://github.com/jedisct1/rust-hmac-sha512
pub fn hmac_sha512<T: AsRef<[u8]>, U: AsRef<[u8]>>(k: T, input: U) -> [u8; 64] {
    let input = input.as_ref();
    let k = k.as_ref();
    let mut hk = [0u8; 64];
    let k2 = if k.len() > 128 {
        hk.copy_from_slice(&CtxSha512::hash(k));
        &hk
    } else {
        k
    };
    let mut ih = CtxSha512::new();
    let mut padded = [0x36; 128];
    for (p, &k) in padded.iter_mut().zip(k2.iter()) {
        *p ^= k;
    }
    ih.update(&padded[..]);
    ih.update(input);

    let mut oh = CtxSha512::new();
    padded = [0x5c; 128];
    for (p, &k) in padded.iter_mut().zip(k2.iter()) {
        *p ^= k;
    }
    oh.update(&padded[..]);
    oh.update(&ih.r#final()[..]);
    oh.r#final()
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

fn add_u8_to_u256_be(number: &mut [u8; 32], t: u8) -> u8 {
    let mut carry = t;

    for i in (0..32).rev() {
        let (sum, new_carry) = number[i].overflowing_add(carry);
        number[i] = sum;
        carry = if new_carry { 1 } else { 0 };
    }

    carry
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

    pub fn as_bytes_xonly(&self) -> [u8; 32] {
        let mut xonly_key = [0u8; 32];
        xonly_key.copy_from_slice(&self.w[1..33]);
        xonly_key
    }

    pub fn ecdsa_verify(&self, hash: &[u8; 32], sig: &[u8]) -> Result<(), SdkError> {
        if !unsafe { ecall_ecdsa_verify(self, hash.as_ptr(), sig.as_ptr(), sig.len()) } {
            Err(SdkError::SignatureVerification)
        } else {
            Ok(())
        }
    }

    pub fn schnorr_verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), SdkError> {
        if !unsafe { ecall_schnorr_verify(
            self,
            CX_ECSCHNORR_BIP0340 | CX_RND_TRNG,
            CxMd::Sha256,
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        ) } {
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

    pub fn from_privkey(priv_key: &EcfpPrivateKey) -> Result<Self, SdkError> {
        // ecfp_generate_keypair needs to borrow mutably
        // (even if it doesn't really modify the priv_key if keep_privkey is true)
        let mut priv_key_clone = priv_key.clone();

        let mut pubkey = EcfpPublicKey::new(CxCurve::Secp256k1, &[0; 65]);

        ecfp_generate_keypair(priv_key.curve, &mut pubkey, &mut priv_key_clone, true)?;

        Ok(pubkey)
    }

    pub fn from_slice(data: &[u8]) -> Result<EcfpPublicKey, SdkError> {
        if data.is_empty() {
            return Err(SdkError::InvalidPublicKey);
        }

        match data.len() {
            33 => {
                let prefix = data[0];
                let x: [u8; 32] = data[1..33].try_into().expect("Cannot fail");

                let mut y: [u8; 32] = x.clone();

                unsafe {
                    // TODO: handle errors

                    ecall_multm(y.as_mut_ptr(), x.as_ptr(), x.as_ptr(), SECP256K1_P.as_ptr(), 32); // y = x^2
                    ecall_multm(y.as_mut_ptr(), y.as_ptr(), x.as_ptr(), SECP256K1_P.as_ptr(), 32); // y = x^3

                    add_u8_to_u256_be(&mut y, 7); // y = x^3 + 7

                    ecall_powm(y.as_mut_ptr(), y.as_ptr(), SECP256K1_SQR_EXPONENT.as_ptr(), 32, SECP256K1_P.as_ptr(), 32);

                    // if the prefix and y don't have the same parity, take the opposite root (mod p)
                    if ((prefix ^ y[31]) & 1) != 0 {
                        ecall_subm(y.as_mut_ptr(), SECP256K1_P.as_ptr(), y.as_ptr(), SECP256K1_P.as_ptr(), 32);
                    }

                }

                let mut w: [u8; 65] = [0; 65];
                w[0] = 0x04;
                w[1..33].copy_from_slice(&x);
                w[33..].copy_from_slice(&y);

                Ok(EcfpPublicKey { curve: CxCurve::Secp256k1, w_len: 65, w })
            },
            65 => Ok(EcfpPublicKey { curve: CxCurve::Secp256k1, w_len: 65, w: data.try_into().expect("Cannot fail") }),
            _ => Err(SdkError::InvalidPublicKey),
        }
    }

    pub fn has_odd_y(&self) -> bool {
        return self.w[64] & 1 != 0
    }

    pub fn add_exp_tweak(&mut self, t: &[u8; 32]) -> Result<(), SdkError> {
        let exp_tweak = secp256k1_point(&t)?;
        unsafe {
            if !ecall_cx_ecfp_add_point(CxCurve::Secp256k1, self.w.as_mut_ptr(), self.w.as_ptr(), exp_tweak.w.as_ptr()) {
                return Err(SdkError::TweakError);
            }
        }

        Ok(())
    }
}


pub fn secp256k1_point(data: &[u8; 32]) -> Result<EcfpPublicKey, SdkError> {
    let mut point = SECP256K1_GENERATOR;
    unsafe {
        if !ecall_cx_ecfp_scalar_mult(CxCurve::Secp256k1, point.as_mut_ptr(), data.as_ptr(), data.len()) {
            return Err(SdkError::TweakError);
        }
    }
    Ok(EcfpPublicKey::new(CxCurve::Secp256k1, &point))
}

impl EcfpPrivateKey {
    pub fn new(curve: CxCurve, bytes: &[u8; 32], chain_code: &[u8; 32]) -> Self {
        Self {
            curve,
            d_len: 32,
            d: *bytes,
            cc_len: 32,
            cc: *chain_code,
        }
    }

    pub fn from_path(curve: CxCurve, path: &[u32]) -> Result<EcfpPrivateKey, SdkError> {
        let mut privkey = Self::new(curve, &[0; 32], &[0; 32]);
        derive_node_bip32(curve, path, Some(&mut privkey.d), Some(&mut privkey.cc))?;
        Ok(privkey)
    }

    pub fn secp256k1_point(&self) -> Result<EcfpPublicKey, SdkError> {
        secp256k1_point(&self.d)
    }

    pub fn pubkey(&self) -> Result<EcfpPublicKey, SdkError> {
        let mut privkey = Self {
            curve: self.curve,
            d_len: self.d_len,
            d: self.d,
            cc_len: self.cc_len,
            cc: self.cc
        };
        let mut pubkey = EcfpPublicKey {
            curve: self.curve,
            w_len: 65,
            w: [0u8; 65],
        };
        ecfp_generate_keypair(self.curve, &mut pubkey, &mut privkey, true)?;
        Ok(pubkey)
    }

    pub fn chaincode(&self) -> Result<[u8; 32], SdkError> {
        Ok(self.cc)
    }

    // todo: the interface of this is too bolos-specific; e.g.: can we get rid of the "mode" argument?
    pub fn ecdsa_sign(&self, mode: i32, hash_id: CxMd, hash: &[u8; 32]) -> Result<(Vec<u8>, u32), SdkError> {
        let mut sig = [0u8; 80];
        let sig_len: usize;
        let mut parity: i32 = 0;

        if !unsafe {
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
            Ok((sig[0..sig_len].to_vec(), parity as u32 & 1u32))
        }
    }

    // todo: the interface of this might be too bolos-specific
    pub fn schnorr_sign(&self, msg: &[u8]) -> Result<Vec<u8>, SdkError> {
        // BIP0340 signatures are always 64 bytes long
        // no other types of Schnorr signatures are implemented at this time
        let mut sig = [0u8; 64];
        let mut sig_len: usize = sig.len();

        unsafe {
            if ecall_schnorr_sign(
                self,
                CX_ECSCHNORR_BIP0340 | CX_RND_TRNG,
                CxMd::Sha256,
                    msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                &mut sig_len,
            ) {
                if sig_len != sig.len() {
                    return Err(SdkError::GenericError); // This should never happen
                }

                Ok(sig[0..sig_len].to_vec())
            } else {
                Err(SdkError::Signature)
            }
        }
    }

    pub fn add_tweak(&mut self, t: &[u8; 32]) -> Result<(), SdkError> {
        let pk = secp256k1_point(&self.d)?;
        unsafe {
            if pk.has_odd_y() {
                // odd y, negate the secret key
                if !ecall_subm(self.d.as_mut_ptr(), SECP256K1_N.as_ptr(), self.d.as_ptr(), SECP256K1_N.as_ptr(), self.d_len) {
                    return Err(SdkError::TweakError);
                }
            }

            // TODO: should fail if t >= SECP256K1_N

            if !ecall_addm(self.d.as_mut_ptr(), self.d.as_ptr(), t.as_ptr(), SECP256K1_N.as_ptr(), 32) {
                return Err(SdkError::TweakError);
            }
        }

        Ok(())
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
    fn test_hmac_sha512() {
        assert_eq!(
            hmac_sha512(&[42u8; 50], &[69u8; 250]),
            hex!("7a6fbbf14ac2166a5fce50d74bcf0b4e255e7d6e7d2afe67e01570f7e9e524c83aeed39c79e70fca805a7eb3bc25c26adfda2dd3955b83e275b8af55e0c552af")
        )
    }

    #[test]
    fn test_handle_get_master_fingerprint() {
        assert_eq!(get_master_fingerprint().unwrap(), 0xf5acc2fdu32);
    }

    // TODO: add more tests for ecdsa; probably, move ecdsa to a submodule
    #[test]
    fn test_ecdsa_sign_verify() {
        let key_raw = [42u8; 32];
        let chain_code = [0u8; 32];
        let mut privkey = EcfpPrivateKey::new(CxCurve::Secp256k1, &key_raw, &chain_code);
        let mut pubkey = EcfpPublicKey::new(CxCurve::Secp256k1, &[0u8; 65]);
        ecfp_generate_keypair(CxCurve::Secp256k1, &mut pubkey, &mut privkey, true).unwrap();

        let msg = "If you don't believe me or don't get it, I don't have time to try to convince you, sorry.";
        let msg_hash = CtxSha256::new().update(msg.as_bytes()).r#final();

        let sig = privkey
            .ecdsa_sign(CX_RND_RFC6979 as i32, CxMd::Sha256, &msg_hash)
            .unwrap();

        assert_eq!(pubkey.ecdsa_verify(&msg_hash, &sig).is_ok(), true)
    }

    #[test]
    fn test_schnorr_sign_verify() {
        let key_raw = [42u8; 32];
        let mut privkey = EcfpPrivateKey::new(CxCurve::Secp256k1, &key_raw);
        let mut pubkey = EcfpPublicKey::new(CxCurve::Secp256k1, &[0u8; 65]);
        ecfp_generate_keypair(CxCurve::Secp256k1, &mut pubkey, &mut privkey, true).unwrap();

        let msg = "If you don't believe me or don't get it, I don't have time to try to convince you, sorry.";
        let msg_hash = CtxSha256::new().update(msg.as_bytes()).r#final();

        let sig = privkey
            .schnorr_sign(&msg_hash)
            .unwrap();

        assert_eq!(pubkey.schnorr_verify(&msg_hash, &sig).is_ok(), true)
    }
}
