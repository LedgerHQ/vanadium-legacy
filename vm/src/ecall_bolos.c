#include <string.h>

#include "ecall.h"
#include "ecall_hash.h"
#include "error.h"
#include "page.h"
#include "uint256-internal.h"

#include "cx.h"
#include "os_random.h"
#include "os_seed.h"

#include "api/ecall-nr.h"

#include "base58.h"
#include "segwit_addr.h"

bool sys_derive_node_bip32(eret_t *eret, cx_curve_t curve, guest_pointer_t p_path, size_t path_count, guest_pointer_t p_private_key, guest_pointer_t p_chain)
{
    const unsigned int path[10];
    uint8_t private_key[32];
    uint8_t chain[32];

    if (path_count > 10) {
        eret->success = false;
        return true;
    }

    if (curve != CX_CURVE_256K1 && curve != CX_CURVE_SECP256R1) {
        fatal("derive_node_bip32: invalid curve (TODO)");
    }

    if (!copy_guest_buffer(p_path, (void *)path, path_count * sizeof(unsigned int))) {
        return false;
    }

    if (!copy_guest_buffer(p_private_key, private_key, sizeof(private_key))) {
        return false;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    os_perso_derive_node_bip32(curve, path, path_count, private_key, chain);
#pragma GCC diagnostic pop

    if (p_private_key.addr != 0) {
        if (!copy_host_buffer(p_private_key, &private_key, sizeof(private_key))) {
            return false;
        }
        explicit_bzero(private_key, sizeof(private_key));
    }

    if (p_chain.addr != 0) {
        if (!copy_host_buffer(p_chain, &chain, sizeof(chain))) {
            return false;
        }
    }

    eret->success = true;

    return true;
}

bool _sys_cx_ecfp_generate_pair(eret_t *eret, cx_curve_t curve, guest_pointer_t p_pubkey, guest_pointer_t p_privkey, bool keep_privkey)
{
    cx_ecfp_public_key_t pubkey;
    cx_ecfp_private_key_t privkey;

    if (keep_privkey) {
        if (!copy_guest_buffer(p_privkey, &privkey, sizeof(privkey))) {
            return false;
        }

        if (privkey.d_len > sizeof(privkey.d)) {
            eret->success = false;
            goto error;
        }
    }

    cx_err_t err = cx_ecfp_generate_pair_no_throw(curve, &pubkey, &privkey, keep_privkey);
    if (err != CX_OK) {
        eret->success = false;
        goto error;
    }

    if (!copy_host_buffer(p_pubkey, &pubkey, sizeof(pubkey))) {
        return false;
    }

    if (!keep_privkey) {
        if (!copy_host_buffer(p_privkey, &privkey, sizeof(privkey))) {
            return false;
        }
    }

    eret->success = true;

 error:
    explicit_bzero(&privkey, sizeof(privkey));

    return true;
}

bool _sys_cx_ecfp_add_point(eret_t *eret, cx_curve_t curve, guest_pointer_t p_r, guest_pointer_t p_p, guest_pointer_t p_q) {
    uint8_t r[65], p[65], q[65];

    if (!copy_guest_buffer(p_r, r, sizeof(r))) return false;
    if (!copy_guest_buffer(p_p, p, sizeof(p))) return false;
    if (!copy_guest_buffer(p_q, q, sizeof(q))) return false;

    cx_err_t err = cx_ecfp_add_point_no_throw(curve, r, p, q);

    if (err != CX_OK) {
        eret->success = false;
        return true;
    }

    if (!copy_host_buffer(p_r, r, sizeof(r))) {
        return false;
    }

    eret->success = true;
    return true;
}

bool _sys_cx_ecfp_scalar_mult(eret_t *eret, cx_curve_t curve, guest_pointer_t p_p, guest_pointer_t p_k, size_t k_len) {
    uint8_t p[65], k[32];

    if (!copy_guest_buffer(p_p, p, sizeof(p))) return false;
    if (!copy_guest_buffer(p_k, k, sizeof(k))) return false;

    cx_err_t err = cx_ecfp_scalar_mult_no_throw(curve, p, k, k_len);

    if (err != CX_OK) {
        eret->success = false;
        return true;
    }

    if (!copy_host_buffer(p_p, p, sizeof(p))) {
        return false;
    }

    eret->success = true;
    return true;
}

bool sys_ecdsa_sign(eret_t *eret, const guest_pointer_t p_key, const int mode,
                    const cx_md_t hash_id, const guest_pointer_t p_hash,
                    guest_pointer_t p_sig, size_t sig_len, guest_pointer_t p_parity)
{
    cx_ecfp_private_key_t key;
    uint8_t hash[CX_SHA512_SIZE];
    size_t hash_len;
    uint8_t sig[100];
    uint32_t info;

    eret->size = 0;

    switch (hash_id) {
    case CX_SHA224: hash_len = CX_SHA224_SIZE; break;
    case CX_SHA256: hash_len = CX_SHA256_SIZE; break;
    case CX_SHA384: hash_len = CX_SHA384_SIZE; break;
    case CX_SHA512: hash_len = CX_SHA512_SIZE; break;
    case CX_RIPEMD160: hash_len = CX_RIPEMD160_SIZE; break;
    default: return true;
    }

    if (!copy_guest_buffer(p_key, (void *)&key, sizeof(key))) {
        return false;
    }
    if (!copy_guest_buffer(p_hash, hash, hash_len)) {
        return false;
    }

    size_t sig_size = sizeof(sig);
    cx_err_t error = cx_ecdsa_sign_no_throw(&key, mode, hash_id, hash, hash_len, sig, &sig_size, &info);
    if (error != CX_OK || sig_size > sig_len) {
        return true;
    }

    if (!copy_host_buffer(p_sig, sig, sig_size)) {
        return false;
    }

    if (p_parity.addr != 0) {
        int int_info = info;
        if (!copy_host_buffer(p_parity, &int_info, sizeof(int_info))) {
            return false;
        }
    }

    eret->size = sig_size;

    return true;
}

bool sys_ecdsa_verify(eret_t *eret, const guest_pointer_t p_key,
                      const guest_pointer_t p_hash,
                      const guest_pointer_t p_sig, const size_t sig_len)
{
    cx_ecfp_public_key_t key;
    uint8_t hash[CX_SHA256_SIZE];
    uint8_t sig[100];

    if (!copy_guest_buffer(p_key, (void *)&key, sizeof(key))) {
        return false;
    }

    if (!copy_guest_buffer(p_hash, hash, sizeof(hash))) {
        return false;
    }

    if (sig_len > sizeof(sig)) {
        eret->success = false;
        return true;
    }

    if (!copy_guest_buffer(p_sig, sig, sig_len)) {
        return false;
    }

    eret->success = cx_ecdsa_verify_no_throw(&key, hash, sizeof(hash), sig, sig_len);

    return true;
}

// BIP0340 signatures are 64 bytes, but it's larger for other supported curves;
// currently, no supported curve produces signatures longer than 72 bytes
#define MAX_SCHNORR_SIGNATURE_SIZE 72

bool sys_schnorr_sign(eret_t *eret, const guest_pointer_t p_key, uint32_t mode,
                      const cx_md_t hash_id, const guest_pointer_t p_msg, size_t msg_len,
                      guest_pointer_t p_sig, guest_pointer_t p_sig_len) {
    cx_ecfp_private_key_t key;
    uint8_t msg[128];
    size_t sig_len;

    eret->success = false;

    if (!copy_guest_buffer(p_key, (void *)&key, sizeof(key))) {
        return false;
    }

    if (msg_len > sizeof(msg)) {
        return true;
    }

    if (!copy_guest_buffer(p_msg, (void *)&msg, msg_len)) {
        return false;
    }

    if (!copy_guest_buffer(p_sig_len, (void *)&sig_len, sizeof(sig_len))) {
        return false;
    }

    uint8_t sig[MAX_SCHNORR_SIGNATURE_SIZE];
    cx_err_t err = cx_ecschnorr_sign_no_throw(&key, mode, hash_id, msg, msg_len, sig, &sig_len);
    if (err != CX_OK || sig_len > sizeof(sig)) {
        return true;
    }

    if (!copy_host_buffer(p_sig, sig, sig_len)) {
        return false;
    }

    if (!copy_host_buffer(p_sig_len, (void *)&sig_len, sig_len)) {
        return false;
    }

    eret->success = true;
    return true;
}

bool sys_schnorr_verify(eret_t *eret, const guest_pointer_t p_key, uint32_t mode,
                        const cx_md_t hash_id, const guest_pointer_t p_msg, size_t msg_len,
                        const guest_pointer_t p_sig, size_t sig_len) {
    cx_ecfp_public_key_t key;
    uint8_t msg[128];

    eret->success = false;

    if (!copy_guest_buffer(p_key, (void *)&key, sizeof(key))) {
        return false;
    }

    if (msg_len > sizeof(msg)) {
        return true;
    }

    if (!copy_guest_buffer(p_msg, (void *)&msg, msg_len)) {
        return false;
    }

    uint8_t sig[MAX_SCHNORR_SIGNATURE_SIZE];
    if (sig_len > sizeof(sig)) {
        return true;
    }
    if (!copy_guest_buffer(p_sig, sig, sig_len)) {
        return false;
    }

    eret->success = cx_ecschnorr_verify(&key, mode, hash_id, msg, msg_len, sig, sig_len);
    return true;
}

bool sys_get_random_bytes(guest_pointer_t p_buffer, size_t size)
{
    while (size > 0) {
        const size_t n = BUFFER_MIN_SIZE(p_buffer.addr, size);
        uint8_t *buffer = get_buffer(p_buffer.addr, n, true);
        if (buffer == NULL) {
            return false;
        }

        if (cx_get_random_bytes(buffer, n) != CX_OK) {
            /* this should never happen */
            return false;
        }

        p_buffer.addr += n;
        size -= n;
    }

    return true;
}

/**
 * If m is NULL, add().
 */
bool sys_addm(eret_t *eret, guest_pointer_t p_r, guest_pointer_t p_a, guest_pointer_t p_b, guest_pointer_t p_m, size_t len)
{
    uint8_t r[64], a[32], b[32];

    if (len > sizeof(a)) {
        err("invalid size for addm");
        eret->success = false;
        return true;
    }

    if (!copy_guest_buffer(p_a, a, len)) {
        return false;
    }

    if (!copy_guest_buffer(p_b, b, len)) {
        return false;
    }

    cx_err_t err;
    if (p_m.addr == 0) {
        err = cx_math_add_no_throw(r, a, b, len);
    } else {
        uint8_t m[32];
        if (!copy_guest_buffer(p_m, m, len)) {
            return false;
        }

        err = cx_math_addm_no_throw(r, a, b, m, len);
    }

    if (err != CX_OK) {
        eret->success = false;
        return true;
    }

    if (!copy_host_buffer(p_r, r, len * 2)) {
        return false;
    }

    eret->success = true;

    return true;
}

/**
 * If m is NULL, sub().
 */
bool sys_subm(eret_t *eret, guest_pointer_t p_r, guest_pointer_t p_a, guest_pointer_t p_b, guest_pointer_t p_m, size_t len)
{
    uint8_t r[64], a[32], b[32];

    if (len > sizeof(a)) {
        err("invalid size for subm");
        eret->success = false;
        return true;
    }

    if (!copy_guest_buffer(p_a, a, len)) {
        return false;
    }

    if (!copy_guest_buffer(p_b, b, len)) {
        return false;
    }

    cx_err_t err;
    if (p_m.addr == 0) {
        err = cx_math_sub_no_throw(r, a, b, len);
    } else {
        uint8_t m[32];
        if (!copy_guest_buffer(p_m, m, len)) {
            return false;
        }

        err = cx_math_subm_no_throw(r, a, b, m, len);
    }

    if (err != CX_OK) {
        eret->success = false;
        return true;
    }

    if (!copy_host_buffer(p_r, r, len * 2)) {
        return false;
    }

    eret->success = true;

    return true;
}

/**
 * If m is NULL, mult().
 */
bool sys_multm(eret_t *eret, guest_pointer_t p_r, guest_pointer_t p_a, guest_pointer_t p_b, guest_pointer_t p_m, size_t len)
{
    uint8_t r[64], a[32], b[32];

    if (len > sizeof(a)) {
        err("invalid size for multm");
        eret->success = false;
        return true;
    }

    if (!copy_guest_buffer(p_a, a, len)) {
        return false;
    }

    if (!copy_guest_buffer(p_b, b, len)) {
        return false;
    }

    cx_err_t err;
    if (p_m.addr == 0) {
        err = cx_math_mult_no_throw(r, a, b, len);
    } else {
        uint8_t m[32];
        if (!copy_guest_buffer(p_m, m, len)) {
            return false;
        }

        err = cx_math_multm_no_throw(r, a, b, m, len);
    }

    if (err != CX_OK) {
        eret->success = false;
        return true;
    }

    if (!copy_host_buffer(p_r, r, len * 2)) {
        return false;
    }

    eret->success = true;

    return true;
}

/**
 * TODO: verify if cx_math_powm_no_throw works for lengths > 32
 */
bool sys_powm(eret_t *eret, guest_pointer_t p_r, guest_pointer_t p_a, guest_pointer_t p_e, size_t len_e, guest_pointer_t p_m, size_t len)
{
    uint8_t r[32], a[32], e[32], m[32];

    if (len > sizeof(r) || len_e > sizeof(e)) {
        err("invalid size for powm");
        eret->success = false;
        return true;
    }

    if (!copy_guest_buffer(p_a, a, len)) {
        return false;
    }

    if (!copy_guest_buffer(p_e, e, len_e)) {
        return false;
    }

    if (!copy_guest_buffer(p_m, m, len)) {
        return false;
    }

    cx_err_t err = cx_math_powm_no_throw(r, a, e, len_e, m, len);

    if (err != CX_OK) {
        eret->success = false;
        return true;
    }

    if (!copy_host_buffer(p_r, r, len)) {
        return false;
    }

    eret->success = true;

    return true;
}

bool sys_tostring256(eret_t *eret, const guest_pointer_t p_number, const unsigned int base, guest_pointer_t p_out, size_t len)
{
    uint256_t number;
    char buf[100];

    if (len > sizeof(buf)) {
        len = sizeof(buf);
    }

    if (!copy_guest_buffer(p_number, &number, sizeof(number))) {
        return false;
    }

    if (!tostring256_implem(&number, base, buf, len)) {
        eret->success = false;
        return true;
    }

    if (!copy_host_buffer(p_out, buf, len)) {
        return false;
    }

    eret->success = true;

    return true;
}

bool sys_get_master_fingerprint(eret_t *eret, guest_pointer_t p_out)
{
    uint8_t raw_private_key[32] = {0};
    uint8_t chain_code[32] = {0};

    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key;

    int ret = 0;

    // derive the seed with bip32_path
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    os_perso_derive_node_bip32(CX_CURVE_256K1,
                               (const uint32_t[]){},
                               0,
                               raw_private_key,
                               chain_code);
#pragma GCC diagnostic pop

    // new private_key from raw
    ret = cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1,
                                            raw_private_key,
                                            sizeof(raw_private_key),
                                            &private_key);
    if (ret < 0) {
        eret->success = false;
        return true;
    }

    // generate corresponding public key
    cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &public_key, &private_key, 1);

    explicit_bzero(raw_private_key, sizeof(raw_private_key));
    explicit_bzero(chain_code, sizeof(chain_code));
    explicit_bzero(&private_key, sizeof(private_key));

    if (ret < 0) {
        eret->success = false;
        return true;
    }

    uint8_t compressed_pubkey[33];
    compressed_pubkey[0] = (public_key.W[64] % 2 == 1) ? 0x03 : 0x02;
    memmove(compressed_pubkey + 1, public_key.W + 1, 32);

    uint8_t hash[32];
    cx_hash_sha256(compressed_pubkey, sizeof(compressed_pubkey), hash, 32);
    cx_hash_ripemd160(hash, 32, hash, 20);

    // the first 4 bytes are the fingerprint
    if (!copy_host_buffer(p_out, hash, 4)) {
        return false;
    }

    eret->success = true;
    return true;
}

// TODO: maybe add an additional param, e.g. for the HRP in bech32m? Unsure
// BASE58ENCODE
// BASE58DECODE
// SEGWITADDRENCODETESTNET
// SEGWITADDRENCODEMAINNET
bool sys_convert(eret_t *eret, FormatConversion format, const guest_pointer_t p_src, size_t src_len, guest_pointer_t p_dst, size_t dst_max_len) {
    uint8_t src[128];
    uint8_t dst[128];

    eret->size = 0; // size 0 signals failure for this ecall

    if (src_len > sizeof(src) || dst_max_len > sizeof(dst)) {
        return true;
    }

    if (!copy_guest_buffer(p_src, &src, sizeof(src))) {
        return false;
    }    

    int actual_output_len = -1; // -1 signals errors
    switch(format) {
        case BASE58ENCODE:
            actual_output_len = base58_encode(src, src_len, (char *)dst, dst_max_len);
            break;
        case BASE58DECODE:
            actual_output_len = base58_decode((const char*)src, src_len, dst, dst_max_len);
            break;
        case SEGWITADDRMAINNET:
        case SEGWITADDRTESTNET:
            if (src_len < 4 || src_len > 42) {
                return true; // invalid segwit scriptPubkey
            }
            if (dst_max_len < 73 + 2) {
                return true; // 73 + strlen(hrp); here hrp is "bc" or "tb"
            }

            int segwit_ver;
            if (src[0] == 0) {
                segwit_ver = 0;
            } else if (src[0] >= 0x51 && src[0] <= 0x60) {
                segwit_ver = src[0] - 0x50;
            } else {
                return true; // invalid segwit script
            }

            size_t prog_len = src[1];
            if (src_len != prog_len + 2) {
                return true; // length mismatch
            }

            if (segwit_addr_encode(
                (char *)dst,
                format == SEGWITADDRMAINNET ? "bc" : "tb",
                segwit_ver,
                src + 2,
                prog_len) != 1)
            {
                actual_output_len = -1;
                break;
            }
            // since segwit_addr_encode succeded, we know the output is a valid 0-terminated string
            actual_output_len = (int)strlen((const char *)dst); 
            break;
        default:
            return true; // unknown format
    }

    if (actual_output_len < 0) {
        return true;
    }

    if (dst_max_len < (size_t)actual_output_len + 1) {
        return true;
    }
    dst[actual_output_len] = '\0';

    if (!copy_host_buffer(p_dst, dst, actual_output_len + 1)) {
        return false;
    }

    eret->size = (size_t)actual_output_len;
    return true;
}