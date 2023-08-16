#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "ecall-vm.h"
#include "ecall.h"
#include "sdk.h"

#include "../../../vm/src/ecall_hash.h"

bool ecall_derive_node_bip32(cx_curve_t curve,
                             const unsigned int *path,
                             size_t path_count,
                             uint8_t *private_key,
                             uint8_t *chain)
{
    eret_t eret;

    if (!sys_derive_node_bip32(&eret, curve, NP(path), path_count, NP(private_key), NP(chain))) {
        errx(1, "sys_derive_node_bip32 failed");
    }

    return eret.success;
}

size_t ecall_ecdsa_sign(const cx_ecfp_private_key_t *key,
                        const int mode,
                        const cx_md_t hash_id,
                        const uint8_t *hash,
                        uint8_t *sig,
                        size_t sig_len,
                        int *parity)
{
    eret_t eret;

    if (!sys_ecdsa_sign(&eret, NP(key), mode, hash_id, NP(hash), NP(sig), sig_len, NP(parity))) {
        errx(1, "sys_ecdsa_sign failed");
    }

    return eret.size;
}

bool ecall_ecdsa_verify(const cx_ecfp_public_key_t *key,
                        const uint8_t *hash,
                        const uint8_t *sig,
                        const size_t sig_len)
{
    eret_t eret;

    if (!sys_ecdsa_verify(&eret, NP(key), NP(hash), NP(sig), sig_len)) {
        errx(1, "sys_ecdsa_verify failed");
    }

    return eret.success;
}

bool ecall_cx_ecfp_generate_pair(cx_curve_t curve,
                                 cx_ecfp_public_key_t *pubkey,
                                 cx_ecfp_private_key_t *privkey,
                                 bool keep_privkey)
{
    eret_t eret;

    if (!_sys_cx_ecfp_generate_pair(&eret, curve, NP(pubkey), NP(privkey), keep_privkey)) {
        errx(1, "_sys_cx_ecfp_generate_pair failed");
    }

    return eret.success;
}

bool ecall_cx_ecfp_add_point(cx_curve_t curve, uint8_t *R, const uint8_t *P, const uint8_t *Q) {
    eret_t eret;

    if (!_sys_cx_ecfp_add_point(&eret, curve, NP(R), NP(P), NP(Q))) {
        errx(1, "_sys_cx_ecfp_add_point failed");
    }

    return eret.success;
}

bool ecall_cx_ecfp_scalar_mult(cx_curve_t curve, uint8_t *P, const uint8_t *k, size_t k_len) {
    eret_t eret;

    if (!_sys_cx_ecfp_scalar_mult(&eret, curve, NP(P), NP(k), k_len)) {
        errx(1, "_sys_cx_ecfp_scalar_mult failed");
    }

    return eret.success;
}



void ecall_get_random_bytes(uint8_t *buffer, const size_t size)
{
    if (!sys_get_random_bytes(NP(buffer), size)) {
        errx(1, "sys_get_random_bytes failed");
    }
}

bool ecall_hash_update(const cx_hash_id_t hash_id,
                       ctx_hash_guest_t *ctx,
                       const uint8_t *buffer,
                       const size_t size)
{
    eret_t eret;

    if (!sys_hash_update(&eret, hash_id, NP(ctx), NP(buffer), size)) {
        errx(1, "sys_hash_update failed");
    }

    return eret.success;
}

bool ecall_hash_final(const cx_hash_id_t hash_id, ctx_hash_guest_t *ctx, uint8_t *digest)
{
    eret_t eret;

    if (!sys_hash_final(&eret, hash_id, NP(ctx), NP(digest))) {
        errx(1, "sys_hash_final failed");
    }

    return eret.success;
}

bool ecall_addm(uint8_t *r, const uint8_t *a, const uint8_t *b, const uint8_t *m, size_t len)
{
    eret_t eret;

    if (!sys_addm(&eret, NP(r), NP(a), NP(b), NP(m), len)) {
        errx(1, "sys_addm failed");
    }

    return eret.success;
}

bool ecall_subm(uint8_t *r, const uint8_t *a, const uint8_t *b, const uint8_t *m, size_t len)
{
    eret_t eret;

    if (!sys_subm(&eret, NP(r), NP(a), NP(b), NP(m), len)) {
        errx(1, "sys_subm failed");
    }

    return eret.success;
}

bool ecall_multm(uint8_t *r, const uint8_t *a, const uint8_t *b, const uint8_t *m, size_t len)
{
    eret_t eret;

    if (!sys_multm(&eret, NP(r), NP(a), NP(b), NP(m), len)) {
        errx(1, "sys_multm failed");
    }

    return eret.success;
}

bool ecall_powm(uint8_t *r, const uint8_t *a, const uint8_t *e, size_t len_e, const uint8_t *m, size_t len)
{
    eret_t eret;

    if (!sys_powm(&eret, NP(r), NP(a), NP(e), len_e, NP(m), len)) {
        errx(1, "sys_powm failed");
    }

    return eret.success;
}

bool ecall_tostring256(const uint256_t *number, const unsigned int base, char *out, size_t len)
{
    eret_t eret;

    if (!sys_tostring256(&eret, NP(number), base, NP(out), len)) {
        errx(1, "sys_tostring256 failed");
    }

    return eret.success;
}

bool ecall_get_master_fingerprint(uint32_t *out)
{
    eret_t eret;

    if (!sys_get_master_fingerprint(&eret, NP(out))) {
        errx(1, "sys_get_master_fingerprint failed");
    }

    return eret.success;
}

size_t ecall_convert(uint32_t format, const char *src, size_t src_len, char *dst, size_t dst_max_len)
{
    eret_t eret;

    if (!sys_convert(&eret, format, NP(src), src_len, NP(dst), dst_max_len)) {
        errx(1, "sys_convert failed");
    }
    return eret.size;
}