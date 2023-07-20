/**
 * Wrappers for speculos syscalls and cxlib functions.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "speculos.h"

cx_err_t cx_bn_alloc(cx_bn_t *x, size_t nbytes)
{
    return sys_cx_bn_alloc(x, nbytes);
}

cx_err_t cx_bn_alloc_init(cx_bn_t *x, size_t nbytes, const uint8_t *value, size_t value_nbytes)
{
    return sys_cx_bn_alloc_init(x, nbytes, value, value_nbytes);
}

cx_err_t cx_bn_cmp(const cx_bn_t bn_a, const cx_bn_t bn_b, int *diff)
{
    return sys_cx_bn_cmp(bn_a, bn_b, diff);
}

cx_err_t cx_bn_destroy(cx_bn_t *bn_x)
{
    return sys_cx_bn_destroy(bn_x);
}

cx_err_t cx_bn_export(const cx_bn_t bn_x, uint8_t *bytes, size_t nbytes)
{
    return sys_cx_bn_export(bn_x, bytes, nbytes);
}

cx_err_t cx_bn_init(cx_bn_t bn_x, const uint8_t *bytes, size_t nbytes)
{
    return sys_cx_bn_init(bn_x, bytes, nbytes);
}

cx_err_t cx_bn_lock(size_t word_size, uint32_t flags)
{
    return sys_cx_bn_lock(word_size, flags);
}

cx_err_t cx_bn_mod_add(cx_bn_t bn_r, const cx_bn_t bn_a, const cx_bn_t bn_b, const cx_bn_t bn_m)
{
    return sys_cx_bn_mod_add(bn_r, bn_a, bn_b, bn_m);
}

cx_err_t cx_bn_mod_mul(cx_bn_t bn_r, const cx_bn_t bn_a, const cx_bn_t bn_b, const cx_bn_t bn_m)
{
    return sys_cx_bn_mod_mul(bn_r, bn_a, bn_b, bn_m);
}

cx_err_t cx_bn_rand(cx_bn_t bn_x)
{
    return sys_cx_bn_rand(bn_x);
}

cx_err_t cx_bn_reduce(cx_bn_t bn_r, const cx_bn_t bn_d, const cx_bn_t bn_n)
{
    return sys_cx_bn_reduce(bn_r, bn_d, bn_n);
}

cx_err_t cx_bn_unlock(void)
{
    return sys_cx_bn_unlock();
}

cx_err_t cx_ecdomain_generator_bn(cx_curve_t cv, cx_ecpoint_t *P)
{
    return sys_cx_ecdomain_generator_bn(cv, P);
}

cx_err_t cx_ecdomain_parameter_bn(cx_curve_t cv, cx_curve_dom_param_t id, cx_bn_t p)
{
    return sys_cx_ecdomain_parameter_bn(cv, id, p);
}

cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length)
{
    return sys_cx_ecdomain_parameters_length(cv, length);
}

cx_err_t cx_ecpoint_add(cx_ecpoint_t *R, const cx_ecpoint_t *P, const cx_ecpoint_t *Q)
{
    return sys_cx_ecpoint_add(R, P, Q);
}

cx_err_t cx_ecpoint_alloc(cx_ecpoint_t *P, cx_curve_t cv)
{
    return sys_cx_ecpoint_alloc(P, cv);
}

cx_err_t cx_ecpoint_cmp(const cx_ecpoint_t *P, const cx_ecpoint_t *Q, bool *is_equal)
{
    return sys_cx_ecpoint_cmp(P, Q, is_equal);
}

cx_err_t cx_ecpoint_compress(const cx_ecpoint_t *P,
                             uint8_t *xy_compressed,
                             size_t xy_compressed_len,
                             uint32_t *sign)
{
    return sys_cx_ecpoint_compress(P, xy_compressed, xy_compressed_len, sign);
}

cx_err_t cx_ecpoint_decompress(cx_ecpoint_t *P,
                               const uint8_t *xy_compressed,
                               size_t xy_compressed_len,
                               uint32_t sign)
{
    return sys_cx_ecpoint_decompress(P, xy_compressed, xy_compressed_len, sign);
}

cx_err_t cx_ecpoint_destroy(cx_ecpoint_t *P)
{
    return sys_cx_ecpoint_destroy(P);
}

cx_err_t cx_ecpoint_double_scalarmul(cx_ecpoint_t *R,
                                     cx_ecpoint_t *P,
                                     cx_ecpoint_t *Q,
                                     const uint8_t *k,
                                     size_t k_len,
                                     const uint8_t *r,
                                     size_t r_len)
{
    return sys_cx_ecpoint_double_scalarmul(R, P, Q, k, k_len, r, r_len);
}

cx_err_t cx_ecpoint_export(const cx_ecpoint_t *P,
                           uint8_t *x,
                           size_t x_len,
                           uint8_t *y,
                           size_t y_len)
{
    return sys_cx_ecpoint_export(P, x, x_len, y, y_len);
}

cx_err_t cx_ecpoint_init(cx_ecpoint_t *P,
                         const uint8_t *x,
                         size_t x_len,
                         const uint8_t *y,
                         size_t y_len)
{
    return sys_cx_ecpoint_init(P, x, x_len, y, y_len);
}

cx_err_t cx_ecpoint_neg(cx_ecpoint_t *P)
{
    return sys_cx_ecpoint_neg(P);
}

cx_err_t cx_ecpoint_rnd_scalarmul(cx_ecpoint_t *P, const uint8_t *k, size_t k_len)
{
    return sys_cx_ecpoint_rnd_scalarmul(P, k, k_len);
}

cx_err_t cx_ecpoint_scalarmul(cx_ecpoint_t *P, const uint8_t *k, size_t k_len)
{
    return sys_cx_ecpoint_scalarmul(P, k, k_len);
}

cx_err_t cx_ecpoint_rnd_fixed_scalarmul(cx_ecpoint_t *ec_P, const uint8_t *k, size_t k_len)
{
    return sys_cx_ecpoint_rnd_fixed_scalarmul(ec_P, k, k_len);
}

cx_err_t cx_keccak_init_no_throw(cx_sha3_t *hash, size_t size) {
    cx_keccak_init(hash, size);
    return 0;
}

void os_perso_derive_node_bip32(cx_curve_t curve,
                                const unsigned int *path,
                                unsigned int pathLength,
                                unsigned char *privateKey,
                                unsigned char *chain)
{
    sys_os_perso_derive_node_bip32(curve, path, pathLength, privateKey, chain);
}

cx_err_t cx_bn_add(cx_bn_t r, const cx_bn_t a, const cx_bn_t b)
{
    return sys_cx_bn_add(r, a, b);
}

cx_err_t cx_bn_is_prime(const cx_bn_t n, bool *prime)
{
    return sys_cx_bn_is_prime(n, prime);
}

cx_err_t cx_bn_mod_invert_nprime(cx_bn_t r, const cx_bn_t a, const cx_bn_t n)
{
    return sys_cx_bn_mod_invert_nprime(r, a, n);
}

cx_err_t cx_bn_mod_pow2(cx_bn_t r,
                        const cx_bn_t a,
                        const uint8_t *e,
                        uint32_t e_len,
                        const cx_bn_t n)
{
    return sys_cx_bn_mod_pow2(r, a, e, e_len, n);
}

cx_err_t cx_bn_mod_sub(cx_bn_t r, const cx_bn_t a, const cx_bn_t b, const cx_bn_t n)
{
    return sys_cx_bn_mod_sub(r, a, b, n);
}

cx_err_t cx_bn_mod_u32_invert(cx_bn_t r, uint32_t a, cx_bn_t n)
{
    return sys_cx_bn_mod_u32_invert(r, a, n);
}

cx_err_t cx_bn_mul(cx_bn_t r, const cx_bn_t a, const cx_bn_t b)
{
    return sys_cx_bn_mul(r, a, b);
}

cx_err_t cx_bn_next_prime(cx_bn_t n)
{
    return sys_cx_bn_next_prime(n);
}

cx_err_t cx_bn_sub(cx_bn_t r, const cx_bn_t a, const cx_bn_t b)
{
    return sys_cx_bn_sub(r, a, b);
}

cx_err_t cx_bn_cmp_u32(const cx_bn_t a, uint32_t b, int *diff)
{
    return sys_cx_bn_cmp_u32(a, b, diff);
}

cx_err_t cx_bn_copy(cx_bn_t a, const cx_bn_t b)
{
    return sys_cx_bn_copy(a, b);
}

cx_err_t cx_bn_is_odd(const cx_bn_t n, bool *odd)
{
    return sys_cx_bn_is_odd(n, odd);
}

cx_err_t cx_bn_rng(cx_bn_t r, const cx_bn_t n)
{
    return sys_cx_bn_rng(r, n);
}

cx_err_t cx_bn_set_u32(cx_bn_t x, uint32_t n)
{
    return sys_cx_bn_set_u32(x, n);
}

cx_err_t cx_bn_shr(cx_bn_t x, uint32_t n)
{
    return sys_cx_bn_shr(x, n);
}

cx_err_t cx_ecdomain_parameter(cx_curve_t cv, cx_curve_dom_param_t id, uint8_t *p, uint32_t p_len)
{
    return sys_cx_ecdomain_parameter(cv, id, p, p_len);
}

cx_err_t cx_ecdomain_size(cx_curve_t cv, size_t *length)
{
    return sys_cx_ecdomain_size(cv, length);
}

cx_err_t cx_ecpoint_double_scalarmul_bn(cx_ecpoint_t *R,
                                        cx_ecpoint_t *P,
                                        cx_ecpoint_t *Q,
                                        const cx_bn_t bn_k,
                                        const cx_bn_t bn_r)
{
    return sys_cx_ecpoint_double_scalarmul_bn(R, P, Q, bn_k, bn_r);
}

cx_err_t cx_ecpoint_export_bn(const cx_ecpoint_t *P, cx_bn_t *x, cx_bn_t *y)
{
    return sys_cx_ecpoint_export_bn(P, x, y);
}

cx_err_t cx_ecpoint_is_at_infinity(const cx_ecpoint_t *R, bool *is_infinite)
{
    return sys_cx_ecpoint_is_at_infinity(R, is_infinite);
}

cx_err_t cx_get_random_bytes(uint8_t *buffer, const size_t size)
{
    return sys_cx_get_random_bytes(buffer, size);
}

void os_longjmp(unsigned int exception)
{
    fprintf(stderr, "os_longjmp() called\n");
    fprintf(stderr, "This shouldn't never happen, there's a bug somewhere\n");
    exit(1);
}


cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t curve,
                                        cx_ecfp_public_key_t *pubkey,
                                        cx_ecfp_private_key_t *privkey,
                                        bool keepprivate) {
    return sys_cx_ecfp_generate_pair(curve, pubkey, privkey, keepprivate);
}

cx_err_t cx_ecdsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                       uint32_t                     mode,
                       cx_md_t                      hashID,
                       const uint8_t *              hash,
                       size_t                       hash_len,
                       uint8_t *                    sig,
                       size_t *                     sig_len,
                       uint32_t *                   info) {
    // TODO: this might throw
    *sig_len = sys_cx_ecdsa_sign(pvkey, mode, hashID, hash, hash_len, sig, *sig_len, info);
    return CX_OK;
}

bool cx_ecdsa_verify_no_throw(const cx_ecfp_public_key_t *key,
                     const uint8_t *             hash,
                     size_t                      hash_len,
                     const uint8_t *             sig,
                     size_t                      sig_len) {
    return sys_cx_ecdsa_verify(key,
        0, 0, // unused params
        hash, hash_len, sig, sig_len);
}

cx_err_t cx_math_mult_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len) {
    // TODO: might throw
    sys_cx_math_mult(r, a, b, len);
    return CX_OK;
}

cx_err_t cx_math_multm_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b, const uint8_t *m, size_t len) {
    // TODO: might throw
    sys_cx_math_multm(r, a, b, m, len);
    return CX_OK;
}

cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t             curve,
                                  const uint8_t *        rawkey,
                                  size_t                 key_len,
                                  cx_ecfp_private_key_t *pvkey) {
    sys_cx_ecfp_init_private_key(curve, rawkey, key_len, pvkey);
    return CX_OK;
}

size_t cx_hash_sha256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    if (out_len < CX_SHA256_SIZE) {
        return 0;
    }
    return sys_cx_hash_sha256(in, in_len, out, out_len);
}

size_t cx_hash_ripemd160(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
  if (out_len < CX_RIPEMD160_SIZE) {
    return 0;
  }

  cx_ripemd160_t ripemd160;
  cx_ripemd160_init(&ripemd160);
  spec_cx_ripemd160_update(&ripemd160, in, in_len);
  spec_cx_ripemd160_final(&ripemd160, out);
  return CX_RIPEMD160_SIZE;
}

cx_err_t cx_ripemd160_init_no_throw(cx_ripemd160_t *hash) {
    cx_ripemd160_init(hash);
    return CX_OK;
}

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    cx_sha256_init(hash);
    return CX_OK;
}

cx_err_t cx_sha512_init_no_throw(cx_sha512_t *hash) {
    cx_sha512_init(hash);
    return CX_OK;
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash,
                          uint32_t mode,
                          const uint8_t *in,
                          size_t len,
                          uint8_t *out,
                          size_t out_len) {
    // TODO: might throw
    sys_cx_hash(hash, mode, in, len, out, out_len);
    return CX_OK;
}