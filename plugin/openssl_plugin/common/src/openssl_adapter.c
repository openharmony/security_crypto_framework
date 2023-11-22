/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "openssl_adapter.h"

#include "log.h"
#include "result.h"

BIGNUM *Openssl_BN_dup(const BIGNUM *a)
{
    return BN_dup(a);
}

void Openssl_BN_clear(BIGNUM *a)
{
    BN_clear(a);
}

void Openssl_BN_clear_free(BIGNUM *a)
{
    BN_clear_free(a);
}

BIGNUM *Openssl_BN_new(void)
{
    return BN_new();
}

void Openssl_BN_free(BIGNUM *a)
{
    BN_free(a);
}

BIGNUM *Openssl_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    return BN_bin2bn(s, len, ret);
}

BIGNUM *Openssl_BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    return BN_lebin2bn(s, len, ret);
}

int Openssl_BN_bn2binpad(const BIGNUM *a, unsigned char *to, int toLen)
{
    return BN_bn2binpad(a, to, toLen);
}

int Openssl_BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int toLen)
{
    return BN_bn2lebinpad(a, to, toLen);
}

BN_CTX *Openssl_BN_CTX_new(void)
{
    return BN_CTX_new();
}

void Openssl_BN_CTX_free(BN_CTX *ctx)
{
    BN_CTX_free(ctx);
}

int Openssl_BN_num_bytes(const BIGNUM *a)
{
    return BN_num_bytes(a);
}

int Openssl_BN_set_word(BIGNUM *a, unsigned int w)
{
    return BN_set_word(a, w);
}

unsigned int Openssl_BN_get_word(const BIGNUM *a)
{
    return BN_get_word(a);
}

int Openssl_BN_num_bits(const BIGNUM *a)
{
    return BN_num_bits(a);
}

int Openssl_BN_hex2bn(BIGNUM **a, const char *str)
{
    return BN_hex2bn(a, str);
}

int Openssl_BN_cmp(const BIGNUM *a, const BIGNUM *b)
{
    return BN_cmp(a, b);
}

EC_KEY *Openssl_EC_KEY_new_by_curve_name(int nid)
{
    return EC_KEY_new_by_curve_name(nid);
}

EC_POINT *Openssl_EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group)
{
    return EC_POINT_dup(src, group);
}

int Openssl_EC_KEY_generate_key(EC_KEY *ecKey)
{
    return EC_KEY_generate_key(ecKey);
}

int Openssl_EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub)
{
    return EC_KEY_set_public_key(key, pub);
}

int Openssl_EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *priv_key)
{
    return EC_KEY_set_private_key(key, priv_key);
}

int Openssl_EC_KEY_check_key(const EC_KEY *key)
{
    return EC_KEY_check_key(key);
}

const EC_POINT *Openssl_EC_KEY_get0_public_key(const EC_KEY *key)
{
    return EC_KEY_get0_public_key(key);
}

const BIGNUM *Openssl_EC_KEY_get0_private_key(const EC_KEY *key)
{
    return EC_KEY_get0_private_key(key);
}

const EC_GROUP *Openssl_EC_KEY_get0_group(const EC_KEY *key)
{
    return EC_KEY_get0_group(key);
}

int Openssl_i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp)
{
    return i2d_EC_PUBKEY(a, pp);
}

int Openssl_i2d_ECPrivateKey(EC_KEY *key, unsigned char **out)
{
    return i2d_ECPrivateKey(key, out);
}

EC_KEY *Openssl_d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length)
{
    return d2i_EC_PUBKEY(a, pp, length);
}

EC_KEY *Openssl_d2i_ECPrivateKey(EC_KEY **key, const unsigned char **in, long len)
{
    return d2i_ECPrivateKey(key, in, len);
}

void Openssl_EC_KEY_set_asn1_flag(EC_KEY *key, int flag)
{
    EC_KEY_set_asn1_flag(key, flag);
}

void Openssl_EC_KEY_set_enc_flags(EC_KEY *ecKey, unsigned int flags)
{
    EC_KEY_set_enc_flags(ecKey, flags);
}

void Openssl_EC_KEY_free(EC_KEY *key)
{
    EC_KEY_free(key);
}

void Openssl_EC_POINT_free(EC_POINT *point)
{
    EC_POINT_free(point);
}

EC_GROUP *Openssl_EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    return EC_GROUP_new_curve_GFp(p, a, b, ctx);
}

void Openssl_EC_GROUP_free(EC_GROUP *group)
{
    EC_GROUP_free(group);
}

EC_POINT *Openssl_EC_POINT_new(const EC_GROUP *group)
{
    return EC_POINT_new(group);
}

int Openssl_EC_POINT_copy(EC_POINT *dst, const EC_POINT *src)
{
    return EC_POINT_copy(dst, src);
}

int Openssl_EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *point, const BIGNUM *x,
    const BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx);
}

int Openssl_EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order,
    const BIGNUM *cofactor)
{
    return EC_GROUP_set_generator(group, generator, order, cofactor);
}

EC_KEY *Openssl_EC_KEY_new(void)
{
    return EC_KEY_new();
}

EC_KEY *Openssl_EC_KEY_dup(const EC_KEY *ecKey)
{
    return EC_KEY_dup(ecKey);
}

int Openssl_EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group)
{
    return EC_KEY_set_group(key, group);
}

int Openssl_EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
{
    return EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
}

const EC_POINT *Openssl_EC_GROUP_get0_generator(const EC_GROUP *group)
{
    return EC_GROUP_get0_generator(group);
}

int Openssl_EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group, const EC_POINT *point, BIGNUM *x,
    BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx);
}

int Openssl_EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx)
{
    return EC_GROUP_get_order(group, order, ctx);
}

int Openssl_EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx)
{
    return EC_GROUP_get_cofactor(group, cofactor, ctx);
}

int Openssl_EC_GROUP_get_degree(const EC_GROUP *group)
{
    return EC_GROUP_get_degree(group);
}

EC_GROUP *Openssl_EC_GROUP_dup(const EC_GROUP *a)
{
    return EC_GROUP_dup(a);
}

void Openssl_EC_GROUP_set_curve_name(EC_GROUP *group, int nid)
{
    EC_GROUP_set_curve_name(group, nid);
}

int Openssl_EC_GROUP_get_curve_name(const EC_GROUP *group)
{
    return EC_GROUP_get_curve_name(group);
}

int Openssl_EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar, const EC_POINT *point,
    const BIGNUM *p_scalar, BN_CTX *ctx)
{
    return EC_POINT_mul(group, r, g_scalar, point, p_scalar, ctx);
}

EVP_MD_CTX *Openssl_EVP_MD_CTX_new(void)
{
    return EVP_MD_CTX_new();
}

void Openssl_EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_free(ctx);
}

void Openssl_EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx)
{
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
}

EVP_PKEY_CTX *Openssl_EVP_MD_CTX_get_pkey_ctx(EVP_MD_CTX *ctx)
{
    return EVP_MD_CTX_get_pkey_ctx(ctx);
}

int Openssl_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
    return EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

int Openssl_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return EVP_DigestSignUpdate(ctx, data, count);
}

int Openssl_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen)
{
    return EVP_DigestSignFinal(ctx, sigret, siglen);
}

int Openssl_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
    return EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

int Openssl_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return EVP_DigestVerifyUpdate(ctx, data, count);
}

int Openssl_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen)
{
    return EVP_DigestVerifyFinal(ctx, sig, siglen);
}

int Openssl_EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_sign_init(ctx);
}

int Openssl_EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs,
    size_t tbslen)
{
    return EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen);
}

int Openssl_EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_verify_init(ctx);
}

int Openssl_EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs,
    size_t tbslen)
{
    return EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
}

EVP_PKEY *Openssl_EVP_PKEY_new(void)
{
    return EVP_PKEY_new();
}

int Openssl_EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key)
{
    return EVP_PKEY_assign_EC_KEY(pkey, key);
}

void Openssl_EVP_PKEY_free(EVP_PKEY *pkey)
{
    EVP_PKEY_free(pkey);
}

EVP_PKEY_CTX *Openssl_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
{
    return EVP_PKEY_CTX_new(pkey, e);
}

int Openssl_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_derive_init(ctx);
}

int Openssl_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{
    return EVP_PKEY_derive_set_peer(ctx, peer);
}

int Openssl_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    return EVP_PKEY_derive(ctx, key, keylen);
}

void Openssl_EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_CTX_free(ctx);
}

int Openssl_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    return EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);
}

int Openssl_EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    return EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);
}

int Openssl_EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_encrypt_init(ctx);
}

int Openssl_EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_decrypt_init(ctx);
}

EVP_PKEY_CTX *Openssl_EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
    return EVP_PKEY_CTX_new_id(id, e);
}

int Openssl_EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, int id_len)
{
    return EVP_PKEY_CTX_set1_id(ctx, id, id_len);
}

int Openssl_EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_paramgen_init(ctx);
}

int Openssl_EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits)
{
    return EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits);
}

int Openssl_EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    return EVP_PKEY_paramgen(ctx, ppkey);
}

int Openssl_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_keygen_init(ctx);
}

int Openssl_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    return EVP_PKEY_keygen(ctx, ppkey);
}

int Openssl_EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key)
{
    return EVP_PKEY_set1_DSA(pkey, key);
}

DSA *Openssl_EVP_PKEY_get1_DSA(EVP_PKEY *pkey)
{
    return EVP_PKEY_get1_DSA(pkey);
}

DSA *Openssl_DSA_new(void)
{
    return DSA_new();
}

void Openssl_DSA_free(DSA *dsa)
{
    DSA_free(dsa);
}

int Openssl_DSA_up_ref(DSA *dsa)
{
    return DSA_up_ref(dsa);
}

int Openssl_DSA_set0_pqg(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    return DSA_set0_pqg(dsa, p, q, g);
}

int Openssl_DSA_set0_key(DSA *dsa, BIGNUM *pub_key, BIGNUM *pri_key)
{
    return DSA_set0_key(dsa, pub_key, pri_key);
}

const BIGNUM *Openssl_DSA_get0_p(const DSA *dsa)
{
    return DSA_get0_p(dsa);
}

const BIGNUM *Openssl_DSA_get0_q(const DSA *dsa)
{
    return DSA_get0_q(dsa);
}

const BIGNUM *Openssl_DSA_get0_g(const DSA *dsa)
{
    return DSA_get0_g(dsa);
}

const BIGNUM *Openssl_DSA_get0_pub_key(const DSA *dsa)
{
    return DSA_get0_pub_key(dsa);
}

const BIGNUM *Openssl_DSA_get0_priv_key(const DSA *dsa)
{
    return DSA_get0_priv_key(dsa);
}

int Openssl_DSA_generate_key(DSA *a)
{
    return DSA_generate_key(a);
}

DSA *Openssl_d2i_DSA_PUBKEY(DSA **dsa, const unsigned char **ppin, long length)
{
    return d2i_DSA_PUBKEY(dsa, ppin, length);
}

DSA *Openssl_d2i_DSAPrivateKey(DSA **dsa, const unsigned char **ppin, long length)
{
    return d2i_DSAPrivateKey(dsa, ppin, length);
}

int Openssl_i2d_DSA_PUBKEY(DSA *dsa, unsigned char **ppout)
{
    return i2d_DSA_PUBKEY(dsa, ppout);
}

int Openssl_i2d_DSAPrivateKey(DSA *dsa, unsigned char **ppout)
{
    return i2d_DSAPrivateKey(dsa, ppout);
}

RSA *Openssl_RSA_new(void)
{
    return RSA_new();
}

void Openssl_RSA_free(RSA *rsa)
{
    RSA_free(rsa);
}

int Openssl_RSA_generate_multi_prime_key(RSA *rsa, int bits, int primes,
    BIGNUM *e, BN_GENCB *cb)
{
    return RSA_generate_multi_prime_key(rsa, bits, primes, e, cb);
}

int Openssl_RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    return RSA_generate_key_ex(rsa, bits, e, cb);
}

int Openssl_RSA_bits(const RSA *rsa)
{
    return RSA_bits(rsa);
}

int Openssl_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    return RSA_set0_key(r, n, e, d);
}

void Openssl_RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    RSA_get0_key(r, n, e, d);
}

const BIGNUM *Openssl_RSA_get0_n(const RSA *d)
{
    return RSA_get0_n(d);
}

const BIGNUM *Openssl_RSA_get0_e(const RSA *d)
{
    return RSA_get0_e(d);
}

const BIGNUM *Openssl_RSA_get0_d(const RSA *d)
{
    return RSA_get0_d(d);
}

void Openssl_RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    RSA_get0_factors(r, p, q);
}

RSA *Openssl_RSAPublicKey_dup(RSA *rsa)
{
    return RSAPublicKey_dup(rsa);
}

RSA *Openssl_RSAPrivateKey_dup(RSA *rsa)
{
    return RSAPrivateKey_dup(rsa);
}

RSA *Openssl_d2i_RSA_PUBKEY(RSA **a, const unsigned char **pp, long length)
{
    return d2i_RSA_PUBKEY(a, pp, length);
}

int Openssl_i2d_RSA_PUBKEY(RSA *a, unsigned char **pp)
{
    return i2d_RSA_PUBKEY(a, pp);
}

int Openssl_EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen)
{
    return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen);
}

int Openssl_EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen)
{
    return EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, saltlen);
}

int Openssl_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad)
{
    return EVP_PKEY_CTX_set_rsa_padding(ctx, pad);
}

int Openssl_EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    return EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md);
}

int Openssl_EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    return EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md);
}

int Openssl_EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *ctx, void *label, int len)
{
    return EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, len);
}

int Openssl_EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char **label)
{
    return EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, label);
}

EVP_PKEY *Openssl_d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length)
{
    return d2i_AutoPrivateKey(a, pp, length);
}

struct rsa_st *Openssl_EVP_PKEY_get1_RSA(EVP_PKEY *pkey)
{
    return EVP_PKEY_get1_RSA(pkey);
}

int Openssl_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key)
{
    return EVP_PKEY_set1_RSA(pkey, key);
}

int Openssl_EVP_PKEY_assign_RSA(EVP_PKEY *pkey, struct rsa_st *key)
{
    return EVP_PKEY_assign_RSA(pkey, key);
}

int Openssl_i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
    char *kstr, int klen, pem_password_cb *cb, void *u)
{
    return i2d_PKCS8PrivateKey_bio(bp, x, enc, kstr, klen, cb, u);
}

BIO *Openssl_BIO_new(const BIO_METHOD *type)
{
    return BIO_new(type);
}

const BIO_METHOD *Openssl_BIO_s_mem(void)
{
    return BIO_s_mem();
}

int Openssl_BIO_read(BIO *b, void *data, int dlen)
{
    return BIO_read(b, data, dlen);
}

void Openssl_BIO_free_all(BIO *a)
{
    return BIO_free_all(a);
}

int Openssl_RAND_priv_bytes(unsigned char *buf, int num)
{
    return RAND_priv_bytes(buf, num);
}

void Openssl_RAND_seed(const void *buf, int num)
{
    RAND_seed(buf, num);
}

const EVP_MD *Openssl_EVP_sha1(void)
{
    return EVP_sha1();
}

const EVP_MD *Openssl_EVP_sha224(void)
{
    return EVP_sha224();
}

const EVP_MD *Openssl_EVP_sha256(void)
{
    return EVP_sha256();
}

const EVP_MD *Openssl_EVP_sha384(void)
{
    return EVP_sha384();
}

const EVP_MD *Openssl_EVP_sha512(void)
{
    return EVP_sha512();
}

const EVP_MD *Openssl_EVP_md5(void)
{
    return EVP_md5();
}

const EVP_MD *Openssl_EVP_sm3(void)
{
    return EVP_sm3();
}

int Openssl_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
    return EVP_DigestFinal_ex(ctx, md, size);
}

int Openssl_EVP_MD_CTX_size(const EVP_MD_CTX *ctx)
{
    return EVP_MD_CTX_size(ctx);
}

int Openssl_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    return EVP_DigestInit_ex(ctx, type, impl);
}

int Openssl_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl)
{
    return HMAC_Init_ex(ctx, key, len, md, impl);
}

int Openssl_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
    return HMAC_Final(ctx, md, len);
}

size_t Openssl_HMAC_size(const HMAC_CTX *ctx)
{
    return HMAC_size(ctx);
}

void Openssl_HMAC_CTX_free(HMAC_CTX *ctx)
{
    HMAC_CTX_free(ctx);
}

HMAC_CTX *Openssl_HMAC_CTX_new(void)
{
    return HMAC_CTX_new();
}

void Openssl_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

const EVP_CIPHER *Openssl_EVP_aes_128_ecb(void)
{
    return EVP_aes_128_ecb();
}

const EVP_CIPHER *Openssl_EVP_aes_192_ecb(void)
{
    return EVP_aes_192_ecb();
}

const EVP_CIPHER *Openssl_EVP_aes_256_ecb(void)
{
    return EVP_aes_256_ecb();
}

const EVP_CIPHER *Openssl_EVP_aes_128_cbc(void)
{
    return EVP_aes_128_cbc();
}

const EVP_CIPHER *Openssl_EVP_aes_192_cbc(void)
{
    return EVP_aes_192_cbc();
}

const EVP_CIPHER *Openssl_EVP_aes_256_cbc(void)
{
    return EVP_aes_256_cbc();
}

const EVP_CIPHER *Openssl_EVP_aes_128_ctr(void)
{
    return EVP_aes_128_ctr();
}

const EVP_CIPHER *Openssl_EVP_aes_192_ctr(void)
{
    return EVP_aes_192_ctr();
}

const EVP_CIPHER *Openssl_EVP_aes_256_ctr(void)
{
    return EVP_aes_256_ctr();
}

const EVP_CIPHER *Openssl_EVP_aes_128_ofb(void)
{
    return EVP_aes_128_ofb();
}

const EVP_CIPHER *Openssl_EVP_aes_192_ofb(void)
{
    return EVP_aes_192_ofb();
}

const EVP_CIPHER *Openssl_EVP_aes_256_ofb(void)
{
    return EVP_aes_256_ofb();
}

const EVP_CIPHER *Openssl_EVP_aes_128_cfb(void)
{
    return EVP_aes_128_cfb();
}

const EVP_CIPHER *Openssl_EVP_aes_192_cfb(void)
{
    return EVP_aes_192_cfb();
}

const EVP_CIPHER *Openssl_EVP_aes_256_cfb(void)
{
    return EVP_aes_256_cfb();
}

const EVP_CIPHER *Openssl_EVP_aes_128_cfb1(void)
{
    return EVP_aes_128_cfb1();
}

const EVP_CIPHER *Openssl_EVP_aes_192_cfb1(void)
{
    return EVP_aes_192_cfb1();
}

const EVP_CIPHER *Openssl_EVP_aes_256_cfb1(void)
{
    return EVP_aes_256_cfb1();
}

const EVP_CIPHER *Openssl_EVP_aes_128_cfb128(void)
{
    return EVP_aes_128_cfb128();
}

const EVP_CIPHER *Openssl_EVP_aes_192_cfb128(void)
{
    return EVP_aes_192_cfb128();
}

const EVP_CIPHER *Openssl_EVP_aes_256_cfb128(void)
{
    return EVP_aes_256_cfb128();
}

const EVP_CIPHER *Openssl_EVP_aes_128_cfb8(void)
{
    return EVP_aes_128_cfb8();
}

const EVP_CIPHER *Openssl_EVP_aes_192_cfb8(void)
{
    return EVP_aes_192_cfb8();
}

const EVP_CIPHER *Openssl_EVP_aes_256_cfb8(void)
{
    return EVP_aes_256_cfb8();
}

const EVP_CIPHER *Openssl_EVP_aes_128_ccm(void)
{
    return EVP_aes_128_ccm();
}

const EVP_CIPHER *Openssl_EVP_aes_192_ccm(void)
{
    return EVP_aes_192_ccm();
}

const EVP_CIPHER *Openssl_EVP_aes_256_ccm(void)
{
    return EVP_aes_256_ccm();
}

const EVP_CIPHER *Openssl_EVP_aes_128_gcm(void)
{
    return EVP_aes_128_gcm();
}

const EVP_CIPHER *Openssl_EVP_aes_192_gcm(void)
{
    return EVP_aes_192_gcm();
}

const EVP_CIPHER *Openssl_EVP_aes_256_gcm(void)
{
    return EVP_aes_256_gcm();
}

const EVP_CIPHER *Openssl_EVP_sm4_ecb(void)
{
    return EVP_sm4_ecb();
}

const EVP_CIPHER *Openssl_EVP_sm4_cbc(void)
{
    return EVP_sm4_cbc();
}

const EVP_CIPHER *Openssl_EVP_sm4_cfb(void)
{
    return EVP_sm4_cfb();
}

const EVP_CIPHER *Openssl_EVP_sm4_cfb128(void)
{
    return EVP_sm4_cfb128();
}

const EVP_CIPHER *Openssl_EVP_sm4_ctr(void)
{
    return EVP_sm4_ctr();
}

const EVP_CIPHER *Openssl_EVP_sm4_ofb(void)
{
    return EVP_sm4_ofb();
}

EVP_CIPHER_CTX *Openssl_EVP_CIPHER_CTX_new(void)
{
    return EVP_CIPHER_CTX_new();
}

int Openssl_EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv, int enc)
{
    return EVP_CipherInit(ctx, cipher, key, iv, enc);
}

int Openssl_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad)
{
    return EVP_CIPHER_CTX_set_padding(ctx, pad);
}

int Openssl_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    return EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);
}

int Openssl_EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    return EVP_CipherFinal_ex(ctx, out, outl);
}

int Openssl_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    return EVP_CipherUpdate(ctx, out, outl, in, inl);
}

const EVP_CIPHER *Openssl_EVP_des_ede3_ecb(void)
{
    return EVP_des_ede3_ecb();
}

const EVP_CIPHER *Openssl_EVP_des_ede3_cbc(void)
{
    return EVP_des_ede3_cbc();
}

const EVP_CIPHER *Openssl_EVP_des_ede3_ofb(void)
{
    return EVP_des_ede3_ofb();
}

const EVP_CIPHER *Openssl_EVP_des_ede3_cfb64(void)
{
    return EVP_des_ede3_cfb64();
}

const EVP_CIPHER *Openssl_EVP_des_ede3_cfb1(void)
{
    return EVP_des_ede3_cfb1();
}

const EVP_CIPHER *Openssl_EVP_des_ede3_cfb8(void)
{
    return EVP_des_ede3_cfb8();
}

int Openssl_sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msgLen, size_t *cipherTextSize)
{
    return ossl_sm2_ciphertext_size(key, digest, msgLen, cipherTextSize);
}

int Openssl_sm2_plaintext_size(const unsigned char *cipherText, size_t cipherTextSize, size_t *plainTextSize)
{
    return ossl_sm2_plaintext_size(cipherText, cipherTextSize, plainTextSize);
}

int Openssl_sm2_encrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *msg,
                        size_t msgLen, uint8_t *cipherTextBuf, size_t *cipherTextLen)
{
    return ossl_sm2_encrypt(key, digest, msg, msgLen, cipherTextBuf, cipherTextLen);
}

int Openssl_sm2_decrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *cipherText,
                        size_t cipherTextLen, uint8_t *plainTextBuf, size_t *plainTextLen)
{
    return ossl_sm2_decrypt(key, digest, cipherText, cipherTextLen, plainTextBuf, plainTextLen);
}

int Openssl_PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt,
    int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out)
{
    return PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, digest, keylen, out);
}

EC_GROUP *Openssl_EC_GROUP_new_by_curve_name(int nid)
{
    return EC_GROUP_new_by_curve_name(nid);
}

int OPENSSL_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    return EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);
}