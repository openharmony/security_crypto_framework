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

#ifndef HCF_OPENSSL_ADAPTER_H
#define HCF_OPENSSL_ADAPTER_H

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/des.h>
#include <crypto/sm2.h>

#ifdef __cplusplus
extern "C" {
#endif

BIGNUM *Openssl_BN_dup(const BIGNUM *a);
void Openssl_BN_clear(BIGNUM *a);
void Openssl_BN_clear_free(BIGNUM *a);
BIGNUM *Openssl_BN_new(void);
void Openssl_BN_free(BIGNUM *a);
BIGNUM *Openssl_BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *Openssl_BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
int Openssl_BN_bn2binpad(const BIGNUM *a, unsigned char *to, int toLen);
int Openssl_BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int toLen);
BN_CTX *Openssl_BN_CTX_new(void);
void Openssl_BN_CTX_free(BN_CTX *ctx);
int Openssl_BN_num_bytes(const BIGNUM *a);
int Openssl_BN_set_word(BIGNUM *a, unsigned int w);
unsigned int Openssl_BN_get_word(const BIGNUM *a);
int Openssl_BN_num_bits(const BIGNUM *a);
int Openssl_BN_hex2bn(BIGNUM **a, const char *str);
int Openssl_BN_cmp(const BIGNUM *a, const BIGNUM *b);

EC_KEY *Openssl_EC_KEY_new_by_curve_name(int nid);
EC_POINT *Openssl_EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group);
int Openssl_EC_KEY_generate_key(EC_KEY *ecKey);
int Openssl_EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
int Openssl_EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *priv_key);
int Openssl_EC_KEY_check_key(const EC_KEY *key);
const EC_POINT *Openssl_EC_KEY_get0_public_key(const EC_KEY *key);
const BIGNUM *Openssl_EC_KEY_get0_private_key(const EC_KEY *key);
const EC_GROUP *Openssl_EC_KEY_get0_group(const EC_KEY *key);
int Openssl_i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp);
int Openssl_i2d_ECPrivateKey(EC_KEY *key, unsigned char **out);
EC_KEY *Openssl_d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length);
EC_KEY *Openssl_d2i_ECPrivateKey(EC_KEY **key, const unsigned char **in, long len);
void Openssl_EC_KEY_set_asn1_flag(EC_KEY *key, int flag);
void Openssl_EC_KEY_set_enc_flags(EC_KEY *ecKey, unsigned int flags);
void Openssl_EC_KEY_free(EC_KEY *key);
void Openssl_EC_POINT_free(EC_POINT *point);
EC_GROUP *Openssl_EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
void Openssl_EC_GROUP_free(EC_GROUP *group);
EC_POINT *Openssl_EC_POINT_new(const EC_GROUP *group);
int Openssl_EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);
int Openssl_EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *point, const BIGNUM *x,
    const BIGNUM *y, BN_CTX *ctx);
int Openssl_EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator,
    const BIGNUM *order, const BIGNUM *cofactor);
EC_KEY *Openssl_EC_KEY_new(void);
EC_KEY *Openssl_EC_KEY_dup(const EC_KEY *ecKey);
int Openssl_EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
int Openssl_EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
const EC_POINT *Openssl_EC_GROUP_get0_generator(const EC_GROUP *group);
int Openssl_EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group, const EC_POINT *point, BIGNUM *x,
    BIGNUM *y, BN_CTX *ctx);
int Openssl_EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);
int Openssl_EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx);
int Openssl_EC_GROUP_get_degree(const EC_GROUP *group);
EC_GROUP *Openssl_EC_GROUP_dup(const EC_GROUP *a);
void Openssl_EC_GROUP_set_curve_name(EC_GROUP *group, int nid);
int Openssl_EC_GROUP_get_curve_name(const EC_GROUP *group);
int Openssl_EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar, const EC_POINT *point,
    const BIGNUM *p_scalar, BN_CTX *ctx);

EVP_MD_CTX *Openssl_EVP_MD_CTX_new(void);
void Openssl_EVP_MD_CTX_free(EVP_MD_CTX *ctx);
void Openssl_EVP_MD_CTX_set_pkey_ctx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx);
EVP_PKEY_CTX *Openssl_EVP_MD_CTX_get_pkey_ctx(EVP_MD_CTX *ctx);
int Openssl_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int Openssl_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *data, size_t count);
int Openssl_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen);
int Openssl_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int Openssl_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data, size_t count);
int Openssl_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
int Openssl_EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);
int Openssl_EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs,
    size_t tbslen);
int Openssl_EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);
int Openssl_EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs,
    size_t tbslen);

EVP_PKEY *Openssl_EVP_PKEY_new(void);
int Openssl_EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
void Openssl_EVP_PKEY_free(EVP_PKEY *pkey);

EVP_PKEY_CTX *Openssl_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
int Openssl_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int Openssl_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int Openssl_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
void Openssl_EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);

// new added
int Openssl_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
int Openssl_EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
int Openssl_EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int Openssl_EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);

EVP_PKEY_CTX *Openssl_EVP_PKEY_CTX_new_id(int id, ENGINE *e);
int Openssl_EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, int id_len);
int Openssl_EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
int Openssl_EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits);
int Openssl_EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int Openssl_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int Openssl_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int Openssl_EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key);
DSA *Openssl_EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
DSA *Openssl_DSA_new(void);
void Openssl_DSA_free(DSA *dsa);
int Openssl_DSA_up_ref(DSA *dsa);
int Openssl_DSA_set0_pqg(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int Openssl_DSA_set0_key(DSA *dsa, BIGNUM *pub_key, BIGNUM *pri_key);
const BIGNUM *Openssl_DSA_get0_p(const DSA *dsa);
const BIGNUM *Openssl_DSA_get0_q(const DSA *dsa);
const BIGNUM *Openssl_DSA_get0_g(const DSA *dsa);
const BIGNUM *Openssl_DSA_get0_pub_key(const DSA *dsa);
const BIGNUM *Openssl_DSA_get0_priv_key(const DSA *dsa);
int Openssl_DSA_generate_key(DSA *a);
DSA *Openssl_d2i_DSA_PUBKEY(DSA **dsa, const unsigned char **ppin, long length);
DSA *Openssl_d2i_DSAPrivateKey(DSA **dsa, const unsigned char **ppin, long length);
int Openssl_i2d_DSA_PUBKEY(DSA *dsa, unsigned char **ppout);
int Openssl_i2d_DSAPrivateKey(DSA *dsa, unsigned char **ppout);

RSA *Openssl_RSA_new(void);
void Openssl_RSA_free(RSA *rsa);
int Openssl_RSA_generate_multi_prime_key(RSA *rsa, int bits, int primes,
    BIGNUM *e, BN_GENCB *cb);
int Openssl_RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
int Openssl_RSA_bits(const RSA *rsa);
int Openssl_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
void Openssl_RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
const BIGNUM *Openssl_RSA_get0_n(const RSA *d);
const BIGNUM *Openssl_RSA_get0_e(const RSA *d);
const BIGNUM *Openssl_RSA_get0_d(const RSA *d);
void Openssl_RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
RSA *Openssl_RSAPublicKey_dup(RSA *rsa);
RSA *Openssl_RSAPrivateKey_dup(RSA *rsa);
RSA *Openssl_d2i_RSA_PUBKEY(RSA **a, const unsigned char **pp, long length);
int Openssl_i2d_RSA_PUBKEY(RSA *a, unsigned char **pp);
int Openssl_EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen);
int Openssl_EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen);
int Openssl_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad);
int Openssl_EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int Openssl_EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int Openssl_EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *ctx, void *label, int len);
int Openssl_EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char **label);
EVP_PKEY *Openssl_d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length);
struct rsa_st *Openssl_EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
int Openssl_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);
int Openssl_EVP_PKEY_assign_RSA(EVP_PKEY *pkey, struct rsa_st *key);
int Openssl_i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
    char *kstr, int klen, pem_password_cb *cb, void *u);
// BIO
BIO *Openssl_BIO_new(const BIO_METHOD *type);
const BIO_METHOD *Openssl_BIO_s_mem(void);
int Openssl_BIO_read(BIO *b, void *data, int dlen);
void Openssl_BIO_free_all(BIO *a);

int Openssl_RAND_priv_bytes(unsigned char *buf, int num);
void Openssl_RAND_seed(const void *buf, int num);

const EVP_MD *Openssl_EVP_sha1(void);
const EVP_MD *Openssl_EVP_sha224(void);
const EVP_MD *Openssl_EVP_sha256(void);
const EVP_MD *Openssl_EVP_sha384(void);
const EVP_MD *Openssl_EVP_sha512(void);
const EVP_MD *Openssl_EVP_md5(void);
const EVP_MD *Openssl_EVP_sm3(void);
int Openssl_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size);
int Openssl_EVP_MD_CTX_size(const EVP_MD_CTX *ctx);
int Openssl_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);

int Openssl_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
int Openssl_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
size_t Openssl_HMAC_size(const HMAC_CTX *ctx);
void Openssl_HMAC_CTX_free(HMAC_CTX *ctx);
HMAC_CTX *Openssl_HMAC_CTX_new(void);

void Openssl_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
const EVP_CIPHER *Openssl_EVP_aes_128_ecb(void);
const EVP_CIPHER *Openssl_EVP_aes_192_ecb(void);
const EVP_CIPHER *Openssl_EVP_aes_256_ecb(void);
const EVP_CIPHER *Openssl_EVP_aes_128_cbc(void);
const EVP_CIPHER *Openssl_EVP_aes_192_cbc(void);
const EVP_CIPHER *Openssl_EVP_aes_256_cbc(void);
const EVP_CIPHER *Openssl_EVP_aes_128_ctr(void);
const EVP_CIPHER *Openssl_EVP_aes_192_ctr(void);
const EVP_CIPHER *Openssl_EVP_aes_256_ctr(void);
const EVP_CIPHER *Openssl_EVP_aes_128_ofb(void);
const EVP_CIPHER *Openssl_EVP_aes_192_ofb(void);
const EVP_CIPHER *Openssl_EVP_aes_256_ofb(void);
const EVP_CIPHER *Openssl_EVP_aes_128_cfb(void);
const EVP_CIPHER *Openssl_EVP_aes_192_cfb(void);
const EVP_CIPHER *Openssl_EVP_aes_256_cfb(void);
const EVP_CIPHER *Openssl_EVP_aes_128_cfb1(void);
const EVP_CIPHER *Openssl_EVP_aes_192_cfb1(void);
const EVP_CIPHER *Openssl_EVP_aes_256_cfb1(void);
const EVP_CIPHER *Openssl_EVP_aes_128_cfb128(void);
const EVP_CIPHER *Openssl_EVP_aes_192_cfb128(void);
const EVP_CIPHER *Openssl_EVP_aes_256_cfb128(void);
const EVP_CIPHER *Openssl_EVP_aes_128_cfb8(void);
const EVP_CIPHER *Openssl_EVP_aes_192_cfb8(void);
const EVP_CIPHER *Openssl_EVP_aes_256_cfb8(void);
const EVP_CIPHER *Openssl_EVP_aes_128_ccm(void);
const EVP_CIPHER *Openssl_EVP_aes_192_ccm(void);
const EVP_CIPHER *Openssl_EVP_aes_256_ccm(void);
const EVP_CIPHER *Openssl_EVP_aes_128_gcm(void);
const EVP_CIPHER *Openssl_EVP_aes_192_gcm(void);
const EVP_CIPHER *Openssl_EVP_aes_256_gcm(void);
const EVP_CIPHER *Openssl_EVP_sm4_ecb(void);
const EVP_CIPHER *Openssl_EVP_sm4_cbc(void);
const EVP_CIPHER *Openssl_EVP_sm4_cfb(void);
const EVP_CIPHER *Openssl_EVP_sm4_cfb128(void);
const EVP_CIPHER *Openssl_EVP_sm4_ctr(void);
const EVP_CIPHER *Openssl_EVP_sm4_ofb(void);
const EVP_CIPHER *Openssl_EVP_des_ede3_ecb(void);
const EVP_CIPHER *Openssl_EVP_des_ede3_cbc(void);
const EVP_CIPHER *Openssl_EVP_des_ede3_ofb(void);
const EVP_CIPHER *Openssl_EVP_des_ede3_cfb64(void);
const EVP_CIPHER *Openssl_EVP_des_ede3_cfb1(void);
const EVP_CIPHER *Openssl_EVP_des_ede3_cfb8(void);
EVP_CIPHER_CTX *Openssl_EVP_CIPHER_CTX_new(void);
int Openssl_EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv, int enc);
int Openssl_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad);
int Openssl_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int Openssl_EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int Openssl_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);

int Openssl_sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msgLen, size_t *cipherTextSize);
int Openssl_sm2_plaintext_size(const unsigned char *cipherText, size_t cipherTextSize, size_t *plainTextSize);
int Openssl_sm2_encrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *msg,
                        size_t msgLen, uint8_t *cipherTextBuf, size_t *cipherTextLen);

int Openssl_sm2_decrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *cipherText,
                        size_t cipherTextLen, uint8_t *plainTextBuf, size_t *plainTextLen);

int Openssl_PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt,
    int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out);

EC_GROUP *Openssl_EC_GROUP_new_by_curve_name(int nid);

int OPENSSL_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

#ifdef __cplusplus
}
#endif

#endif