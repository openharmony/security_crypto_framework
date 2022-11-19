/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifdef __cplusplus
extern "C" {
#endif

BIGNUM *Openssl_BN_dup(const BIGNUM *a);
void Openssl_BN_clear(BIGNUM *a);
void Openssl_BN_clear_free(BIGNUM *a);

EC_KEY *Openssl_EC_KEY_new_by_curve_name(int nid);
EC_POINT *Openssl_EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group);
int Openssl_EC_KEY_generate_key(EC_KEY *eckey);
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
void Openssl_EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags);
void Openssl_EC_KEY_free(EC_KEY *key);
void Openssl_EC_POINT_free(EC_POINT *point);

EVP_MD_CTX *Openssl_EVP_MD_CTX_new(void);
void Openssl_EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int Openssl_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int Openssl_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *data, size_t count);
int Openssl_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen);
int Openssl_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int Openssl_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data, size_t count);
int Openssl_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);

EVP_PKEY *Openssl_EVP_PKEY_new(void);
int Openssl_EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
void Openssl_EVP_PKEY_free(EVP_PKEY *pkey);

EVP_PKEY_CTX *Openssl_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
int Openssl_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int Openssl_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int Openssl_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
void Openssl_EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif
