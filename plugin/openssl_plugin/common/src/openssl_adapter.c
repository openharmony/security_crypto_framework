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

EC_KEY *Openssl_EC_KEY_new_by_curve_name(int nid)
{
    return EC_KEY_new_by_curve_name(nid);
}

EC_POINT *Openssl_EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group)
{
    return EC_POINT_dup(src, group);
}

int Openssl_EC_KEY_generate_key(EC_KEY *eckey)
{
    return EC_KEY_generate_key(eckey);
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

void Openssl_EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags)
{
    EC_KEY_set_enc_flags(eckey, flags);
}

void Openssl_EC_KEY_free(EC_KEY *key)
{
    EC_KEY_free(key);
}

void Openssl_EC_POINT_free(EC_POINT *point)
{
    EC_POINT_free(point);
}

EVP_MD_CTX *Openssl_EVP_MD_CTX_new(void)
{
    return EVP_MD_CTX_new();
}

void Openssl_EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_free(ctx);
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