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
#include "openssl_adapter_mock.h"

#include "log.h"
#include "result.h"

static uint32_t g_mockIndex = __INT32_MAX__;
static uint32_t g_callNum = 0;
static bool g_isRecordCallNum = false;
static bool g_isNeedSpecialMock = false;

static bool Is_Need_Mock(void)
{
    if (!g_isRecordCallNum) {
        return false;
    }
    g_callNum++;
    if (g_callNum == g_mockIndex) {
        LOGI("mock malloc return NULL.");
        return true;
    }
    return false;
}

void StartRecordOpensslCallNum(void)
{
    ResetOpensslCallNum();
    g_isRecordCallNum = true;
}

void EndRecordOpensslCallNum(void)
{
    ResetOpensslCallNum();
    g_isRecordCallNum = false;
}

uint32_t GetOpensslCallNum(void)
{
    return g_callNum;
}

void ResetOpensslCallNum(void)
{
    g_callNum = 0;
    g_mockIndex = __INT32_MAX__;
}

void SetOpensslCallMockIndex(uint32_t index)
{
    g_mockIndex = index;
}

BIGNUM *Openssl_BN_dup(const BIGNUM *a)
{
    if (Is_Need_Mock()) {
        return NULL;
    }
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
    if (Is_Need_Mock()) {
        return NULL;
    }
    return EC_KEY_new_by_curve_name(nid);
}

EC_POINT *Openssl_EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group)
{
    if (Is_Need_Mock()) {
        return NULL;
    }
    return EC_POINT_dup(src, group);
}

int Openssl_EC_KEY_generate_key(EC_KEY *eckey)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EC_KEY_generate_key(eckey);
}

int Openssl_EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EC_KEY_set_public_key(key, pub);
}

int Openssl_EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *priv_key)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EC_KEY_set_private_key(key, priv_key);
}

int Openssl_EC_KEY_check_key(const EC_KEY *key)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EC_KEY_check_key(key);
}

const EC_POINT *Openssl_EC_KEY_get0_public_key(const EC_KEY *key)
{
    if (Is_Need_Mock()) {
        return NULL;
    }
    return EC_KEY_get0_public_key(key);
}

const BIGNUM *Openssl_EC_KEY_get0_private_key(const EC_KEY *key)
{
    if (Is_Need_Mock()) {
        return NULL;
    }
    return EC_KEY_get0_private_key(key);
}

const EC_GROUP *Openssl_EC_KEY_get0_group(const EC_KEY *key)
{
    if (Is_Need_Mock()) {
        return NULL;
    }
    return EC_KEY_get0_group(key);
}

int Openssl_i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return i2d_EC_PUBKEY(a, pp);
}

int Openssl_i2d_ECPrivateKey(EC_KEY *key, unsigned char **out)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return i2d_ECPrivateKey(key, out);
}

EC_KEY *Openssl_d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length)
{
    if (Is_Need_Mock()) {
        return NULL;
    }
    return d2i_EC_PUBKEY(a, pp, length);
}

EC_KEY *Openssl_d2i_ECPrivateKey(EC_KEY **key, const unsigned char **in, long len)
{
    if (Is_Need_Mock()) {
        return NULL;
    }
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
    if (Is_Need_Mock()) {
        return NULL;
    }
    return EVP_MD_CTX_new();
}

void Openssl_EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_free(ctx);
}

int Openssl_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

int Openssl_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EVP_DigestSignUpdate(ctx, data, count);
}

int Openssl_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen)
{
    if (sigret != NULL && g_isNeedSpecialMock) {
        g_callNum++;
    }
    if (Is_Need_Mock()) {
        if (sigret == NULL) {
            return -1;
        }
        if (g_isNeedSpecialMock) {
            int res = EVP_DigestSignFinal(ctx, sigret, siglen);
            *siglen = *siglen * 2;
            g_isNeedSpecialMock = false;
            return res;
        }
        g_isNeedSpecialMock = true;
        return -1;
    }
    if (sigret != NULL) {
        g_callNum++;
    }
    return EVP_DigestSignFinal(ctx, sigret, siglen);
}

int Openssl_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

int Openssl_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EVP_DigestVerifyUpdate(ctx, data, count);
}

int Openssl_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EVP_DigestVerifyFinal(ctx, sig, siglen);
}

EVP_PKEY *Openssl_EVP_PKEY_new(void)
{
    if (Is_Need_Mock()) {
        return NULL;
    }
    return EVP_PKEY_new();
}

int Openssl_EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EVP_PKEY_assign_EC_KEY(pkey, key);
}

void Openssl_EVP_PKEY_free(EVP_PKEY *pkey)
{
    EVP_PKEY_free(pkey);
}

EVP_PKEY_CTX *Openssl_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
{
    if (Is_Need_Mock()) {
        return NULL;
    }
    return EVP_PKEY_CTX_new(pkey, e);
}

int Openssl_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EVP_PKEY_derive_init(ctx);
}

int Openssl_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{
    if (Is_Need_Mock()) {
        return -1;
    }
    return EVP_PKEY_derive_set_peer(ctx, peer);
}

int Openssl_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    if (key != NULL && g_isNeedSpecialMock) {
        g_callNum++;
    }
    if (Is_Need_Mock()) {
        if (key == NULL) {
            return -1;
        }
        if (g_isNeedSpecialMock) {
            int res = EVP_PKEY_derive(ctx, key, keylen);
            *keylen = *keylen * 2;
            g_isNeedSpecialMock = false;
            return res;
        }
        g_isNeedSpecialMock = true;
        return -1;
    }
    if (key != NULL) {
        g_callNum++;
    }
    return EVP_PKEY_derive(ctx, key, keylen);
}

void Openssl_EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_CTX_free(ctx);
}
