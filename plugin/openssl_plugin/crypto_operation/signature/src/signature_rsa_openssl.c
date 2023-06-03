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

#include "signature_rsa_openssl.h"

#include <string.h>

#include <openssl/evp.h>

#include "securec.h"

#include "algorithm_parameter.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "rsa_openssl_common.h"
#include "utils.h"

#define PSS_TRAILER_FIELD_SUPPORTED_INT 1
#define PSS_SALTLEN_INVALID_INIT (-9)

typedef struct {
    HcfSignSpi base;

    EVP_MD_CTX *mdctx;

    EVP_PKEY_CTX *ctx;

    int32_t padding;

    int32_t md;

    int32_t mgf1md;

    CryptoStatus initFlag;

    int32_t saltLen;
} HcfSignSpiRsaOpensslImpl;

typedef struct {
    HcfVerifySpi base;

    EVP_MD_CTX *mdctx;

    EVP_PKEY_CTX *ctx;

    int32_t padding;

    int32_t md;

    int32_t mgf1md;

    CryptoStatus initFlag;

    int32_t saltLen;
} HcfVerifySpiRsaOpensslImpl;

static const char *GetRsaSignClass(void)
{
    return OPENSSL_RSA_SIGN_CLASS;
}

static const char *GetRsaVerifyClass(void)
{
    return OPENSSL_RSA_VERIFY_CLASS;
}

static void DestroyRsaSign(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    Openssl_EVP_MD_CTX_free(impl->mdctx);
    impl->mdctx = NULL;
    // ctx will be freed with mdctx
    HcfFree(impl);
    impl = NULL;
    LOGD("DestroyRsaSign success.");
}

static void DestroyRsaVerify(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Class is null");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    Openssl_EVP_MD_CTX_free(impl->mdctx);
    impl->mdctx = NULL;
    HcfFree(impl);
    impl = NULL;
    LOGD("DestroyRsaVerify success.");
}

static HcfResult CheckInitKeyType(HcfKey *key, bool signing)
{
    if (signing) {
        if (!IsClassMatch((HcfObjectBase *)key, OPENSSL_RSA_PRIKEY_CLASS)) {
            LOGE("Input keyType dismatch with sign option, please use priKey.");
            return HCF_INVALID_PARAMS;
        }
    } else {
        if (!IsClassMatch((HcfObjectBase *)key, OPENSSL_RSA_PUBKEY_CLASS)) {
            LOGE("Input keyType dismatch with sign option, please use pubKey.");
            return HCF_INVALID_PARAMS;
        }
    }
    return HCF_SUCCESS;
}

static EVP_PKEY *InitRsaEvpKey(const HcfKey *key, bool signing)
{
    RSA *rsa = NULL;
    if (signing == true) {
        if (DuplicateRsa(((HcfOpensslRsaPriKey *)key)->sk, signing, &rsa) != HCF_SUCCESS) {
            RSA *tmp = Openssl_RSA_new();
            if (tmp == NULL) {
                LOGE("malloc rsa failed");
                return NULL;
            }
            const BIGNUM *n = NULL;
            const BIGNUM *e = NULL;
            const BIGNUM *d = NULL;
            Openssl_RSA_get0_key(((HcfOpensslRsaPriKey *)key)->sk, &n, &e, &d);
            if (n == NULL || e == NULL || d == NULL) {
                LOGE("get key attribute fail");
                return NULL;
            }
            BIGNUM *dupN = Openssl_BN_dup(n);
            BIGNUM *dupE = Openssl_BN_dup(e);
            BIGNUM *dupD = Openssl_BN_dup(d);
            if (Openssl_RSA_set0_key(tmp, dupN, dupE, dupD) != HCF_OPENSSL_SUCCESS) {
                LOGE("assign RSA n, e, d failed");
                Openssl_BN_clear_free(dupN);
                Openssl_BN_clear_free(dupE);
                Openssl_BN_clear_free(dupD);
                return NULL;
            }
            LOGE("duplicate RSA pri key success");
            rsa = tmp;
        }
    } else if (signing == false) {
        if (DuplicateRsa(((HcfOpensslRsaPubKey *)key)->pk, signing, &rsa) != HCF_SUCCESS) {
            LOGE("dup pub RSA fail");
            return NULL;
        }
    }
    if (rsa == NULL) {
        LOGE("The Key has lost.");
        return NULL;
    }
    EVP_PKEY *pkey = NewEvpPkeyByRsa(rsa, false);
    if (pkey == NULL) {
        LOGE("New evp pkey failed");
        HcfPrintOpensslError();
        Openssl_RSA_free(rsa);
        return NULL;
    }
    return pkey;
}

// the params has been checked in the CheckSignatureParams
static HcfResult SetPaddingAndDigest(EVP_PKEY_CTX *ctx, int32_t hcfPadding, int32_t md, int32_t mgf1md)
{
    int32_t opensslPadding = 0;
    (void)GetOpensslPadding(hcfPadding, &opensslPadding);
    if (Openssl_EVP_PKEY_CTX_set_rsa_padding(ctx, opensslPadding) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EVP_PKEY_CTX_set_rsa_padding fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (hcfPadding == HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGD("padding is pss, set mgf1 md");
        EVP_MD *opensslAlg = NULL;
        (void)GetOpensslDigestAlg(mgf1md, &opensslAlg);
        if (Openssl_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, opensslAlg) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_CTX_set_rsa_mgf1_md fail");
            HcfPrintOpensslError();
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}


static HcfResult SetSignParams(HcfSignSpiRsaOpensslImpl *impl, HcfPriKey *privateKey)
{
    EVP_PKEY *dupKey = InitRsaEvpKey((HcfKey *)privateKey, true);
    if (dupKey == NULL) {
        LOGE("InitRsaEvpKey fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *opensslAlg = NULL;
    (void)GetOpensslDigestAlg(impl->md, &opensslAlg);
    if (opensslAlg == NULL) {
        LOGE("Get openssl digest alg fail");
        return HCF_INVALID_PARAMS;
    }
    if (Openssl_EVP_DigestSignInit(impl->mdctx, &ctx, opensslAlg, NULL, dupKey) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EVP_DigestSignInit fail.");
        Openssl_EVP_PKEY_free(dupKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (SetPaddingAndDigest(ctx, impl->padding, impl->md, impl->mgf1md) != HCF_SUCCESS) {
        LOGE("set padding and digest fail");
        Openssl_EVP_PKEY_free(dupKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        if (Openssl_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, impl->saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("get saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    impl->ctx = ctx;
    Openssl_EVP_PKEY_free(dupKey);
    return HCF_SUCCESS;
}

static HcfResult EngineSignInit(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    if (self == NULL || privateKey == NULL) {
        LOGE("Invalid input params");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->initFlag != UNINITIALIZED) {
        LOGE("Sign has been init");
        return HCF_INVALID_PARAMS;
    }
    if (CheckInitKeyType((HcfKey *)privateKey, true) != HCF_SUCCESS) {
        LOGE("KeyType dismatch.");
        return HCF_INVALID_PARAMS;
    }
    if (SetSignParams(impl, privateKey) != HCF_SUCCESS) {
        LOGE("Sign set padding or md fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->initFlag = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult SetVerifyParams(HcfVerifySpiRsaOpensslImpl *impl, HcfPubKey *publicKey)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *dupKey = InitRsaEvpKey((HcfKey *)publicKey, false);
    if (dupKey == NULL) {
        LOGE("InitRsaEvpKey fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_MD *opensslAlg = NULL;
    (void)GetOpensslDigestAlg(impl->md, &opensslAlg);
    if (opensslAlg == NULL) {
        LOGE("Get openssl digest alg fail");
        return HCF_INVALID_PARAMS;
    }
    if (Openssl_EVP_DigestVerifyInit(impl->mdctx, &ctx, opensslAlg, NULL, dupKey) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EVP_DigestVerifyInit fail.");
        HcfPrintOpensslError();
        Openssl_EVP_PKEY_free(dupKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (SetPaddingAndDigest(ctx, impl->padding, impl->md, impl->mgf1md) != HCF_SUCCESS) {
        LOGE("set padding and digest fail");
        Openssl_EVP_PKEY_free(dupKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        if (Openssl_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, impl->saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("get saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    impl->ctx = ctx;
    Openssl_EVP_PKEY_free(dupKey);
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyInit(HcfVerifySpi *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    if (self == NULL || publicKey == NULL) {
        LOGE("Invalid input params.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->initFlag != UNINITIALIZED) {
        LOGE("Verigy has been init.");
        return HCF_INVALID_PARAMS;
    }
    if (CheckInitKeyType((HcfKey *)publicKey, false) != HCF_SUCCESS) {
        LOGE("KeyType dismatch.");
        return HCF_INVALID_PARAMS;
    }
    if (SetVerifyParams(impl, publicKey) != HCF_SUCCESS) {
        LOGE("Verify set padding or md fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->initFlag = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineSignUpdate(HcfSignSpi *self, HcfBlob *data)
{
    if ((self == NULL) || (data == NULL) || (data->data == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("The Sign has not been init");
        return HCF_INVALID_PARAMS;
    }
    if (Openssl_EVP_DigestSignUpdate(impl->mdctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EVP_DigestSignUpdate fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyUpdate(HcfVerifySpi *self, HcfBlob *data)
{
    if ((self == NULL) || (data == NULL) || (data->data == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("The Sign has not been init");
        return HCF_INVALID_PARAMS;
    }
    if (Openssl_EVP_DigestVerifyUpdate(impl->mdctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EVP_DigestSignUpdate fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineSign(HcfSignSpi *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if (self == NULL || returnSignatureData == NULL) {
        LOGE("Invalid input params.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("The Sign has not been init");
        return HCF_INVALID_PARAMS;
    }
    if (data != NULL && data->data != NULL) {
        if (Openssl_EVP_DigestSignUpdate(impl->mdctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            LOGE("Dofinal update data fail.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    size_t maxLen;
    if (Openssl_EVP_DigestSignFinal(impl->mdctx, NULL, &maxLen) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EVP_DigestSignFinal fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    LOGD("sign maxLen is %d", maxLen);
    uint8_t *outData = (uint8_t *)HcfMalloc(maxLen, 0);
    if (outData == NULL) {
        LOGE("Failed to allocate outData memory!");
        return HCF_ERR_MALLOC;
    }
    size_t actualLen = maxLen;
    if (Openssl_EVP_DigestSignFinal(impl->mdctx, outData, &actualLen) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EVP_DigestSignFinal fail");
        HcfFree(outData);
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (actualLen > maxLen) {
        LOGE("signature data too long.");
        HcfFree(outData);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    returnSignatureData->data = outData;
    returnSignatureData->len = (uint32_t)actualLen;

    return HCF_SUCCESS;
}

static bool EngineVerify(HcfVerifySpi *self, HcfBlob *data, HcfBlob *signatureData)
{
    if (self == NULL || signatureData == NULL || signatureData->data == NULL) {
        LOGE("Invalid input params");
        return false;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return false;
    }

    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->initFlag != INITIALIZED) {
        LOGE("The Sign has not been init");
        return false;
    }
    if (data != NULL && data->data != NULL) {
        if (Openssl_EVP_DigestVerifyUpdate(impl->mdctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            LOGE("Openssl_EVP_DigestVerifyUpdate fail");
            return false;
        }
    }
    if (Openssl_EVP_DigestVerifyFinal(impl->mdctx, signatureData->data, signatureData->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EVP_DigestVerifyFinal fail");
        return false;
    }
    return true;
}

static HcfResult CheckSignatureParams(HcfSignatureParams *params)
{
    int32_t opensslPadding = 0;
    if (GetOpensslPadding(params->padding, &opensslPadding) != HCF_SUCCESS) {
        LOGE("getpadding fail.");
        return HCF_INVALID_PARAMS;
    }
    if (opensslPadding != RSA_PKCS1_PADDING && opensslPadding != RSA_PKCS1_PSS_PADDING) {
        LOGE("signature cannot use that padding mode");
        return HCF_INVALID_PARAMS;
    }
    EVP_MD *md = NULL;
    (void)GetOpensslDigestAlg(params->md, &md);
    if (md == NULL) {
        LOGE("Md is NULL");
        return HCF_INVALID_PARAMS;
    }
    if (params->padding == HCF_OPENSSL_RSA_PSS_PADDING) {
        EVP_MD *mgf1md = NULL;
        (void)GetOpensslDigestAlg(params->mgf1md, &mgf1md);
        if (mgf1md == NULL) {
            LOGE("Use pss padding, but mgf1md is NULL");
            return HCF_INVALID_PARAMS;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult EngineSetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t saltLen)
{
    if (self == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (item != PSS_SALT_LEN_INT) {
        LOGE("Invalid sign spec item");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (saltLen < 0) {
        // RSA_PSS_SALTLEN_MAX_SIGN: max sign is old compatible max salt length for sign only
        if (saltLen != RSA_PSS_SALTLEN_DIGEST && saltLen != RSA_PSS_SALTLEN_MAX_SIGN &&
            saltLen != RSA_PSS_SALTLEN_MAX) {
            LOGE("Invalid salt Len %d", saltLen);
            return HCF_INVALID_PARAMS;
        }
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    impl->saltLen = saltLen;
    if (impl->initFlag == INITIALIZED) {
        if (Openssl_EVP_PKEY_CTX_set_rsa_pss_saltlen(impl->ctx, saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("set saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    LOGD("Set sign saltLen success");
    return HCF_SUCCESS;
}

static HcfResult EngineGetSignSpecInt(HcfSignSpi *self, SignSpecItem item, int32_t *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (item != PSS_TRAILER_FIELD_INT && item != PSS_SALT_LEN_INT) {
        LOGE("Invalid input spec");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    if (item == PSS_TRAILER_FIELD_INT) {
        *returnInt = PSS_TRAILER_FIELD_SUPPORTED_INT;
        return HCF_SUCCESS;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        *returnInt = impl->saltLen;
        return HCF_SUCCESS;
    }
    if (impl->initFlag == INITIALIZED) {
        if (Openssl_EVP_PKEY_CTX_get_rsa_pss_saltlen(impl->ctx, returnInt) != HCF_OPENSSL_SUCCESS) {
            LOGE("get saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        return HCF_SUCCESS;
    } else {
        LOGE("No set saltLen and not init!");
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult EngineGetSignSpecString(HcfSignSpi *self, SignSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_SIGN_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *impl = (HcfSignSpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case PSS_MD_NAME_STR:
            ret = GetRsaSpecStringMd(impl->md, returnString);
            break;
        case PSS_MGF_NAME_STR:
            // only support mgf1
            ret = GetRsaSpecStringMGF(returnString);
            break;
        case PSS_MGF1_MD_STR:
            ret = GetRsaSpecStringMd(impl->mgf1md, returnString);
            break;
        default:
            LOGE("Invalid input sign spec item");
            return HCF_INVALID_PARAMS;
    }
    return ret;
}

static HcfResult EngineSetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t saltLen)
{
    if (self == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (item != PSS_SALT_LEN_INT) {
        LOGE("Invalid verify spec item");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (saltLen < 0) {
        // RSA_PSS_SALTLEN_AUTO: Verify only: auto detect salt length(only support verify)
        if (saltLen != RSA_PSS_SALTLEN_DIGEST && saltLen != RSA_PSS_SALTLEN_AUTO &&
            saltLen != RSA_PSS_SALTLEN_MAX) {
            LOGE("Invalid salt Len %d", saltLen);
            return HCF_INVALID_PARAMS;
        }
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    impl->saltLen = saltLen;
    if (impl->initFlag == INITIALIZED) {
        if (Openssl_EVP_PKEY_CTX_set_rsa_pss_saltlen(impl->ctx, saltLen) != HCF_OPENSSL_SUCCESS) {
            LOGE("set saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGetVerifySpecInt(HcfVerifySpi *self, SignSpecItem item, int32_t *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    if (item != PSS_TRAILER_FIELD_INT && item != PSS_SALT_LEN_INT) {
        LOGE("Invalid input sign spec item");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    if (item == PSS_TRAILER_FIELD_INT) {
        *returnInt = PSS_TRAILER_FIELD_SUPPORTED_INT;
        return HCF_SUCCESS;
    }
    if (impl->saltLen != PSS_SALTLEN_INVALID_INIT) {
        *returnInt = impl->saltLen;
        return HCF_SUCCESS;
    }
    if (impl->initFlag == INITIALIZED) {
        if (Openssl_EVP_PKEY_CTX_get_rsa_pss_saltlen(impl->ctx, returnInt) != HCF_OPENSSL_SUCCESS) {
            LOGE("get saltLen fail");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        return HCF_SUCCESS;
    } else {
        LOGE("No set saltLen and not init!");
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult EngineGetVerifySpecString(HcfVerifySpi *self, SignSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_VERIFY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiRsaOpensslImpl *impl = (HcfVerifySpiRsaOpensslImpl *)self;
    if (impl->padding != HCF_OPENSSL_RSA_PSS_PADDING) {
        LOGE("Only support pss parameter");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case PSS_MD_NAME_STR:
            ret = GetRsaSpecStringMd(impl->md, returnString);
            break;
        case PSS_MGF_NAME_STR:
            // only support mgf1
            ret = GetRsaSpecStringMGF(returnString);
            break;
        case PSS_MGF1_MD_STR:
            ret = GetRsaSpecStringMd(impl->mgf1md, returnString);
            break;
        default:
            LOGE("Invalid input sign spec item");
            return HCF_INVALID_PARAMS;
    }
    return ret;
}

HcfResult HcfSignSpiRsaCreate(HcfSignatureParams *params, HcfSignSpi **returnObj)
{
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (CheckSignatureParams(params) != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiRsaOpensslImpl *returnImpl = (HcfSignSpiRsaOpensslImpl *)HcfMalloc(
        sizeof(HcfSignSpiRsaOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetRsaSignClass;
    returnImpl->base.base.destroy = DestroyRsaSign;
    returnImpl->base.engineInit = EngineSignInit;
    returnImpl->base.engineUpdate = EngineSignUpdate;
    returnImpl->base.engineSign = EngineSign;
    returnImpl->base.engineSetSignSpecInt = EngineSetSignSpecInt;
    returnImpl->base.engineGetSignSpecInt = EngineGetSignSpecInt;
    returnImpl->base.engineGetSignSpecString = EngineGetSignSpecString;

    returnImpl->md = params->md;
    returnImpl->padding = params->padding;
    returnImpl->mgf1md = params->mgf1md;
    returnImpl->mdctx = EVP_MD_CTX_create();
    returnImpl->initFlag = UNINITIALIZED;
    returnImpl->saltLen = PSS_SALTLEN_INVALID_INIT;
    *returnObj = (HcfSignSpi *)returnImpl;
    return HCF_SUCCESS;
}

HcfResult HcfVerifySpiRsaCreate(HcfSignatureParams *params, HcfVerifySpi **returnObj)
{
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (CheckSignatureParams(params) != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpiRsaOpensslImpl *returnImpl = (HcfVerifySpiRsaOpensslImpl *)HcfMalloc(
        sizeof(HcfVerifySpiRsaOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetRsaVerifyClass;
    returnImpl->base.base.destroy = DestroyRsaVerify;
    returnImpl->base.engineInit = EngineVerifyInit;
    returnImpl->base.engineUpdate = EngineVerifyUpdate;
    returnImpl->base.engineVerify = EngineVerify;
    returnImpl->base.engineSetVerifySpecInt = EngineSetVerifySpecInt;
    returnImpl->base.engineGetVerifySpecInt = EngineGetVerifySpecInt;
    returnImpl->base.engineGetVerifySpecString = EngineGetVerifySpecString;

    returnImpl->md = params->md;
    returnImpl->padding = params->padding;
    returnImpl->mgf1md = params->mgf1md;
    returnImpl->mdctx = EVP_MD_CTX_create();
    returnImpl->initFlag = UNINITIALIZED;
    returnImpl->saltLen = PSS_SALTLEN_INVALID_INIT;
    *returnObj = (HcfVerifySpi *)returnImpl;
    return HCF_SUCCESS;
}