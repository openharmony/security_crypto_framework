/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "sm2_openssl.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include "algorithm_parameter.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#define OPENSSL_SM2_SIGN_CLASS "OPENSSL.SM2.SIGN"
#define OPENSSL_SM2_VERIFY_CLASS "OPENSSL.SM2.VERIFY"

typedef struct {
    HcfSignSpi base;

    const EVP_MD *digestAlg;

    EVP_MD_CTX *ctx;

    CryptoStatus status;
} HcfSignSpiSm2OpensslImpl;

typedef struct {
    HcfVerifySpi base;

    const EVP_MD *digestAlg;

    EVP_MD_CTX *ctx;

    CryptoStatus status;
} HcfVerifySpiSm2OpensslImpl;

static bool IsDigestAlgValid(uint32_t alg)
{
    if (alg == HCF_OPENSSL_DIGEST_SM3) {
        return true;
    } else {
        LOGE("Invalid digest num!");
        return false;
    }
}

// export interfaces
static const char *GetSm2SignClass(void)
{
    return OPENSSL_SM2_SIGN_CLASS;
}

static const char *GetSm2VerifyClass(void)
{
    return OPENSSL_SM2_VERIFY_CLASS;
}

static void DestroySm2Sign(HcfObjectBase *self)
{
    if (self == NULL || !IsClassMatch(self, self->getClass())) {
        return;
    }
    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    impl->digestAlg = NULL;
    if (impl->ctx != NULL) {
        Openssl_EVP_MD_CTX_free(impl->ctx);
        impl->ctx = NULL;
    }
    HcfFree(impl);
}

static void DestroySm2Verify(HcfObjectBase *self)
{
    if (self == NULL || !IsClassMatch(self, self->getClass())) {
        return;
    }
    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    impl->digestAlg = NULL;
    if (impl->ctx != NULL) {
        Openssl_EVP_MD_CTX_free(impl->ctx);
        impl->ctx = NULL;
    }
    HcfFree(impl);
}

static HcfResult SetSM2Id(EVP_MD_CTX *mdCtx, EVP_PKEY *pKey, char *userId)
{
    EVP_PKEY_CTX *pKeyCtx = Openssl_EVP_PKEY_CTX_new(pKey, NULL);
    if (pKeyCtx == NULL) {
        LOGE("new EVP_PKEY_CTX fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EVP_PKEY_CTX_set1_id(pKeyCtx, (const void*)userId, strlen(userId)) != HCF_OPENSSL_SUCCESS) {
        LOGE("Set sm2 user id fail");
        HcfPrintOpensslError();
        Openssl_EVP_PKEY_CTX_free(pKeyCtx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_EVP_MD_CTX_set_pkey_ctx(mdCtx, pKeyCtx);
    return HCF_SUCCESS;
}

static HcfResult EngineSignInit(HcfSignSpi *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    (void)params;
    if ((self == NULL) || (privateKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if ((!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) ||
        (!IsClassMatch((HcfObjectBase *)privateKey, HCF_OPENSSL_SM2_PRI_KEY_CLASS))) {
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = Openssl_EC_KEY_dup(((HcfOpensslSm2PriKey *)privateKey)->ecKey);
    if (ecKey == NULL) {
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY *pKey = Openssl_EVP_PKEY_new();
    if (pKey == NULL) {
        HcfPrintOpensslError();
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EVP_PKEY_assign_EC_KEY(pKey, ecKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        Openssl_EC_KEY_free(ecKey);
        Openssl_EVP_PKEY_free(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (SetSM2Id(impl->ctx, pKey, SM2_DEFAULT_USERID) != HCF_SUCCESS) {
        Openssl_EVP_PKEY_free(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EVP_DigestSignInit(impl->ctx, NULL, impl->digestAlg, NULL, pKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        Openssl_EVP_PKEY_free(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_EVP_PKEY_free(pKey);
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineSignUpdate(HcfSignSpi *self, HcfBlob *data)
{
    if ((self == NULL) || (!IsBlobValid(data))) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGE("Sign object has not been initialized.");
        return HCF_INVALID_PARAMS;
    }
    if (Openssl_EVP_DigestSignUpdate(impl->ctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->status = READY;
    return HCF_SUCCESS;
}

static HcfResult EngineSignDoFinal(HcfSignSpi *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if ((self == NULL) || (returnSignatureData == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiSm2OpensslImpl *impl = (HcfSignSpiSm2OpensslImpl *)self;
    if (IsBlobValid(data)) {
        if (Openssl_EVP_DigestSignUpdate(impl->ctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            return HCF_ERR_CRYPTO_OPERATION;
        }
        impl->status = READY;
    }
    if (impl->status != READY) {
        LOGE("The message has not been transferred.");
        return HCF_INVALID_PARAMS;
    }
    size_t maxLen;
    if (Openssl_EVP_DigestSignFinal(impl->ctx, NULL, &maxLen) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *outData = (uint8_t *)HcfMalloc(maxLen, 0);
    if (outData == NULL) {
        LOGE("Failed to allocate outData memory!");
        return HCF_ERR_MALLOC;
    }
    size_t actualLen = maxLen;
    if (Openssl_EVP_DigestSignFinal(impl->ctx, outData, &actualLen) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        HcfFree(outData);
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

static HcfResult EngineVerifyInit(HcfVerifySpi *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    (void)params;
    if ((self == NULL) || (publicKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if ((!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) ||
        (!IsClassMatch((HcfObjectBase *)publicKey, HCF_OPENSSL_SM2_PUB_KEY_CLASS))) {
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    if (impl->status != UNINITIALIZED) {
        LOGE("Repeated initialization is not allowed.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = Openssl_EC_KEY_dup(((HcfOpensslSm2PubKey *)publicKey)->ecKey);
    if (ecKey == NULL) {
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY *pKey = Openssl_EVP_PKEY_new();
    if (pKey == NULL) {
        HcfPrintOpensslError();
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EVP_PKEY_assign_EC_KEY(pKey, ecKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        Openssl_EC_KEY_free(ecKey);
        Openssl_EVP_PKEY_free(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (SetSM2Id(impl->ctx, pKey, SM2_DEFAULT_USERID) != HCF_SUCCESS) {
        Openssl_EVP_PKEY_free(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EVP_DigestVerifyInit(impl->ctx, NULL, impl->digestAlg, NULL, pKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        Openssl_EVP_PKEY_free(pKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_EVP_PKEY_free(pKey);
    impl->status = INITIALIZED;
    return HCF_SUCCESS;
}

static HcfResult EngineVerifyUpdate(HcfVerifySpi *self, HcfBlob *data)
{
    if ((self == NULL) || (!IsBlobValid(data))) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    if (impl->status == UNINITIALIZED) {
        LOGE("Verify object has not been initialized.");
        return HCF_INVALID_PARAMS;
    }
    if (Openssl_EVP_DigestVerifyUpdate(impl->ctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    impl->status = READY;
    return HCF_SUCCESS;
}

static bool EngineVerifyDoFinal(HcfVerifySpi *self, HcfBlob *data, HcfBlob *signatureData)
{
    if ((self == NULL) || (!IsBlobValid(signatureData))) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        return false;
    }

    HcfVerifySpiSm2OpensslImpl *impl = (HcfVerifySpiSm2OpensslImpl *)self;
    if (IsBlobValid(data)) {
        if (Openssl_EVP_DigestVerifyUpdate(impl->ctx, data->data, data->len) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            return false;
        }
        impl->status = READY;
    }
    if (impl->status != READY) {
        LOGE("The message has not been transferred.");
        return false;
    }
    if (Openssl_EVP_DigestVerifyFinal(impl->ctx, signatureData->data, signatureData->len) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        return false;
    }
    return true;
}

HcfResult HcfSignSpiSm2Create(HcfSignatureParams *params, HcfSignSpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsDigestAlgValid(params->md)) {
        return HCF_INVALID_PARAMS;
    }
    EVP_MD *opensslAlg = NULL;
    int32_t ret = GetOpensslDigestAlg(params->md, &opensslAlg);
    if (ret != HCF_SUCCESS || opensslAlg == NULL) {
        LOGE("Failed to Invalid digest!");
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiSm2OpensslImpl *returnImpl = (HcfSignSpiSm2OpensslImpl *)HcfMalloc(
        sizeof(HcfSignSpiSm2OpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetSm2SignClass;
    returnImpl->base.base.destroy = DestroySm2Sign;
    returnImpl->base.engineInit = EngineSignInit;
    returnImpl->base.engineUpdate = EngineSignUpdate;
    returnImpl->base.engineSign = EngineSignDoFinal;
    returnImpl->digestAlg = opensslAlg;
    returnImpl->status = UNINITIALIZED;
    returnImpl->ctx = Openssl_EVP_MD_CTX_new();
    if (returnImpl->ctx == NULL) {
        LOGE("Failed to allocate ctx memory!");
        HcfFree(returnImpl);
        return HCF_ERR_MALLOC;
    }

    *returnObj = (HcfSignSpi *)returnImpl;
    return HCF_SUCCESS;
}

HcfResult HcfVerifySpiSm2Create(HcfSignatureParams *params, HcfVerifySpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsDigestAlgValid(params->md)) {
        return HCF_INVALID_PARAMS;
    }
    EVP_MD *opensslAlg = NULL;
    int32_t ret = GetOpensslDigestAlg(params->md, &opensslAlg);
    if (ret != HCF_SUCCESS || opensslAlg == NULL) {
        LOGE("Failed to Invalid digest!");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiSm2OpensslImpl *returnImpl = (HcfVerifySpiSm2OpensslImpl *)HcfMalloc(
        sizeof(HcfVerifySpiSm2OpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetSm2VerifyClass;
    returnImpl->base.base.destroy = DestroySm2Verify;
    returnImpl->base.engineInit = EngineVerifyInit;
    returnImpl->base.engineUpdate = EngineVerifyUpdate;
    returnImpl->base.engineVerify = EngineVerifyDoFinal;
    returnImpl->digestAlg = opensslAlg;
    returnImpl->status = UNINITIALIZED;
    returnImpl->ctx = Openssl_EVP_MD_CTX_new();
    if (returnImpl->ctx == NULL) {
        LOGE("Failed to allocate ctx memory!");
        HcfFree(returnImpl);
        return HCF_ERR_MALLOC;
    }

    *returnObj = (HcfVerifySpi *)returnImpl;
    return HCF_SUCCESS;
}
