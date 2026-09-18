/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mac_mbedtls.h"

#include "mbedtls_common.h"
#include "mbedtls/md.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "config.h"
#include "utils.h"
#include "detailed_hmac_params.h"
#include "mbedtls_sym_key.h"

typedef struct {
    HcfMacSpi base;
    mbedtls_md_context_t *ctx;
    char mbedtlsMdName[HCF_MAX_MD_NAME_LEN];
    bool initFlag;
} MbedtlsHmacSpiImpl;

static const char *MbedtlsGetHmacClass(void)
{
    return "MbedtlsHmac";
}

static mbedtls_md_context_t *MbedtlsGetHmacCtx(HcfMacSpi *self)
{
    if (!HcfIsClassMatch((HcfObjectBase *)self, MbedtlsGetHmacClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((MbedtlsHmacSpiImpl *)self)->ctx;
}

static HcfResult MbedtlsEngineInitHmac(HcfMacSpi *self, const HcfSymKey *key)
{
    if (self == NULL) {
        LOGE("self is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, MbedtlsGetHmacClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (MbedtlsGetHmacCtx(self) == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if ((key == NULL) || !HcfIsClassMatch((HcfObjectBase *)key, MBEDTLS_SYM_KEY_CLASS)) {
        LOGE("Invalid key or key class is not match!");
        return HCF_INVALID_PARAMS;
    }
    SymKeyImpl *keyImpl = (SymKeyImpl *)key;
    if (!HcfIsBlobValid(&keyImpl->keyMaterial)) {
        LOGE("Invalid keyMaterial");
        return HCF_INVALID_PARAMS;
    }
    mbedtls_md_context_t *ctx = MbedtlsGetHmacCtx(self);
    int32_t ret = mbedtls_md_hmac_starts(ctx, keyImpl->keyMaterial.data, keyImpl->keyMaterial.len);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_md_hmac_starts return error %d!", ret);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ((MbedtlsHmacSpiImpl *)self)->initFlag = true;
    return HCF_SUCCESS;
}

static HcfResult MbedtlsEngineUpdateHmac(HcfMacSpi *self, HcfBlob *input)
{
    if ((self == NULL) || (input == NULL)) {
        LOGE("The input self ptr or input is NULL!");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsHmacSpiImpl *hmacImpl = (MbedtlsHmacSpiImpl *)self;
    if (!hmacImpl->initFlag) {
        LOGW("HMAC instance may not have been initialized, "
            "ensure init interface of HMAC instance is executed completely!");
    }
    mbedtls_md_context_t *ctx = MbedtlsGetHmacCtx(self);
    if (ctx == NULL) {
        LOGE("The CTX of HMAC instance is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if ((input->data == NULL) || (input->len == 0)) {
        LOGE("Invalid input data!");
        return HCF_INVALID_PARAMS;
    }
    int32_t ret = mbedtls_md_hmac_update(ctx, input->data, input->len);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_md_hmac_update return error %d!", ret);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult MbedtlsEngineDoFinalHmac(HcfMacSpi *self, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) {
        LOGE("The input self ptr or output is NULL!");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsHmacSpiImpl *hmacImpl = (MbedtlsHmacSpiImpl *)self;
    if (!hmacImpl->initFlag) {
        LOGW("HMAC instance may not have been initialized, "
            "ensure init interface of HMAC instance is executed completely!");
    }
    mbedtls_md_context_t *ctx = MbedtlsGetHmacCtx(self);
    if (ctx == NULL) {
        LOGE("The CTX of HMAC instance is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    unsigned char outputBuf[HCF_EVP_MAX_MD_SIZE] = { 0 };
    const mbedtls_md_info_t *info = mbedtls_md_info_from_ctx(ctx);
    if (info == NULL) {
        LOGE("Failed to get md info from ctx!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    uint32_t outputLen = mbedtls_md_get_size(info);
    if (outputLen == 0) {
        LOGE("Failed to get hmac output size!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int32_t ret = mbedtls_md_hmac_finish(ctx, outputBuf);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_md_hmac_finish return error %d!", ret);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->data = (uint8_t *)HcfMalloc(outputLen, 0);
    if (output->data == NULL) {
        LOGE("Failed to allocate output->data memory!");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(output->data, outputLen, outputBuf, outputLen) != EOK) {
        LOGE("Failed to copy hmac output!");
        HcfFree(output->data);
        output->data = NULL;
        return HCF_ERR_MALLOC;
    }
    output->len = outputLen;
    return HCF_SUCCESS;
}

static uint32_t MbedtlsEngineGetHmacLength(HcfMacSpi *self)
{
    mbedtls_md_context_t *ctx = MbedtlsGetHmacCtx(self);
    if (ctx == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_MBEDTLS_INVALID_MAC_LEN;
    }
    return mbedtls_md_get_size(mbedtls_md_info_from_ctx(ctx));
}

static void MbedtlsDestroyHmac(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL");
        return;
    }
    if (!HcfIsClassMatch(self, MbedtlsGetHmacClass())) {
        LOGE("Class is not match.");
        return;
    }
    MbedtlsHmacSpiImpl *impl = (MbedtlsHmacSpiImpl *)self;
    if (impl->ctx != NULL) {
        mbedtls_md_free(impl->ctx);
        HcfFree(impl->ctx);
        impl->ctx = NULL;
    }
    HcfFree(impl);
}

static HcfResult MbedtlsHmacSetupCtx(MbedtlsHmacSpiImpl *impl)
{
    mbedtls_md_init(impl->ctx);
    mbedtls_md_type_t mdType = MBEDTLS_MD_SHA256;
    if (strcmp(impl->mbedtlsMdName, "SHA256") != 0) {
        LOGE("Unsupported digest algorithm: %{public}s, only support SHA256!", impl->mbedtlsMdName);
        return HCF_INVALID_PARAMS;
    }
    int32_t ret = mbedtls_md_setup(impl->ctx, mbedtls_md_info_from_type(mdType), 1);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_md_setup return error %d!", ret);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult MbedtlsHmacSpiCreate(HcfMacParamsSpec *paramsSpec, HcfMacSpi **spiObj)
{
    if ((paramsSpec == NULL) || (spiObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsHmacSpiImpl *returnSpiImpl = (MbedtlsHmacSpiImpl *)HcfMalloc(sizeof(MbedtlsHmacSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnSpiImpl->mbedtlsMdName, HCF_MAX_MD_NAME_LEN,
        ((HcfHmacParamsSpec *)paramsSpec)->mdName) != EOK) {
        LOGE("Failed to copy mdName!");
        HcfFree(returnSpiImpl);
        return HCF_INVALID_PARAMS;
    }
    returnSpiImpl->ctx = (mbedtls_md_context_t *)HcfMalloc(sizeof(mbedtls_md_context_t), 0);
    if (returnSpiImpl->ctx == NULL) {
        LOGE("Failed to create ctx!");
        HcfFree(returnSpiImpl);
        return HCF_ERR_MALLOC;
    }
    HcfResult res = MbedtlsHmacSetupCtx(returnSpiImpl);
    if (res != HCF_SUCCESS) {
        mbedtls_md_free(returnSpiImpl->ctx);
        HcfFree(returnSpiImpl->ctx);
        returnSpiImpl->ctx = NULL;
        HcfFree(returnSpiImpl);
        return res;
    }
    returnSpiImpl->base.base.getClass = MbedtlsGetHmacClass;
    returnSpiImpl->base.base.destroy = MbedtlsDestroyHmac;
    returnSpiImpl->base.engineInitMac = MbedtlsEngineInitHmac;
    returnSpiImpl->base.engineUpdateMac = MbedtlsEngineUpdateHmac;
    returnSpiImpl->base.engineDoFinalMac = MbedtlsEngineDoFinalHmac;
    returnSpiImpl->base.engineGetMacLength = MbedtlsEngineGetHmacLength;
    *spiObj = (HcfMacSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}
