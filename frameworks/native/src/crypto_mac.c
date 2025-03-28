/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "crypto_mac.h"
#include <string.h>
#include "securec.h"
#include "memory.h"
#include "crypto_common.h"
#include "crypto_sym_key.h"
#include "native_common.h"
#include "mac.h"
#include "mac_params.h"
#include "detailed_cmac_params.h"
#include "detailed_hmac_params.h"

typedef struct OH_CryptoMac {
    HcfMacParamsSpec *paramsSpec;
    HcfMac *macObj;
} OH_CryptoMac;

OH_Crypto_ErrCode OH_CryptoMac_Create(const char *algoName, OH_CryptoMac **ctx)
{
    if ((algoName == NULL) || (ctx == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    OH_CryptoMac *tmpCtx = (OH_CryptoMac *)HcfMalloc(sizeof(OH_CryptoMac), 0);
    if (tmpCtx == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfMacParamsSpec *paramsSpec = NULL;
    if (strcmp(algoName, "CMAC") == 0) {
        paramsSpec = (HcfMacParamsSpec *)HcfMalloc(sizeof(HcfCmacParamsSpec), 0);
    } else if (strcmp(algoName, "HMAC") == 0) {
        paramsSpec = (HcfMacParamsSpec *)HcfMalloc(sizeof(HcfHmacParamsSpec), 0);
    } else {
        HcfFree(tmpCtx);
        return CRYPTO_INVALID_PARAMS;
    }

    if (paramsSpec == NULL) {
        HcfFree(tmpCtx);
        return CRYPTO_MEMORY_ERROR;
    }

    char *algName = (char *)HcfMalloc(strlen(algoName) + 1, 0);
    if (algName == NULL) {
        HcfFree(paramsSpec);
        HcfFree(tmpCtx);
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(algName, strlen(algoName), algoName, strlen(algoName));
    paramsSpec->algName = algName;
    tmpCtx->paramsSpec = paramsSpec;
    *ctx = tmpCtx;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetCmacParam(HcfCmacParamsSpec *paramsSpec, CryptoMac_ParamType type, const Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_MAC_CIPHER_NAME_STR: {
            char *cipherName = (char *)HcfMalloc(value->len + 1, 0);
            if (cipherName == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(cipherName, value->len, value->data, value->len);
            paramsSpec->cipherName = cipherName;
            return CRYPTO_SUCCESS;
        }
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode SetHmacParam(HcfHmacParamsSpec *paramsSpec, CryptoMac_ParamType type, const Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_MAC_DIGEST_NAME_STR: {
            char *mdName = (char *)HcfMalloc(value->len + 1, 0);
            if (mdName == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(mdName, value->len, value->data, value->len);
            paramsSpec->mdName = mdName;
            return CRYPTO_SUCCESS;
        }
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

OH_Crypto_ErrCode OH_CryptoMac_SetParam(OH_CryptoMac *ctx, CryptoMac_ParamType type, const Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (ctx->paramsSpec == NULL) || (ctx->paramsSpec->algName == NULL) || (value == NULL) ||
        (value->data == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    if (strcmp(ctx->paramsSpec->algName, "CMAC") == 0) {
        return SetCmacParam((HcfCmacParamsSpec*)(ctx->paramsSpec), type, value);
    } else if (strcmp(ctx->paramsSpec->algName, "HMAC") == 0) {
        return SetHmacParam((HcfHmacParamsSpec*)(ctx->paramsSpec), type, value);
    } else {
        return CRYPTO_INVALID_PARAMS;
    }
}

OH_Crypto_ErrCode OH_CryptoMac_Init(OH_CryptoMac *ctx, const OH_CryptoSymKey *key)
{
    if ((ctx == NULL) || (key == NULL)) {
        return HCF_INVALID_PARAMS;
    }

    HcfMac *macObj = NULL;
    HcfResult ret = HcfMacCreate(ctx->paramsSpec, &macObj);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCode(ret);
    }
    if (macObj->init == NULL) {
        HcfObjDestroy(macObj);
        return CRYPTO_INVALID_PARAMS;
    }
    ret = macObj->init(macObj, (const HcfSymKey *)key);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(macObj);
        return GetOhCryptoErrCode(ret);
    }
    ctx->macObj = macObj;
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoMac_Update(OH_CryptoMac *ctx, const Crypto_DataBlob *in)
{
    if ((ctx == NULL) || (ctx->macObj == NULL) || (ctx->macObj->update == NULL) || (in == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = ctx->macObj->update(ctx->macObj, (HcfBlob *)in);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoMac_Final(OH_CryptoMac *ctx, Crypto_DataBlob *out)
{
    if ((ctx == NULL) || (ctx->macObj == NULL) || (ctx->macObj->doFinal == NULL) || (out == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->macObj->doFinal(ctx->macObj, (HcfBlob *)out);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoMac_GetLength(OH_CryptoMac *ctx, uint32_t *length)
{
    if ((ctx == NULL) || (ctx->macObj == NULL) || (ctx->macObj->getMacLength == NULL) || (length == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    *length = ctx->macObj->getMacLength(ctx->macObj);
    return CRYPTO_SUCCESS;
}

static void FreeMacParams(HcfMacParamsSpec *params)
{
    if ((params == NULL) || (params->algName == NULL)) {
        return;
    }
    if (strcmp(params->algName, "CMAC") == 0) {
        HcfFree((void *)(((HcfCmacParamsSpec *)params)->cipherName));
        ((HcfCmacParamsSpec *)params)->cipherName = NULL;
    } else if (strcmp(params->algName, "HMAC") == 0) {
        HcfFree((void *)(((HcfHmacParamsSpec *)params)->mdName));
        ((HcfHmacParamsSpec *)params)->mdName = NULL;
    }
    HcfFree((void *)(params->algName));
    params->algName = NULL;
    HcfFree(params);
}

void OH_CryptoMac_Destroy(OH_CryptoMac *ctx)
{
    if (ctx == NULL) {
        return;
    }
    FreeMacParams(ctx->paramsSpec);
    ctx->paramsSpec = NULL;
    HcfObjDestroy(ctx->macObj);
    ctx->macObj = NULL;
    HcfFree(ctx);
}