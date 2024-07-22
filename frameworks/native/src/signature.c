/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "crypto_signature.h"
#include <string.h>
#include <stdlib.h>
#include "signature.h"
#include "memory.h"
#include "crypto_common.h"
#include "blob.h"
#include "object_base.h"
#include "result.h"
#include "native_common.h"

struct OH_CryptoVerify {
    HcfObjectBase base;

    HcfResult (*init)(HcfVerify *self, HcfParamsSpec *params, HcfPubKey *publicKey);

    HcfResult (*update)(HcfVerify *self, HcfBlob *data);

    bool (*verify)(HcfVerify *self, HcfBlob *data, HcfBlob *signatureData);

    HcfResult (*recover)(HcfVerify *self, HcfBlob *signatureData, HcfBlob *rawSignatureData);

    const char *(*getAlgoName)(HcfVerify *self);

    HcfResult (*setVerifySpecInt)(HcfVerify *self, SignSpecItem item, int32_t saltLen);

    HcfResult (*getVerifySpecString)(HcfVerify *self, SignSpecItem item, char **returnString);

    HcfResult (*getVerifySpecInt)(HcfVerify *self, SignSpecItem item, int32_t *returnInt);

    HcfResult (*setVerifySpecUint8Array)(HcfVerify *self, SignSpecItem item, HcfBlob blob);
};

OH_Crypto_ErrCode OH_CryptoVerify_Create(const char *algoName, OH_CryptoVerify **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfVerifyCreate(algoName, (HcfVerify **)ctx);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoVerify_Init(OH_CryptoVerify *ctx, OH_CryptoPubKey *pubKey)
{
    if ((ctx == NULL) || (pubKey == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->init((HcfVerify *)ctx, NULL, (HcfPubKey *)pubKey);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoVerify_Update(OH_CryptoVerify *ctx, Crypto_DataBlob *in)
{
    if ((ctx == NULL) || (in == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->update((HcfVerify *)ctx, (HcfBlob *)in);
    return GetOhCryptoErrCode(ret);
}

bool OH_CryptoVerify_Final(OH_CryptoVerify *ctx, Crypto_DataBlob *in, Crypto_DataBlob *signData)
{
    if ((ctx == NULL) || (signData == NULL)) {
        return false;
    }
    bool ret = ctx->verify((HcfVerify *)ctx, (HcfBlob *)in, (HcfBlob *)signData);
    if (ret != true) {
        return false;
    }

    return ret;
}

OH_Crypto_ErrCode OH_CryptoVerify_Recover(OH_CryptoVerify *ctx, Crypto_DataBlob *signData,
    Crypto_DataBlob *rawSignData)
{
    if ((ctx == NULL) || (signData == NULL) || (rawSignData == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->recover((HcfVerify *)ctx, (HcfBlob *)signData, (HcfBlob *)rawSignData);
    return GetOhCryptoErrCode(ret);
}

const char *OH_CryptoVerify_GetAlgoName(OH_CryptoVerify *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return ctx->getAlgoName((HcfVerify *)ctx);
}

OH_Crypto_ErrCode OH_CryptoVerify_SetParam(OH_CryptoVerify *ctx, CryptoSignature_ParamType type,
    Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (type) {
        case CRYPTO_PSS_SALT_LEN_INT:
        case CRYPTO_PSS_TRAILER_FIELD_INT:
            if (value->len != sizeof(int32_t)) {
                ret = HCF_INVALID_PARAMS;
                break;
            }
            ret = ctx->setVerifySpecInt((HcfVerify *)ctx, (SignSpecItem)type, *((int32_t *)value->data));
            break;
        case CRYPTO_SM2_USER_ID_DATABLOB:
        case CRYPTO_PSS_MGF1_NAME_STR:
        case CRYPTO_PSS_MGF_NAME_STR:
        case CRYPTO_PSS_MD_NAME_STR:
            ret = ctx->setVerifySpecUint8Array((HcfVerify *)ctx, (SignSpecItem)type, *((HcfBlob *)value));
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoVerify_GetParam(OH_CryptoVerify *ctx, CryptoSignature_ParamType type,
    Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    int32_t *returnInt = NULL;
    char *returnStr = NULL;
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (type) {       
        case CRYPTO_PSS_SALT_LEN_INT:
        case CRYPTO_PSS_TRAILER_FIELD_INT:
        case CRYPTO_SM2_USER_ID_DATABLOB:
            returnInt = (int32_t *)HcfMalloc(sizeof(int32_t), 0);
            if (returnInt == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            ret = ctx->getVerifySpecInt((HcfVerify *)ctx, (SignSpecItem)type, returnInt);
            if (ret != HCF_SUCCESS) {
                HcfFree(returnInt);
                break;
            }
            value->data = (uint8_t *)returnInt;
            value->len = sizeof(int32_t);
            break;
        case CRYPTO_PSS_MD_NAME_STR:
        case CRYPTO_PSS_MGF_NAME_STR:
        case CRYPTO_PSS_MGF1_NAME_STR:
            ret = ctx->getVerifySpecString((HcfVerify *)ctx, (SignSpecItem)type, &returnStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)returnStr;
            value->len = strlen(returnStr);
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return GetOhCryptoErrCode(ret);
}


void OH_CryptoVerify_Destroy(OH_CryptoVerify *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->base.destroy((HcfObjectBase *)ctx);
}
