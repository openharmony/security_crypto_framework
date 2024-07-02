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

#include "crypto_asym_key.h"
#include <string.h>
#include <stdlib.h>
#include "key_pair.h"
#include "memory.h"
#include "pub_key.h"
#include "result.h"
#include "blob.h"
#include "object_base.h"
#include "native_common.h"
#include "big_integer.h"
#include "asy_key_generator.h"


typedef struct OH_CryptoAsymKeyGenerator {
    HcfObjectBase base;

    HcfResult (*generateKeyPair)(HcfAsyKeyGenerator *self, HcfParamsSpec *params,
        HcfKeyPair **returnKeyPair);

    HcfResult (*convertKey)(HcfAsyKeyGenerator *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
        HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair);

    HcfResult (*convertPemKey)(HcfAsyKeyGenerator *self, HcfParamsSpec *params, const char *pubKeyStr,
        const char *priKeyStr, HcfKeyPair **returnKeyPair);

    const char *(*getAlgoName)(HcfAsyKeyGenerator *self);
} OH_CryptoAsymKeyGenerator;

typedef struct OH_CryptoKeyPair {
    HcfObjectBase base;

    HcfPriKey *priKey;

    HcfPubKey *pubKey;
} OH_CryptoKeyPair;

typedef struct OH_CryptoPubKey {
    HcfKey base;

    HcfResult (*getAsyKeySpecBigInteger)(const HcfPubKey *self, const AsyKeySpecItem item,
        HcfBigInteger *returnBigInteger);

    HcfResult (*getAsyKeySpecString)(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString);

    HcfResult (*getAsyKeySpecInt)(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt);

    HcfResult (*getEncodedDer)(const HcfPubKey *self, const char *format, HcfBlob *returnBlob);
} OH_CryptoPubKey;

OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_Create(const char *algoName, OH_CryptoAsymKeyGenerator **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfAsyKeyGeneratorCreate(algoName, (HcfAsyKeyGenerator **)ctx);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_Generate(OH_CryptoAsymKeyGenerator *ctx, OH_CryptoKeyPair **keyCtx)
{
    if ((ctx == NULL) || (keyCtx == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->generateKeyPair((HcfAsyKeyGenerator *)ctx, NULL, (HcfKeyPair **)keyCtx);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGenerator_Convert(OH_CryptoAsymKeyGenerator *ctx, Crypto_EncodingType type,
    Crypto_DataBlob *pubKeyData, Crypto_DataBlob *priKeyData, OH_CryptoKeyPair **keyCtx)
{
    if ((ctx == NULL) || (pubKeyData == NULL && priKeyData == NULL) || (keyCtx == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    const char *priKeyStr = (priKeyData == NULL)? NULL : (const char *)priKeyData->data;
    const char *pubKeyStr = (pubKeyData == NULL)? NULL : (const char *)pubKeyData->data;
    switch (type) {
        case CRYPTO_PEM:
            ret = ctx->convertPemKey((HcfAsyKeyGenerator *)ctx, NULL, pubKeyStr, priKeyStr, (HcfKeyPair **)keyCtx);
            break;
        case CRYPTO_DER:
            ret = ctx->convertKey((HcfAsyKeyGenerator *)ctx, NULL,
                (HcfBlob *)pubKeyData, (HcfBlob *)priKeyData, (HcfKeyPair **)keyCtx);
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return GetOhCryptoErrCode(ret);
}

const char *OH_CryptoAsymKeyGenerator_GetAlgoName(OH_CryptoAsymKeyGenerator *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return ctx->getAlgoName((HcfAsyKeyGenerator *)ctx);
}

void OH_CryptoAsymKeyGenerator_Destroy(OH_CryptoAsymKeyGenerator *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->base.destroy((HcfObjectBase *)ctx);
}

void OH_CryptoKeyPair_Destroy(OH_CryptoKeyPair *keyCtx)
{
    if (keyCtx == NULL) {
        return;
    }
    keyCtx->base.destroy((HcfObjectBase *)keyCtx);
}

OH_CryptoPubKey *OH_CryptoKeyPair_GetPubKey(OH_CryptoKeyPair *keyCtx)
{
    if (keyCtx == NULL) {
        return NULL;
    }
    return (OH_CryptoPubKey *)keyCtx->pubKey;
}

OH_Crypto_ErrCode OH_CryptoPubKey_Encode(OH_CryptoPubKey *key, Crypto_EncodingType type,
    const char *encodingStandard, Crypto_DataBlob *out)
{
    if ((key == NULL) || (out == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    char *pemStr = NULL;
    switch (type) {
        case CRYPTO_PEM:
            ret = key->base.getEncodedPem((HcfKey *)key, encodingStandard, &pemStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            out->data = (uint8_t *)pemStr;
            out->len = strlen(pemStr);
            break;
        case CRYPTO_DER:
            if (encodingStandard != NULL) {
                ret = key->getEncodedDer((HcfPubKey *)key, encodingStandard, (HcfBlob *)out);
                break;
            } else {
                ret = key->base.getEncoded((HcfKey *)key, (HcfBlob *)out);
                break;
            }
        default:
            return CRYPTO_INVALID_PARAMS;
    }

    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoPubKey_GetParam(OH_CryptoPubKey *key, CryptoAsymKey_ParamType item, Crypto_DataBlob *value)
{
    if ((key == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    int32_t *returnInt = NULL;
    char *returnStr = NULL;
    HcfBigInteger bigIntValue = {0};
    switch (item) {
        case CRYPTO_ECC_H_INT:
        case CRYPTO_ECC_FIELD_SIZE_INT:
            returnInt = (int32_t *)HcfMalloc(sizeof(int32_t), 0);
            if (returnInt == NULL) {
                ret = HCF_ERR_MALLOC;
                break;
            }
            ret = key->getAsyKeySpecInt((HcfPubKey *)key, (AsyKeySpecItem)item, returnInt);
            if (ret != HCF_SUCCESS) {
                HcfFree(returnInt);
                break;
            }
            value->data = (uint8_t *)returnInt;
            value->len = sizeof(int32_t);
        case CRYPTO_ECC_FIELD_TYPE_STR:
        case CRYPTO_ECC_CURVE_NAME_STR:
            ret = key->getAsyKeySpecString((HcfPubKey *)key, (AsyKeySpecItem)item, &returnStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)returnStr;
            value->len = strlen(returnStr);
        case CRYPTO_DH_L_INT:
            ret = key->getAsyKeySpecBigInteger((HcfPubKey *)key,
                (AsyKeySpecItem)item, &bigIntValue);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)bigIntValue.data;
            value->len = (size_t)bigIntValue.len;
        default:
            ret = key->getAsyKeySpecBigInteger((HcfPubKey *)key,
                (AsyKeySpecItem)item, &bigIntValue);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)bigIntValue.data;
            value->len = (size_t)bigIntValue.len;
    }
    return GetOhCryptoErrCode(ret);
}
