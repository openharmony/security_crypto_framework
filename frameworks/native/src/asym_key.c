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
#include "securec.h"
#include "key_pair.h"
#include "detailed_ecc_key_params.h"
#include "detailed_dh_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_dsa_key_params.h"
#include "detailed_alg_25519_key_params.h"
#include "params_parser.h"
#include "ecc_key_util.h"
#include "dh_key_util.h"
#include "key_utils.h"
#include "memory.h"
#include "pub_key.h"
#include "pri_key.h"
#include "result.h"
#include "blob.h"
#include "object_base.h"
#include "native_common.h"
#include "crypto_common.h"
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

typedef struct OH_CryptoPrivKey {
    HcfKey base;

    HcfResult (*getAsyKeySpecBigInteger)(const HcfPriKey *self, const AsyKeySpecItem item,
        HcfBigInteger *returnBigInteger);

    HcfResult (*getAsyKeySpecString)(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString);

    HcfResult (*getAsyKeySpecInt)(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt);

    HcfResult (*getEncodedDer)(const HcfPriKey *self, const char *format, HcfBlob *returnBlob);

    HcfResult (*getEncodedPem)(const HcfPriKey *self, HcfParamsSpec *params, const char *format, char **returnString);

    void (*clearMem)(HcfPriKey *self);
} OH_CryptoPrivKey;

typedef struct OH_CryptoPrivKeyEncodingParams {
    HcfParamsSpec base;

    char *password;

    char *cipher;
} OH_CryptoPrivKeyEncodingParams;

typedef struct OH_CryptoAsymKeySpec {
    char *algName;
    HcfAsyKeySpecType specType;
} OH_CryptoAsymKeySpec;

typedef struct OH_CryptoAsymKeyGeneratorWithSpec {
    HcfObjectBase base;

    HcfResult (*generateKeyPair)(const HcfAsyKeyGeneratorBySpec *self, HcfKeyPair **returnKeyPair);

    HcfResult (*generatePubKey)(const HcfAsyKeyGeneratorBySpec *self, HcfPubKey **returnPubKey);

    HcfResult (*generatePriKey)(const HcfAsyKeyGeneratorBySpec *self, HcfPriKey **returnPriKey);

    const char *(*getAlgName)(const HcfAsyKeyGeneratorBySpec *self);
} OH_CryptoAsymKeyGeneratorWithSpec;

typedef struct OH_CryptoEcPoint {
    HcfPoint pointBase;
    char *curveName;
} OH_CryptoEcPoint;

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
    if ((ctx == NULL) || (ctx->generateKeyPair == NULL) || (keyCtx == NULL)) {
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
            ret = ctx->convertPemKey == NULL ? HCF_INVALID_PARAMS :
                ctx->convertPemKey((HcfAsyKeyGenerator *)ctx, NULL, pubKeyStr, priKeyStr, (HcfKeyPair **)keyCtx);
            break;
        case CRYPTO_DER:
            ret = ctx->convertKey == NULL ? HCF_INVALID_PARAMS :
                ctx->convertKey((HcfAsyKeyGenerator *)ctx, NULL, (HcfBlob *)pubKeyData,
                                (HcfBlob *)priKeyData, (HcfKeyPair **)keyCtx);
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return GetOhCryptoErrCode(ret);
}

const char *OH_CryptoAsymKeyGenerator_GetAlgoName(OH_CryptoAsymKeyGenerator *ctx)
{
    if ((ctx == NULL) || (ctx->getAlgoName == NULL)) {
        return NULL;
    }
    return ctx->getAlgoName((HcfAsyKeyGenerator *)ctx);
}

void OH_CryptoAsymKeyGenerator_Destroy(OH_CryptoAsymKeyGenerator *ctx)
{
    if ((ctx == NULL) || (ctx->base.destroy == NULL)) {
        return;
    }
    ctx->base.destroy((HcfObjectBase *)ctx);
}

void OH_CryptoKeyPair_Destroy(OH_CryptoKeyPair *keyCtx)
{
    if ((keyCtx == NULL) || (keyCtx->base.destroy == NULL)) {
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

OH_CryptoPrivKey *OH_CryptoKeyPair_GetPrivKey(OH_CryptoKeyPair *keyCtx)
{
    if (keyCtx == NULL) {
        return NULL;
    }
    return (OH_CryptoPrivKey *)keyCtx->priKey;
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
            if (key->base.getEncodedPem == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            ret = key->base.getEncodedPem((HcfKey *)key, encodingStandard, &pemStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            out->data = (uint8_t *)pemStr;
            out->len = strlen(pemStr);
            break;
        case CRYPTO_DER:
            if (encodingStandard != NULL) {
                ret = key->getEncodedDer == NULL ? HCF_INVALID_PARAMS :
                    key->getEncodedDer((HcfPubKey *)key, encodingStandard, (HcfBlob *)out);
                break;
            } else {
                ret = key->base.getEncoded == NULL ? HCF_INVALID_PARAMS
                                                   : key->base.getEncoded((HcfKey *)key, (HcfBlob *)out);
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
        case CRYPTO_DH_L_INT:
        case CRYPTO_ECC_H_INT:
        case CRYPTO_ECC_FIELD_SIZE_INT:
            returnInt = (int32_t *)HcfMalloc(sizeof(int32_t), 0);
            if (returnInt == NULL) {
                ret = HCF_ERR_MALLOC;
                break;
            }
            ret = key->getAsyKeySpecInt == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecInt((HcfPubKey *)key, (AsyKeySpecItem)item, returnInt);
            if (ret != HCF_SUCCESS) {
                HcfFree(returnInt);
                break;
            }
            value->data = (uint8_t *)returnInt;
            value->len = sizeof(int32_t);
            break;
        case CRYPTO_ECC_FIELD_TYPE_STR:
        case CRYPTO_ECC_CURVE_NAME_STR:
            ret = key->getAsyKeySpecString == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecString((HcfPubKey *)key, (AsyKeySpecItem)item, &returnStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)returnStr;
            value->len = strlen(returnStr);
            break;
        default:
            ret = key->getAsyKeySpecBigInteger == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecBigInteger((HcfPubKey *)key, (AsyKeySpecItem)item, &bigIntValue);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)bigIntValue.data;
            value->len = (size_t)bigIntValue.len;
            break;
    }
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoPrivKeyEncodingParams_Create(OH_CryptoPrivKeyEncodingParams **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    *ctx = (OH_CryptoPrivKeyEncodingParams *)HcfMalloc(sizeof(OH_CryptoPrivKeyEncodingParams), 0);
    if (*ctx == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoPrivKeyEncodingParams_SetParam(OH_CryptoPrivKeyEncodingParams *ctx,
    CryptoPrivKeyEncoding_ParamType type, Crypto_DataBlob *value)
{
    if ((ctx == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    char *data = (char *)HcfMalloc(value->len + 1, 0);
    if (data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(data, value->len, value->data, value->len);
    switch (type) {
        case CRYPTO_PRIVATE_KEY_ENCODING_PASSWORD_STR:
            ctx->password = data;
            break;
        case CRYPTO_PRIVATE_KEY_ENCODING_SYMMETRIC_CIPHER_STR:
            ctx->cipher = data;
            break;
        default:
            HcfFree(data);
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

void OH_CryptoPrivKeyEncodingParams_Destroy(OH_CryptoPrivKeyEncodingParams *ctx)
{
    if (ctx == NULL) {
        return;
    }
    HcfFree(ctx->password);
    ctx->password = NULL;
    HcfFree(ctx->cipher);
    ctx->cipher = NULL;
    HcfFree(ctx);
}

OH_Crypto_ErrCode OH_CryptoPrivKey_Encode(OH_CryptoPrivKey *key, Crypto_EncodingType type,
    const char *encodingStandard, OH_CryptoPrivKeyEncodingParams *params, Crypto_DataBlob *out)
{
    if ((key == NULL) || (out == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    char *pemStr = NULL;
    switch (type) {
        case CRYPTO_PEM:
            if (key->getEncodedPem == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            ret = key->getEncodedPem((HcfPriKey *)key, (HcfParamsSpec *)params, encodingStandard, &pemStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            out->data = (uint8_t *)pemStr;
            out->len = strlen(pemStr);
            break;
        case CRYPTO_DER:
            if (encodingStandard != NULL) {
                ret = key->getEncodedDer == NULL ? HCF_INVALID_PARAMS :
                    key->getEncodedDer((HcfPriKey *)key, encodingStandard, (HcfBlob *)out);
                break;
            } else {
                ret = key->base.getEncoded == NULL ? HCF_INVALID_PARAMS
                                                   : key->base.getEncoded((HcfKey *)key, (HcfBlob *)out);
                break;
            }
        default:
            return CRYPTO_INVALID_PARAMS;
    }

    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoPrivKey_GetParam(OH_CryptoPrivKey *key, CryptoAsymKey_ParamType item,
    Crypto_DataBlob *value)
{
    if ((key == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    int32_t *returnInt = NULL;
    char *returnStr = NULL;
    HcfBigInteger bigIntValue = {0};
    switch (item) {
        case CRYPTO_DH_L_INT:
        case CRYPTO_ECC_H_INT:
        case CRYPTO_ECC_FIELD_SIZE_INT:
            returnInt = (int32_t *)HcfMalloc(sizeof(int32_t), 0);
            if (returnInt == NULL) {
                ret = HCF_ERR_MALLOC;
                break;
            }
            ret = key->getAsyKeySpecInt == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecInt((HcfPriKey *)key, (AsyKeySpecItem)item, returnInt);
            if (ret != HCF_SUCCESS) {
                HcfFree(returnInt);
                break;
            }
            value->data = (uint8_t *)returnInt;
            value->len = sizeof(int32_t);
            break;
        case CRYPTO_ECC_FIELD_TYPE_STR:
        case CRYPTO_ECC_CURVE_NAME_STR:
            ret = key->getAsyKeySpecString == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecString((HcfPriKey *)key, (AsyKeySpecItem)item, &returnStr);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)returnStr;
            value->len = strlen(returnStr);
            break;
        default:
            ret = key->getAsyKeySpecBigInteger == NULL ? HCF_INVALID_PARAMS :
                key->getAsyKeySpecBigInteger((HcfPriKey *)key, (AsyKeySpecItem)item, &bigIntValue);
            if (ret != HCF_SUCCESS) {
                break;
            }
            value->data = (uint8_t *)bigIntValue.data;
            value->len = (size_t)bigIntValue.len;
            break;
    }
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_GenEcCommonParamsSpec(const char *curveName, OH_CryptoAsymKeySpec **spec)
{
    if ((curveName == NULL) || (spec == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }

    HcfResult ret = HcfEccKeyUtilCreate(curveName, (HcfEccCommParamsSpec **)spec);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_GenDhCommonParamsSpec(int pLen, int skLen, OH_CryptoAsymKeySpec **spec)
{
    if (spec == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfDhKeyUtilCreate(pLen, skLen, (HcfDhCommParamsSpec **)spec);
    return GetOhCryptoErrCode(ret);
}

static OH_Crypto_ErrCode CreateDsaSpec(OH_CryptoAsymKeySpec **spec, CryptoAsymKeySpec_Type type)
{
    switch(type) {
        case CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfDsaCommParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfDsaPubKeyParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_KEY_PAIR_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfDsaKeyPairParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode CreateRsaSpec(OH_CryptoAsymKeySpec **spec, CryptoAsymKeySpec_Type type)
{
    switch(type) {
        case CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfRsaCommParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfRsaPubKeyParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_KEY_PAIR_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfRsaKeyPairParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode CreateEccSpec(OH_CryptoAsymKeySpec **spec, CryptoAsymKeySpec_Type type)
{
    switch(type) {
        case CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfEccCommParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfEccPriKeyParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfEccPubKeyParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_KEY_PAIR_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfEccKeyPairParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode CreateDhSpec(OH_CryptoAsymKeySpec **spec, CryptoAsymKeySpec_Type type)
{
    switch(type) {
        case CRYPTO_ASYM_KEY_COMMON_PARAMS_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfDhCommParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfDhPriKeyParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfDhPubKeyParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_KEY_PAIR_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfDhKeyPairParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode CreateAlg25519Spec(OH_CryptoAsymKeySpec **spec, CryptoAsymKeySpec_Type type)
{
    switch(type) {
        case CRYPTO_ASYM_KEY_PRIVATE_KEY_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfAlg25519PriKeyParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_PUBLIC_KEY_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfAlg25519PubKeyParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        case CRYPTO_ASYM_KEY_KEY_PAIR_SPEC:
            *spec = (OH_CryptoAsymKeySpec *)HcfMalloc(sizeof(HcfAlg25519KeyPairParamsSpec), 0);
            if (*spec == NULL) {
                return CRYPTO_MEMORY_ERROR;
            };
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_Create(const char *algoName, CryptoAsymKeySpec_Type type,
    OH_CryptoAsymKeySpec **spec)
{
    if ((algoName == NULL) || (spec == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfAsyKeyGenParams params = { 0 };
    HcfResult ret = ParseAlgNameToParams(algoName, &params);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCode(ret);
    }

    OH_Crypto_ErrCode res = CRYPTO_SUCCESS;
    switch(params.algo) {
        case HCF_ALG_DSA:
            res = CreateDsaSpec(spec, type);
            break;
        case HCF_ALG_RSA:
            res = CreateRsaSpec(spec, type);
            break;
        case HCF_ALG_ECC:
        case HCF_ALG_SM2:
            res = CreateEccSpec(spec, type);
            break;
        case HCF_ALG_DH:
            res = CreateDhSpec(spec, type);
            break;
        case HCF_ALG_ED25519:
        case HCF_ALG_X25519:
            res = CreateAlg25519Spec(spec, type);
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }

    if (res != CRYPTO_SUCCESS) {
        HcfFree(*spec);
        *spec = NULL;
        return res;
    }

    char *algName = (char *)HcfMalloc(strlen(algoName) + 1, 0);
    if (algName == NULL) {
        HcfFree(*spec);
        *spec = NULL;
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(algName, strlen(algoName), algoName, strlen(algoName));
    (*spec)->specType = (HcfAsyKeySpecType)type;
    (*spec)->algName = algName;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDsaCommSpec(HcfDsaCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DSA_P_DATABLOB:
            spec->p.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->p.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->p.data, value->len, value->data, value->len);
            spec->p.len = value->len;
            break;
        case CRYPTO_DSA_Q_DATABLOB:
            spec->q.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->q.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->q.data, value->len, value->data, value->len);
            spec->q.len = value->len;
            break;
        case CRYPTO_DSA_G_DATABLOB:
            spec->g.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->g.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->g.data, value->len, value->data, value->len);
            spec->g.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDsaPubKeySpec(HcfDsaPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DSA_PK_DATABLOB:
            spec->pk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.data, value->len, value->data, value->len);
            spec->pk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDsaKeyPairSpec(HcfDsaKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DSA_SK_DATABLOB:
            spec->sk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->sk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->sk.data, value->len, value->data, value->len);
            spec->sk.len = value->len;
            break;
        case CRYPTO_DSA_PK_DATABLOB:
            spec->pk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.data, value->len, value->data, value->len);
            spec->pk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDsaSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (SetDsaCommSpec((HcfDsaCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch(spec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            return SetDsaPubKeySpec((HcfDsaPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetDsaKeyPairSpec((HcfDsaKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode SetRsaCommSpec(HcfRsaCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_RSA_N_DATABLOB:
            spec->n.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->n.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->n.data, value->len, value->data, value->len);
            spec->n.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetRsaPubKeySpec(HcfRsaPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_RSA_E_DATABLOB:
            spec->pk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.data, value->len, value->data, value->len);
            spec->pk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetRsaKeyPairSpec(HcfRsaKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_RSA_D_DATABLOB:
            spec->sk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->sk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->sk.data, value->len, value->data, value->len);
            spec->sk.len = value->len;
            break;
        case CRYPTO_RSA_E_DATABLOB:
            spec->pk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.data, value->len, value->data, value->len);
            spec->pk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetRsaSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (SetRsaCommSpec((HcfRsaCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch(spec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            return SetRsaPubKeySpec((HcfRsaPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetRsaKeyPairSpec((HcfRsaKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode SetEccField(HcfEccCommParamsSpec *spec, Crypto_DataBlob *value)
{
    HcfECFieldFp *field = (HcfECFieldFp *)HcfMalloc(sizeof(HcfECFieldFp), 0);
    if (field == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    char *fieldType = "Fp";
    size_t fieldTypeLen = strlen(fieldType);
    field->base.fieldType = (char *)HcfMalloc(fieldTypeLen + 1, 0);
    if (field->base.fieldType == NULL) {
        HcfFree(field);
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(field->base.fieldType, fieldTypeLen, fieldType, fieldTypeLen);
    field->p.data = (uint8_t *)HcfMalloc(value->len, 0);
    if (field->p.data == NULL) {
        HcfFree(field->base.fieldType);
        HcfFree(field);
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(field->p.data, value->len, value->data, value->len);
    field->p.len = value->len;
    spec->field = (HcfECField *)field;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetEccCommSpec(HcfEccCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ECC_FP_P_DATABLOB:
            return SetEccField(spec, value);
        case CRYPTO_ECC_A_DATABLOB:
            spec->a.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->a.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->a.data, value->len, value->data, value->len);
            spec->a.len = value->len;
            break;
        case CRYPTO_ECC_B_DATABLOB:
            spec->b.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->b.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->b.data, value->len, value->data, value->len);
            spec->b.len = value->len;
            break;
        case CRYPTO_ECC_G_X_DATABLOB:
            spec->g.x.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->g.x.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->g.x.data, value->len, value->data, value->len);
            spec->g.x.len = value->len;
            break;
        case CRYPTO_ECC_G_Y_DATABLOB:
            spec->g.y.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->g.y.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->g.y.data, value->len, value->data, value->len);
            spec->g.y.len = value->len;
            break;
        case CRYPTO_ECC_N_DATABLOB:
            spec->n.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->n.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->n.data, value->len, value->data, value->len);
            spec->n.len = value->len;
            break;
        case CRYPTO_ECC_H_INT:
            if (value->len != sizeof(spec->h)) {
                return CRYPTO_INVALID_PARAMS;
            }
            spec->h = *((int *)(value->data));
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetEccPriSpec(HcfEccPriKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ECC_SK_DATABLOB:
            spec->sk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->sk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->sk.data, value->len, value->data, value->len);
            spec->sk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetEccPubKeySpec(HcfEccPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ECC_PK_X_DATABLOB:
            spec->pk.x.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.x.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.x.data, value->len, value->data, value->len);
            spec->pk.x.len = value->len;
            break;
        case CRYPTO_ECC_PK_Y_DATABLOB:
            spec->pk.y.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.y.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.y.data, value->len, value->data, value->len);
            spec->pk.y.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ECC_SK_DATABLOB:
            spec->sk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->sk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->sk.data, value->len, value->data, value->len);
            spec->sk.len = value->len;
            break;
        case CRYPTO_ECC_PK_X_DATABLOB:
            spec->pk.x.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.x.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.x.data, value->len, value->data, value->len);
            spec->pk.x.len = value->len;
            break;
        case CRYPTO_ECC_PK_Y_DATABLOB:
            spec->pk.y.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.y.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.y.data, value->len, value->data, value->len);
            spec->pk.y.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetEccSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (SetEccCommSpec((HcfEccCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch(spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return SetEccPriSpec((HcfEccPriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return SetEccPubKeySpec((HcfEccPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetEccKeyPairSpec((HcfEccKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode SetDhCommSpec(HcfDhCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DH_P_DATABLOB:
            spec->p.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->p.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->p.data, value->len, value->data, value->len);
            spec->p.len = value->len;
            break;
        case CRYPTO_DH_G_DATABLOB:
            spec->g.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->g.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->g.data, value->len, value->data, value->len);
            spec->g.len = value->len;
            break;
        case CRYPTO_DH_L_INT:
            if (value->len != sizeof(spec->length)) {
                return CRYPTO_INVALID_PARAMS;
            }
            spec->length = *((int *)(value->data));
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDhPriKeySpec(HcfDhPriKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DH_SK_DATABLOB:
            spec->sk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->sk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->sk.data, value->len, value->data, value->len);
            spec->sk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDhPubKeySpec(HcfDhPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DH_PK_DATABLOB:
            spec->pk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.data, value->len, value->data, value->len);
            spec->pk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDhKeyPairSpec(HcfDhKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DH_SK_DATABLOB:
            spec->sk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->sk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->sk.data, value->len, value->data, value->len);
            spec->sk.len = value->len;
            break;
        case CRYPTO_DH_PK_DATABLOB:
            spec->pk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.data, value->len, value->data, value->len);
            spec->pk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDhSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (SetDhCommSpec((HcfDhCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch(spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return SetDhPriKeySpec((HcfDhPriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return SetDhPubKeySpec((HcfDhPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetDhKeyPairSpec((HcfDhKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode SetAlg25519PriKeySpec(HcfAlg25519PriKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ED25519_SK_DATABLOB:
        case CRYPTO_X25519_SK_DATABLOB:
            spec->sk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->sk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->sk.data, value->len, value->data, value->len);
            spec->sk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetAlg25519PubKeySpec(HcfAlg25519PubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ED25519_PK_DATABLOB:
        case CRYPTO_X25519_PK_DATABLOB:
            spec->pk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.data, value->len, value->data, value->len);
            spec->pk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetAlg25519KeyPairSpec(HcfAlg25519KeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ED25519_SK_DATABLOB:
        case CRYPTO_X25519_SK_DATABLOB:
            spec->sk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->sk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->sk.data, value->len, value->data, value->len);
            spec->sk.len = value->len;
            break;
        case CRYPTO_ED25519_PK_DATABLOB:
        case CRYPTO_X25519_PK_DATABLOB:
            spec->pk.data = (uint8_t *)HcfMalloc(value->len, 0);
            if (spec->pk.data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(spec->pk.data, value->len, value->data, value->len);
            spec->pk.len = value->len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetAlg25519Spec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return SetAlg25519PriKeySpec((HcfAlg25519PriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return SetAlg25519PubKeySpec((HcfAlg25519PubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return SetAlg25519KeyPairSpec((HcfAlg25519KeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_SetParam(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    if ((spec == NULL) || (value == NULL) || (value->data == NULL) || (value->len == 0)) {
        return CRYPTO_INVALID_PARAMS;
    }

    HcfAsyKeyGenParams params = { 0 };
    HcfResult ret = ParseAlgNameToParams(spec->algName, &params);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCode(ret);
    }

    switch(params.algo) {
        case HCF_ALG_DSA:
            return SetDsaSpec(spec, type, value);
        case HCF_ALG_RSA:
            return SetRsaSpec(spec, type, value);
        case HCF_ALG_ECC:
        case HCF_ALG_SM2:
            return SetEccSpec(spec, type, value);
        case HCF_ALG_DH:
            return SetDhSpec(spec, type, value);
        case HCF_ALG_ED25519:
        case HCF_ALG_X25519:
            return SetAlg25519Spec(spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode SetEccCommonSpec(HcfEccCommParamsSpec *commonParamsSpec, HcfEccCommParamsSpec *spec)
{
    HcfEccCommParamsSpec eccCommParamsSpec = {};
    HcfResult ret = CopyEccCommonSpec(commonParamsSpec, &eccCommParamsSpec);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCode(ret);
    }
    spec->field = eccCommParamsSpec.field;
    spec->field->fieldType = eccCommParamsSpec.field->fieldType;
    ((HcfECFieldFp *)(spec->field))->p.data = ((HcfECFieldFp *)(eccCommParamsSpec.field))->p.data;
    ((HcfECFieldFp *)(spec->field))->p.len = ((HcfECFieldFp *)(eccCommParamsSpec.field))->p.len;
    spec->a.data = eccCommParamsSpec.a.data;
    spec->a.len = eccCommParamsSpec.a.len;
    spec->b.data = eccCommParamsSpec.b.data;
    spec->b.len = eccCommParamsSpec.b.len;
    spec->g.x.data = eccCommParamsSpec.g.x.data;
    spec->g.x.len = eccCommParamsSpec.g.x.len;
    spec->g.y.data = eccCommParamsSpec.g.y.data;
    spec->g.y.len = eccCommParamsSpec.g.y.len;
    spec->n.data = eccCommParamsSpec.n.data;
    spec->n.len = eccCommParamsSpec.n.len;
    spec->h = eccCommParamsSpec.h;
    HcfFree(eccCommParamsSpec.base.algName);
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetDhCommonSpec(HcfDhCommParamsSpec *commonParamsSpec, HcfDhCommParamsSpec *spec)
{
    HcfDhCommParamsSpec dhCommParamsSpec = {};
    HcfResult ret = CopyDhCommonSpec(commonParamsSpec, &dhCommParamsSpec);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCode(ret);
    }
    spec->p.data = dhCommParamsSpec.p.data;
    spec->p.len = dhCommParamsSpec.p.len;
    spec->g.data = dhCommParamsSpec.g.data;
    spec->g.len = dhCommParamsSpec.g.len;
    spec->length = dhCommParamsSpec.length;
    HcfFree(dhCommParamsSpec.base.algName);
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_SetCommonParamsSpec(OH_CryptoAsymKeySpec *spec,
    OH_CryptoAsymKeySpec *commonParamsSpec)
{
    if ((spec == NULL) || (commonParamsSpec == NULL) || (commonParamsSpec->specType != HCF_COMMON_PARAMS_SPEC)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfAsyKeyGenParams params = { 0 };
    HcfResult ret = ParseAlgNameToParams(spec->algName, &params);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCode(ret);
    }

    switch(params.algo) {
        case HCF_ALG_ECC:
        case HCF_ALG_SM2:
            return SetEccCommonSpec((HcfEccCommParamsSpec *)commonParamsSpec, (HcfEccCommParamsSpec *)spec);
            break;
        case HCF_ALG_DH:
            return SetDhCommonSpec((HcfDhCommParamsSpec *)commonParamsSpec, (HcfDhCommParamsSpec *)spec);
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode GetDsaCommSpec(HcfDsaCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DSA_P_DATABLOB:
            if (spec->p.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->p.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->p.len, spec->p.data, spec->p.len);
            value->len = spec->p.len;
            break;
        case CRYPTO_DSA_Q_DATABLOB:
            if (spec->q.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->q.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->q.len, spec->q.data, spec->q.len);
            value->len = spec->q.len;
            break;
        case CRYPTO_DSA_G_DATABLOB:
            if (spec->g.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->g.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->g.len, spec->g.data, spec->g.len);
             value->len = spec->g.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetDsaPubKeySpec(HcfDsaPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DSA_PK_DATABLOB:
            if (spec->pk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.len, spec->pk.data, spec->pk.len);
            value->len = spec->pk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetDsaKeyPairSpec(HcfDsaKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DSA_SK_DATABLOB:
            if (spec->sk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->sk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->sk.len, spec->sk.data, spec->sk.len);
            value->len = spec->sk.len;
            break;
        case CRYPTO_DSA_PK_DATABLOB:
            if (spec->pk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.len, spec->pk.data, spec->pk.len);
            value->len = spec->pk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetDsaSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (GetDsaCommSpec((HcfDsaCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch(spec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            return GetDsaPubKeySpec((HcfDsaPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetDsaKeyPairSpec((HcfDsaKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode GetRsaCommSpec(HcfRsaCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_RSA_N_DATABLOB:
            if (spec->n.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->n.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->n.len, spec->n.data, spec->n.len);
            value->len = spec->n.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetRsaPubKeySpec(HcfRsaPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_RSA_E_DATABLOB:
            if (spec->pk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.len, spec->pk.data, spec->pk.len);
            value->len = spec->pk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetRsaKeyPairSpec(HcfRsaKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_RSA_D_DATABLOB:
            if (spec->sk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->sk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->sk.len, spec->sk.data, spec->sk.len);
            value->len = spec->sk.len;
            break;
        case CRYPTO_RSA_E_DATABLOB:
            if (spec->pk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.len, spec->pk.data, spec->pk.len);
            value->len = spec->pk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetRsaSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (GetRsaCommSpec((HcfRsaCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch(spec->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            return GetRsaPubKeySpec((HcfRsaPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetRsaKeyPairSpec((HcfRsaKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode GetEccField(HcfEccCommParamsSpec *spec, Crypto_DataBlob *value)
{
    if ((spec->field == NULL) || (((HcfECFieldFp *)(spec->field))->p.data == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    uint8_t *pData = ((HcfECFieldFp *)(spec->field))->p.data;
    uint32_t pLen = ((HcfECFieldFp *)(spec->field))->p.len;
    value->data = (uint8_t *)HcfMalloc(pLen, 0);
    if (value->data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(value->data, pLen, pData, pLen);
    value->len = pLen;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetEccCommSpec(HcfEccCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ECC_FP_P_DATABLOB:
            return GetEccField(spec, value);
        case CRYPTO_ECC_A_DATABLOB:
            if (spec->a.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->a.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->a.len, spec->a.data, spec->a.len);
            value->len = spec->a.len;
            break;
        case CRYPTO_ECC_B_DATABLOB:
            if (spec->b.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->b.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->b.len, spec->b.data, spec->b.len);
            value->len = spec->b.len;
            break;
        case CRYPTO_ECC_G_X_DATABLOB:
            if (spec->g.x.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->g.x.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->g.x.len, spec->g.x.data, spec->g.x.len);
            value->len = spec->g.x.len;
            break;
        case CRYPTO_ECC_G_Y_DATABLOB:
            if (spec->g.y.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->g.y.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->g.y.len, spec->g.y.data, spec->g.y.len);
            value->len = spec->g.y.len;
            break;
        case CRYPTO_ECC_N_DATABLOB:
            if (spec->n.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->n.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->n.len, spec->n.data, spec->n.len);
            value->len = spec->n.len;
            break;
        case CRYPTO_ECC_H_INT:
            value->data = (uint8_t *)HcfMalloc(sizeof(spec->h), 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, sizeof(spec->h), &(spec->h), sizeof(spec->h));
            value->len = sizeof(spec->h);
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetEccPriSpec(HcfEccPriKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ECC_SK_DATABLOB:
            if (spec->sk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->sk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->sk.len, spec->sk.data, spec->sk.len);
            value->len = spec->sk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetEccPubKeySpec(HcfEccPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ECC_PK_X_DATABLOB:
            if (spec->pk.x.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.x.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.x.len, spec->pk.x.data, spec->pk.x.len);
            value->len = spec->pk.x.len;
            break;
        case CRYPTO_ECC_PK_Y_DATABLOB:
            if (spec->pk.y.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.y.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.y.len, spec->pk.y.data, spec->pk.y.len);
            value->len = spec->pk.y.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ECC_SK_DATABLOB:
            if (spec->sk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->sk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->sk.len, spec->sk.data, spec->sk.len);
            value->len = spec->sk.len;
            break;
        case CRYPTO_ECC_PK_X_DATABLOB:
            if (spec->pk.x.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.x.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.x.len, spec->pk.x.data, spec->pk.x.len);
            value->len = spec->pk.x.len;
            break;
        case CRYPTO_ECC_PK_Y_DATABLOB:
            if (spec->pk.y.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.y.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.y.len, spec->pk.y.data, spec->pk.y.len);
            value->len = spec->pk.y.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetEccSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (GetEccCommSpec((HcfEccCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch(spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return GetEccPriSpec((HcfEccPriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return GetEccPubKeySpec((HcfEccPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetEccKeyPairSpec((HcfEccKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode GetDhCommSpec(HcfDhCommParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DH_P_DATABLOB:
            if (spec->p.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->p.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->p.len, spec->p.data, spec->p.len);
            value->len = spec->p.len;
            break;
        case CRYPTO_DH_G_DATABLOB:
            if (spec->g.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->g.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->g.len, spec->g.data, spec->g.len);
             value->len = spec->g.len;
            break;
        case CRYPTO_DH_L_INT:
            value->data = (uint8_t *)HcfMalloc(sizeof(spec->length), 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, sizeof(spec->length), &(spec->length), sizeof(spec->length));
            value->len = sizeof(spec->length);
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetDhPriSpec(HcfDhPriKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DH_SK_DATABLOB:
            if (spec->sk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->sk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->sk.len, spec->sk.data, spec->sk.len);
            value->len = spec->sk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetDhPubKeySpec(HcfDhPubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DH_PK_DATABLOB:
            if (spec->pk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.len, spec->pk.data, spec->pk.len);
            value->len = spec->pk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetDhKeyPairSpec(HcfDhKeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_DH_SK_DATABLOB:
            if (spec->sk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->sk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->sk.len, spec->sk.data, spec->sk.len);
            value->len = spec->sk.len;
            break;
        case CRYPTO_DH_PK_DATABLOB:
            if (spec->pk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.len, spec->pk.data, spec->pk.len);
            value->len = spec->pk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetDhSpec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    if (GetDhCommSpec((HcfDhCommParamsSpec *)spec, type, value) == CRYPTO_SUCCESS) {
        return CRYPTO_SUCCESS;
    }
    switch(spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return GetDhPriSpec((HcfDhPriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return GetDhPubKeySpec((HcfDhPubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetDhKeyPairSpec((HcfDhKeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

static OH_Crypto_ErrCode GetAlg25519PriSpec(HcfAlg25519PriKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ED25519_SK_DATABLOB:
        case CRYPTO_X25519_SK_DATABLOB:
            if (spec->sk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->sk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->sk.len, spec->sk.data, spec->sk.len);
            value->len = spec->sk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetAlg25519PubKeySpec(HcfAlg25519PubKeyParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ED25519_PK_DATABLOB:
        case CRYPTO_X25519_PK_DATABLOB:
            if (spec->pk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.len, spec->pk.data, spec->pk.len);
            value->len = spec->pk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetAlg25519KeyPairSpec(HcfAlg25519KeyPairParamsSpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(type) {
        case CRYPTO_ED25519_SK_DATABLOB:
        case CRYPTO_X25519_SK_DATABLOB:
            if (spec->sk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->sk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->sk.len, spec->sk.data, spec->sk.len);
            value->len = spec->sk.len;
            break;
        case CRYPTO_ED25519_PK_DATABLOB:
        case CRYPTO_X25519_PK_DATABLOB:
            if (spec->pk.data == NULL) {
                return CRYPTO_INVALID_PARAMS;
            }
            value->data = (uint8_t *)HcfMalloc(spec->pk.len, 0);
            if (value->data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(value->data, spec->pk.len, spec->pk.data, spec->pk.len);
            value->len = spec->pk.len;
            break;
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode GetAlg25519Spec(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type, Crypto_DataBlob *value)
{
    switch(spec->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            return GetAlg25519PriSpec((HcfAlg25519PriKeyParamsSpec *)spec, type, value);
        case HCF_PUBLIC_KEY_SPEC:
            return GetAlg25519PubKeySpec((HcfAlg25519PubKeyParamsSpec *)spec, type, value);
        case HCF_KEY_PAIR_SPEC:
            return GetAlg25519KeyPairSpec((HcfAlg25519KeyPairParamsSpec *)spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

OH_Crypto_ErrCode OH_CryptoAsymKeySpec_GetParam(OH_CryptoAsymKeySpec *spec, CryptoAsymKey_ParamType type,
    Crypto_DataBlob *value)
{
    if ((spec == NULL) || (value == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }

    HcfAsyKeyGenParams params = { 0 };
    HcfResult ret = ParseAlgNameToParams(spec->algName, &params);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCode(ret);
    }

    switch(params.algo) {
        case HCF_ALG_DSA:
            return GetDsaSpec(spec, type, value);
        case HCF_ALG_RSA:
            return GetRsaSpec(spec, type, value);
        case HCF_ALG_ECC:
        case HCF_ALG_SM2:
            return GetEccSpec(spec, type, value);
        case HCF_ALG_DH:
            return GetDhSpec(spec, type, value);
        case HCF_ALG_ED25519:
        case HCF_ALG_X25519:
            return GetAlg25519Spec(spec, type, value);
        default:
            return CRYPTO_INVALID_PARAMS;
    }
}

void OH_CryptoAsymKeySpec_Destroy(OH_CryptoAsymKeySpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeAsyKeySpec((HcfAsyKeyParamsSpec *)spec);
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGeneratorWithSpec_Create(OH_CryptoAsymKeySpec *keySpec,
    OH_CryptoAsymKeyGeneratorWithSpec **generator)
{
    if ((keySpec == NULL) || (generator == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfAsyKeyGeneratorBySpecCreate((HcfAsyKeyParamsSpec *)keySpec, (HcfAsyKeyGeneratorBySpec **)generator);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoAsymKeyGeneratorWithSpec_GenKeyPair(OH_CryptoAsymKeyGeneratorWithSpec *generator,
    OH_CryptoKeyPair **keyPair)
{
    if ((generator == NULL) || (keyPair == NULL)) {
        return CRYPTO_INVALID_PARAMS;

    }
    HcfResult ret = generator->generateKeyPair((HcfAsyKeyGeneratorBySpec *)generator, (HcfKeyPair **)keyPair);
    return GetOhCryptoErrCode(ret);
}

void OH_CryptoAsymKeyGeneratorWithSpec_Destroy(OH_CryptoAsymKeyGeneratorWithSpec *generator)
{
    HcfObjDestroy(generator);
}

OH_Crypto_ErrCode OH_CryptoEcPoint_Create(const char *curveName, Crypto_DataBlob *ecKeyData, OH_CryptoEcPoint **point)
{
    if ((curveName == NULL) || (point == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    *point = (OH_CryptoEcPoint*)HcfMalloc(sizeof(OH_CryptoEcPoint), 0);
    if (*point == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (*point)->curveName = (char *)HcfMalloc(strlen(curveName) + 1, 0);
    if (*point == NULL) {
        HcfFree(*point);
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s((*point)->curveName, strlen(curveName), curveName, strlen(curveName));
    if (ecKeyData == NULL) {
        return CRYPTO_SUCCESS;
    }
    HcfResult ret = HcfConvertPoint(curveName, (HcfBlob *)ecKeyData, &((*point)->pointBase));
    if (ret != HCF_SUCCESS) {
        HcfFree(*point);
        *point = NULL;
    }
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoEcPoint_GetCoordinate(OH_CryptoEcPoint *point, Crypto_DataBlob *x, Crypto_DataBlob *y)
{
    if ((point == NULL) || (x == NULL) || (y == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfPoint dPoint = {};
    HcfResult ret = CopyPoint(&(point->pointBase), &dPoint);
    if (ret != HCF_SUCCESS) {
        return GetOhCryptoErrCode(ret);
    }
    x->data = dPoint.x.data;
    y->data = dPoint.y.data;
    x->len = dPoint.x.len;
    y->len = dPoint.y.len;
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoEcPoint_SetCoordinate(OH_CryptoEcPoint *point, Crypto_DataBlob *x, Crypto_DataBlob *y)
{
    if ((point == NULL) || (x == NULL) || (y == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfPoint sPoint = {};
    sPoint.x.data = x->data;
    sPoint.x.len = x->len;
    sPoint.y.data = y->data;
    sPoint.y.len = y->len;
    HcfResult ret = CopyPoint(&sPoint, &(point->pointBase));
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoEcPoint_Encode(OH_CryptoEcPoint *point, const char *format, Crypto_DataBlob *out)
{
    if ((point == NULL) || (format == NULL) || (out == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfGetEncodedPoint(point->curveName, &(point->pointBase), format, (HcfBlob *)out);
    return GetOhCryptoErrCode(ret);
}

void OH_CryptoEcPoint_Destroy(OH_CryptoEcPoint *point)
{
    if (point == NULL) {
        return;
    }
    HcfFree(point->curveName);
    point->curveName = NULL;
    FreeEcPointMem(&(point->pointBase));
    HcfFree(point);
}