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

#include "crypto_kdf.h"
#include <stdlib.h>
#include "securec.h"
#include "crypto_common.h"
#include "native_common.h"
#include "memory.h"
#include "kdf.h"
#include "kdf_params.h"
#include "detailed_hkdf_params.h"
#include "detailed_pbkdf2_params.h"
#include "detailed_scrypt_params.h"

typedef struct OH_CryptoKdf {
    HcfObjectBase base;

    const char *(*getAlgorithm)(HcfKdf *self);

    HcfResult (*generateSecret)(HcfKdf *self, HcfKdfParamsSpec* paramsSpec);
} OH_CryptoKdf;


typedef struct OH_CryptoKdfParams {
    const char *algName;
} OH_CryptoKdfParams;

static const char *g_hkdfName = "HKDF";
static const char *g_pbkdf2Name = "PBKDF2";
static const char *g_scryptName = "SCRYPT";

OH_Crypto_ErrCode OH_CryptoKdfParams_Create(const char *algoName, OH_CryptoKdfParams **params)
{
    if ((algoName == NULL) || (params == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }

    OH_CryptoKdfParams *tmParams = NULL;
    const char *algName = NULL;
    if (strcmp(algoName, g_hkdfName) == 0) {
        tmParams = (OH_CryptoKdfParams *)HcfMalloc(sizeof(HcfHkdfParamsSpec), 0);
        algName = g_hkdfName;
    } else if (strcmp(algoName, g_pbkdf2Name) == 0) {
        tmParams = (OH_CryptoKdfParams *)HcfMalloc(sizeof(HcfPBKDF2ParamsSpec), 0);
        algName = g_pbkdf2Name;
    } else if (strcmp(algoName, g_scryptName) == 0) {
        tmParams = (OH_CryptoKdfParams *)HcfMalloc(sizeof(HcfScryptParamsSpec), 0);
        algName = g_scryptName;
    } else {
        return CRYPTO_INVALID_PARAMS;
    }
    if (tmParams == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    tmParams->algName = algName;
    *params = tmParams;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetHkdfParam(HcfHkdfParamsSpec *params, CryptoKdf_ParamType type, Crypto_DataBlob *value)
{
    uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
    if (data == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    (void)memcpy_s(data, value->len, value->data, value->len);
    switch (type) {
        case CRYPTO_KDF_KEY_DATABLOB:
            params->key.data = data;
            params->key.len = value->len;
            break;
        case CRYPTO_KDF_SALT_DATABLOB:
            params->salt.data = data;
            params->salt.len = value->len;
            break;
        case CRYPTO_KDF_INFO_DATABLOB:
            params->info.data = data;
            params->info.len = value->len;
            break;
        default:
            HcfFree(data);
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetPbkdf2Param(HcfPBKDF2ParamsSpec *params, CryptoKdf_ParamType type, Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_KDF_KEY_DATABLOB: {
            uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
            if (data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(data, value->len, value->data, value->len);
            params->password.data = data;
            params->password.len = value->len;
            break;
        }
        case CRYPTO_KDF_SALT_DATABLOB: {
            uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
            if (data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            params->salt.data = data;
            params->salt.len = value->len;
            break;
        }
        case CRYPTO_KDF_ITER_COUNT_INT: {
            if (value->len != sizeof(int)) {
                return CRYPTO_INVALID_PARAMS;
            }
            params->iterations = *(int *)(value->data);
            break;
        }
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode SetScryptParam(HcfScryptParamsSpec *params, CryptoKdf_ParamType type, Crypto_DataBlob *value)
{
    switch (type) {
        case CRYPTO_KDF_KEY_DATABLOB: {
            uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
            if (data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(data, value->len, value->data, value->len);
            params->passPhrase.data = data;
            params->passPhrase.len = value->len;
            break;
        }
        case CRYPTO_KDF_SALT_DATABLOB: {
            uint8_t *data = (uint8_t *)HcfMalloc(value->len, 0);
            if (data == NULL) {
                return CRYPTO_MEMORY_ERROR;
            }
            (void)memcpy_s(data, value->len, value->data, value->len);
            params->salt.data = data;
            params->salt.len = value->len;
            break;
        }
        case CRYPTO_KDF_SCRYPT_N_UINT64: {
            if (value->len != sizeof(uint64_t)) {
                return CRYPTO_INVALID_PARAMS;
            }
            params->n = *(uint64_t *)(value->data);
            break;
        }
        case CRYPTO_KDF_SCRYPT_R_UINT64: {
            if (value->len != sizeof(uint64_t)) {
                return CRYPTO_INVALID_PARAMS;
            }
            params->r = *(uint64_t *)(value->data);
            break;
        }
        case CRYPTO_KDF_SCRYPT_P_UINT64: {
            if (value->len != sizeof(uint64_t)) {
                return CRYPTO_INVALID_PARAMS;
            }
            params->p = *(uint64_t *)(value->data);
            break;
        }
        case CRYPTO_KDF_SCRYPT_MAX_MEM_UINT64: {
            if (value->len != sizeof(uint64_t)) {
                return CRYPTO_INVALID_PARAMS;
            }
            params->maxMem = *(uint64_t *)(value->data);
            break;
        }
        default:
            return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoKdfParams_SetParam(OH_CryptoKdfParams *params, CryptoKdf_ParamType type,
    Crypto_DataBlob *value)
{
    if ((params == NULL) || (params->algName == NULL) || (value == NULL) || (value->data == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    if (strcmp(params->algName, g_hkdfName) == 0) {
        return SetHkdfParam((HcfHkdfParamsSpec*)params, type, value);
    } else if (strcmp(params->algName, g_pbkdf2Name) == 0) {
        return SetPbkdf2Param((HcfPBKDF2ParamsSpec*)params, type, value);
    } else if (strcmp(params->algName, g_scryptName) == 0) {
        return SetScryptParam((HcfScryptParamsSpec*)params, type, value);
    } else {
        return CRYPTO_INVALID_PARAMS;
    }
}

static void FreeHkdfParamSpec(HcfHkdfParamsSpec *params)
{
    HcfBlobDataClearAndFree(&(params->key));
    HcfBlobDataClearAndFree(&(params->salt));
    HcfBlobDataClearAndFree(&(params->info));
    HcfBlobDataClearAndFree(&(params->output));
}

static void FreePbkdf2ParamSpec(HcfPBKDF2ParamsSpec *params)
{
    HcfBlobDataClearAndFree(&(params->password));
    HcfBlobDataClearAndFree(&(params->salt));
    HcfBlobDataClearAndFree(&(params->output));
}

static void FreeScryptParamSpec(HcfScryptParamsSpec *params)
{
    HcfBlobDataClearAndFree(&(params->passPhrase));
    HcfBlobDataClearAndFree(&(params->salt));
    HcfBlobDataClearAndFree(&(params->output));
}

static void FreeParamSpec(OH_CryptoKdfParams *params)
{
    if (params->algName == NULL) {
        return;
    }
    if (strcmp(params->algName, g_hkdfName) == 0) {
        FreeHkdfParamSpec((HcfHkdfParamsSpec*)params);
    } else if (strcmp(params->algName, g_pbkdf2Name) == 0) {
        FreePbkdf2ParamSpec((HcfPBKDF2ParamsSpec*)params);
    } else if (strcmp(params->algName, g_scryptName) == 0) {
        FreeScryptParamSpec((HcfScryptParamsSpec*)params);
    }
}

void OH_CryptoKdfParams_Destroy(OH_CryptoKdfParams *params)
{
    if (params == NULL) {
        return;
    }
    FreeParamSpec(params);
    params->algName = NULL;
    HcfFree(params);
}

OH_Crypto_ErrCode OH_CryptoKdf_Create(const char *algoName, OH_CryptoKdf **ctx)
{
    if ((algoName == NULL) || (ctx == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfKdfCreate(algoName, (HcfKdf **)ctx);
    return GetOhCryptoErrCode(ret);
}

static OH_Crypto_ErrCode HkdfDerive(HcfKdf *ctx, const HcfHkdfParamsSpec *params, int keyLen, HcfBlob *key)
{
    uint8_t *out = (uint8_t *)HcfMalloc(keyLen, 0);
    if (out == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfBlob output = {.data = out, .len = keyLen};
    HcfHkdfParamsSpec hkdfParams = {
        .base = { .algName = g_hkdfName, },
        .key = params->key,
        .salt = params->salt,
        .info = params->info,
        .output = output,
    };
    HcfResult ret = ctx->generateSecret(ctx, &(hkdfParams.base));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&output);
        return GetOhCryptoErrCode(ret);
    }
    key->data = hkdfParams.output.data;
    key->len = hkdfParams.output.len;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode Pbkdf2Derive(HcfKdf *ctx, const HcfPBKDF2ParamsSpec *params, int keyLen, HcfBlob *key)
{
    uint8_t *out = (uint8_t *)HcfMalloc(keyLen, 0);
    if (out == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfBlob output = {.data = out, .len = keyLen};
    HcfPBKDF2ParamsSpec pbkdf2Params = {
        .base.algName = g_pbkdf2Name,
        .password = params->password,
        .salt = params->salt,
        .iterations = params->iterations,
        .output = output,
    };
    HcfResult ret = ctx->generateSecret(ctx, &(pbkdf2Params.base));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&output);
        return GetOhCryptoErrCode(ret);
    }
    key->data = pbkdf2Params.output.data;
    key->len = pbkdf2Params.output.len;
    return CRYPTO_SUCCESS;
}

static OH_Crypto_ErrCode ScryptDerive(HcfKdf *ctx, const HcfScryptParamsSpec *params, int keyLen, HcfBlob *key)
{
    uint8_t *out = (uint8_t *)HcfMalloc(keyLen, 0);
    if (out == NULL) {
        return CRYPTO_MEMORY_ERROR;
    }
    HcfBlob output = {.data = out, .len = keyLen};
    HcfScryptParamsSpec scryptParams = {
        .base = { .algName = g_scryptName, },
        .passPhrase = params->passPhrase,
        .salt = params->salt,
        .n = params->n,
        .p = params->p,
        .r = params->r,
        .maxMem = params->maxMem,
        .output = output,
    };
    HcfResult ret = ctx->generateSecret(ctx, &(scryptParams.base));
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(&output);
        return GetOhCryptoErrCode(ret);
    }
    key->data = scryptParams.output.data;
    key->len = scryptParams.output.len;
    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode OH_CryptoKdf_Derive(OH_CryptoKdf *ctx, const OH_CryptoKdfParams *params, int keyLen,
    Crypto_DataBlob *key)
{
    if ((ctx == NULL) || (params == NULL) || (params->algName == NULL) || (key == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }

    if (strcmp(params->algName, g_hkdfName) == 0) {
        return HkdfDerive((HcfKdf *)ctx, (HcfHkdfParamsSpec *)params, keyLen, (HcfBlob *)key);
    } else if (strcmp(params->algName, g_pbkdf2Name) == 0) {
        return Pbkdf2Derive((HcfKdf *)ctx, (HcfPBKDF2ParamsSpec*)params, keyLen, (HcfBlob *)key);
    } else if (strcmp(params->algName, g_scryptName) == 0) {
        return ScryptDerive((HcfKdf *)ctx, (HcfScryptParamsSpec*)params, keyLen, (HcfBlob *)key);
    } else {
        return CRYPTO_INVALID_PARAMS;
    }
}

void OH_CryptoKdf_Destroy(OH_CryptoKdf *ctx)
{
    HcfObjDestroy((HcfKdf *)ctx);
}