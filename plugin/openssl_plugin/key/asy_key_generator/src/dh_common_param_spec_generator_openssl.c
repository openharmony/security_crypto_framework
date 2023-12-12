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

#include "dh_common_param_spec_generator_openssl.h"
#include "dh_openssl_common.h"
#include "securec.h"

#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "utils.h"

#define PARAMS_NUM_TWO 2
#define PARAMS_NUM_THREE 3

static HcfResult GenerateDhUnknownGroupEvpKey(int32_t pLen, EVP_PKEY **ppkey)
{
    EVP_PKEY_CTX *paramsCtx = Openssl_EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (paramsCtx == NULL) {
        HcfPrintOpensslError();
        LOGE("Create params ctx failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    do {
        if (Openssl_EVP_PKEY_paramgen_init(paramsCtx) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("Params ctx generate init failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (Openssl_EVP_PKEY_CTX_set_dh_paramgen_prime_len(paramsCtx, pLen) <= 0) {
            HcfPrintOpensslError();
            LOGE("Set length of bits to params ctx failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (Openssl_EVP_PKEY_paramgen(paramsCtx, ppkey) != HCF_OPENSSL_SUCCESS) {
            HcfPrintOpensslError();
            LOGE("Generate params pkey failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    Openssl_EVP_PKEY_CTX_free(paramsCtx);
    return ret;
}

static HcfResult GenerateDhKnownGroupEvpKey(int32_t skLen, char *nidName, EVP_PKEY **ppkey)
{
    HcfResult ret = HCF_SUCCESS;
    EVP_PKEY_CTX *paramsCtx = NULL;
    OSSL_PARAM params[PARAMS_NUM_THREE];

    params[0] = Openssl_OSSL_PARAM_construct_utf8_string("group", nidName, 0);
    if (skLen != 0) {
        params[1] = Openssl_OSSL_PARAM_construct_int("priv_len", &skLen);
        params[PARAMS_NUM_TWO] = Openssl_OSSL_PARAM_construct_end();
    } else {
        params[1] = Openssl_OSSL_PARAM_construct_end();
    }
    do {
        paramsCtx = Openssl_EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        if (paramsCtx == NULL) {
            LOGE("New paramsCtx from name failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (Openssl_EVP_PKEY_keygen_init(paramsCtx) != HCF_OPENSSL_SUCCESS) {
            LOGE("ParamsCtx generate init failed.");
            HcfPrintOpensslError();
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (Openssl_EVP_PKEY_CTX_set_params(paramsCtx, params) != HCF_OPENSSL_SUCCESS) {
            LOGE("ParamsCtx set failed.");
            HcfPrintOpensslError();
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (Openssl_EVP_PKEY_generate(paramsCtx, ppkey) != HCF_OPENSSL_SUCCESS) {
            LOGE("Create generate failed.");
            HcfPrintOpensslError();
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    if (paramsCtx != NULL) {
        Openssl_EVP_PKEY_CTX_free(paramsCtx);
    }
    return ret;
}

static HcfResult BuildCommonParam(EVP_PKEY *dhKey, HcfDhCommParamsSpecSpi *returnCommonParamSpec)
{
    DH *sk = Openssl_EVP_PKEY_get1_DH(dhKey);
    if (sk == NULL) {
        LOGE("Get dh private key from pkey failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigNumToBigInteger(Openssl_DH_get0_p(sk), &(returnCommonParamSpec->paramsSpec.p)) != HCF_SUCCESS) {
        LOGE("BuildCommonParamPrime failed.");
        Openssl_DH_free(sk);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigNumToBigInteger(Openssl_DH_get0_g(sk), &(returnCommonParamSpec->paramsSpec.g)) != HCF_SUCCESS) {
        LOGE("BuildCommonParamGenerator failed.");
        Openssl_DH_free(sk);
        HcfFree(returnCommonParamSpec->paramsSpec.p.data);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_DH_free(sk);
    return HCF_SUCCESS;
}

HcfResult SetAlgName(const char *algName, char **returnAlgName)
{
    size_t srcAlgNameLen = HcfStrlen(algName);
    if (!srcAlgNameLen) {
        LOGE("algName is empty!");
        return HCF_INVALID_PARAMS;
    }
    *returnAlgName = (char *)HcfMalloc(srcAlgNameLen + 1, 0);
    if (*returnAlgName == NULL) {
        LOGE("algName malloc failed.");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(*returnAlgName, srcAlgNameLen, algName, srcAlgNameLen) != EOK) {
        LOGE("memcpy algName failed.");
        HcfFree(*returnAlgName);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult HcfDhCommonParamSpecCreate(uint32_t pLen, int32_t skLen, HcfDhCommParamsSpecSpi **returnCommonParamSpec)
{
    if (returnCommonParamSpec == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    EVP_PKEY *dhKey = NULL;
    char *nidName = GetNidNameByDhPLen(pLen);
    if (nidName == NULL) {
        if (GenerateDhUnknownGroupEvpKey(pLen, &dhKey) != HCF_SUCCESS) {
            LOGE("generate dh unknown group evpKey failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    } else {
        if (GenerateDhKnownGroupEvpKey(skLen, nidName, &dhKey) != HCF_SUCCESS) {
            LOGE("generate dh known group evpKey failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    HcfDhCommParamsSpecSpi *object = (HcfDhCommParamsSpecSpi*)HcfMalloc(sizeof(HcfDhCommParamsSpecSpi), 0);
    if (object == NULL) {
        LOGE("build dh common params object failed.");
        Openssl_EVP_PKEY_free(dhKey);
        return HCF_ERR_MALLOC;
    }
    const char *algName = "DH";
    object->paramsSpec.base.specType = HCF_COMMON_PARAMS_SPEC;
    object->paramsSpec.length = skLen;
    if (SetAlgName(algName, &(object->paramsSpec.base.algName)) != HCF_SUCCESS) {
        LOGE("get algName parameter failed.");
        HcfFree(object);
        Openssl_EVP_PKEY_free(dhKey);
        return HCF_INVALID_PARAMS;
    }
    if (BuildCommonParam(dhKey, object)!= HCF_SUCCESS) {
        LOGE("create keyPair failed.");
        HcfFree(object->paramsSpec.base.algName);
        HcfFree(object);
        Openssl_EVP_PKEY_free(dhKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnCommonParamSpec = object;
    Openssl_EVP_PKEY_free(dhKey);
    return HCF_SUCCESS;
}
