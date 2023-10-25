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

#include "signature.h"

#include <securec.h>

#include "config.h"
#include "dsa_openssl.h"
#include "ecdsa_openssl.h"
#include "log.h"
#include "memory.h"
#include "params_parser.h"
#include "signature_spi.h"
#include "signature_rsa_openssl.h"
#include "sm2_openssl.h"
#include "utils.h"

typedef HcfResult (*HcfSignSpiCreateFunc)(HcfSignatureParams *, HcfSignSpi **);
typedef HcfResult (*HcfVerifySpiCreateFunc)(HcfSignatureParams *, HcfVerifySpi **);

typedef struct {
    HcfSign base;

    HcfSignSpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfSignImpl;

typedef struct {
    HcfVerify base;

    HcfVerifySpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfVerifyImpl;

typedef struct {
    HcfAlgValue algo;

    HcfSignSpiCreateFunc createFunc;
} HcfSignGenAbility;

typedef struct {
    HcfAlgValue algo;

    HcfVerifySpiCreateFunc createFunc;
} HcfVerifyGenAbility;

static const HcfSignGenAbility SIGN_GEN_ABILITY_SET[] = {
    { HCF_ALG_ECC, HcfSignSpiEcdsaCreate },
    { HCF_ALG_RSA, HcfSignSpiRsaCreate },
    { HCF_ALG_DSA, HcfSignSpiDsaCreate },
    { HCF_ALG_SM2, HcfSignSpiSm2Create }
};

static const HcfVerifyGenAbility VERIFY_GEN_ABILITY_SET[] = {
    { HCF_ALG_ECC, HcfVerifySpiEcdsaCreate },
    { HCF_ALG_RSA, HcfVerifySpiRsaCreate },
    { HCF_ALG_DSA, HcfVerifySpiDsaCreate },
    { HCF_ALG_SM2, HcfVerifySpiSm2Create }
};

static HcfSignSpiCreateFunc FindSignAbility(HcfSignatureParams *params)
{
    for (uint32_t i = 0; i < sizeof(SIGN_GEN_ABILITY_SET) / sizeof(SIGN_GEN_ABILITY_SET[0]); i++) {
        if (SIGN_GEN_ABILITY_SET[i].algo == params->algo) {
            return SIGN_GEN_ABILITY_SET[i].createFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %d", params->algo);
    return NULL;
}

static HcfVerifySpiCreateFunc FindVerifyAbility(HcfSignatureParams *params)
{
    for (uint32_t i = 0; i < sizeof(VERIFY_GEN_ABILITY_SET) / sizeof(VERIFY_GEN_ABILITY_SET[0]); i++) {
        if (VERIFY_GEN_ABILITY_SET[i].algo == params->algo) {
            return VERIFY_GEN_ABILITY_SET[i].createFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %d", params->algo);
    return NULL;
}

static void SetKeyTypeDefault(HcfAlgParaValue value,  HcfSignatureParams *paramsObj)
{
    switch (value) {
        case HCF_ALG_ECC_DEFAULT:
            paramsObj->algo = HCF_ALG_ECC;
            break;
        case HCF_ALG_RSA_DEFAULT:
            paramsObj->algo = HCF_ALG_RSA;
            break;
        case HCF_ALG_DSA_DEFAULT:
            paramsObj->algo = HCF_ALG_DSA;
            break;
        case HCF_ALG_SM2_DEFAULT:
            paramsObj->algo = HCF_ALG_SM2;
            break;
        default:
            LOGE("Invalid algo %u.", value);
            break;
    }
}

static void SetKeyType(HcfAlgParaValue value, HcfSignatureParams *paramsObj)
{
    switch (value) {
        case HCF_ALG_ECC_224:
        case HCF_ALG_ECC_256:
        case HCF_ALG_ECC_384:
        case HCF_ALG_ECC_521:
            paramsObj->algo = HCF_ALG_ECC;
            break;
        case HCF_OPENSSL_RSA_512:
        case HCF_OPENSSL_RSA_768:
        case HCF_OPENSSL_RSA_1024:
        case HCF_OPENSSL_RSA_2048:
        case HCF_OPENSSL_RSA_3072:
        case HCF_OPENSSL_RSA_4096:
        case HCF_OPENSSL_RSA_8192:
            paramsObj->algo = HCF_ALG_RSA;
            break;
        case HCF_ALG_DSA_1024:
        case HCF_ALG_DSA_2048:
        case HCF_ALG_DSA_3072:
            paramsObj->algo = HCF_ALG_DSA;
            break;
        case HCF_ALG_SM2_256:
            paramsObj->algo = HCF_ALG_SM2;
            break;
        default:
            LOGE("there is not matched algorithm.");
            break;
    }
}

static HcfResult ParseSignatureParams(const HcfParaConfig *config, void *params)
{
    if (config == NULL || params == NULL) {
        LOGE("Invalid signature params");
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    HcfSignatureParams *paramsObj = (HcfSignatureParams *)params;
    LOGD("Set Parameter: %s", config->tag);
    switch (config->paraType) {
        case HCF_ALG_TYPE:
            SetKeyTypeDefault(config->paraValue, paramsObj);
            break;
        case HCF_ALG_KEY_TYPE:
            SetKeyType(config->paraValue, paramsObj);
            break;
        case HCF_ALG_DIGEST:
            paramsObj->md = config->paraValue;
            break;
        case HCF_ALG_PADDING_TYPE:
            paramsObj->padding = config->paraValue;
            break;
        case HCF_ALG_MGF1_DIGEST:
            paramsObj->mgf1md = config->paraValue;
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static const char *GetSignClass(void)
{
    return "HcfSign";
}

static const char *GetVerifyClass(void)
{
    return "HcfVerify";
}

static const char *GetSignAlgoName(HcfSign *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        return NULL;
    }
    return ((HcfSignImpl *)self)->algoName;
}

static const char *GetVerifyAlgoName(HcfVerify *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        return NULL;
    }
    return ((HcfVerifyImpl *)self)->algoName;
}

static void DestroySign(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetSignClass())) {
        return;
    }
    HcfSignImpl *impl = (HcfSignImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

static void DestroyVerify(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetVerifyClass())) {
        return;
    }
    HcfVerifyImpl *impl = (HcfVerifyImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

static HcfResult SetSignSpecInt(HcfSign *self, SignSpecItem item, int32_t saltLen)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfSignImpl *tmpSelf = (HcfSignImpl *)self;
    return tmpSelf->spiObj->engineSetSignSpecInt(tmpSelf->spiObj, item, saltLen);
}

static HcfResult GetSignSpecString(HcfSign *self, SignSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfSignImpl *tmpSelf = (HcfSignImpl *)self;
    return tmpSelf->spiObj->engineGetSignSpecString(tmpSelf->spiObj, item, returnString);
}

static HcfResult GetSignSpecInt(HcfSign *self, SignSpecItem item, int32_t *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfSignImpl *tmpSelf = (HcfSignImpl *)self;
    return tmpSelf->spiObj->engineGetSignSpecInt(tmpSelf->spiObj, item, returnInt);
}

static HcfResult SignInit(HcfSign *self, HcfParamsSpec *params, HcfPriKey *privateKey)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        return HCF_INVALID_PARAMS;
    }
    return ((HcfSignImpl *)self)->spiObj->engineInit(((HcfSignImpl *)self)->spiObj, params, privateKey);
}

static HcfResult SignUpdate(HcfSign *self, HcfBlob *data)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        return HCF_INVALID_PARAMS;
    }
    return ((HcfSignImpl *)self)->spiObj->engineUpdate(((HcfSignImpl *)self)->spiObj, data);
}

static HcfResult SignDoFinal(HcfSign *self, HcfBlob *data, HcfBlob *returnSignatureData)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, GetSignClass())) {
        return HCF_INVALID_PARAMS;
    }
    return ((HcfSignImpl *)self)->spiObj->engineSign(((HcfSignImpl *)self)->spiObj, data, returnSignatureData);
}

static HcfResult SetVerifySpecInt(HcfVerify *self, SignSpecItem item, int32_t saltLen)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfVerifyImpl *tmpSelf = (HcfVerifyImpl *)self;
    return tmpSelf->spiObj->engineSetVerifySpecInt(tmpSelf->spiObj, item, saltLen);
}

static HcfResult GetVerifySpecString(HcfVerify *self, SignSpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfVerifyImpl *tmpSelf = (HcfVerifyImpl *)self;
    return tmpSelf->spiObj->engineGetVerifySpecString(tmpSelf->spiObj, item, returnString);
}

static HcfResult GetVerifySpecInt(HcfVerify *self, SignSpecItem item, int32_t *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfVerifyImpl *tmpSelf = (HcfVerifyImpl *)self;
    return tmpSelf->spiObj->engineGetVerifySpecInt(tmpSelf->spiObj, item, returnInt);
}

static HcfResult VerifyInit(HcfVerify *self, HcfParamsSpec *params, HcfPubKey *publicKey)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        return HCF_INVALID_PARAMS;
    }
    return ((HcfVerifyImpl *)self)->spiObj->engineInit(((HcfVerifyImpl *)self)->spiObj, params, publicKey);
}

static HcfResult VerifyUpdate(HcfVerify *self, HcfBlob *data)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        return HCF_INVALID_PARAMS;
    }
    return ((HcfVerifyImpl *)self)->spiObj->engineUpdate(((HcfVerifyImpl *)self)->spiObj, data);
}

static bool VerifyDoFinal(HcfVerify *self, HcfBlob *data, HcfBlob *signatureData)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetVerifyClass())) {
        return false;
    }
    return ((HcfVerifyImpl *)self)->spiObj->engineVerify(((HcfVerifyImpl *)self)->spiObj, data, signatureData);
}

HcfResult HcfSignCreate(const char *algoName, HcfSign **returnObj)
{
    LOGD("HcfSignCreate start");
    if ((!IsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN)) || (returnObj == NULL)) {
        return HCF_INVALID_PARAMS;
    }

    HcfSignatureParams params = { 0 };
    if (ParseAndSetParameter(algoName, &params, ParseSignatureParams) != HCF_SUCCESS) {
        LOGE("Failed to parser parmas!");
        return HCF_INVALID_PARAMS;
    }

    HcfSignSpiCreateFunc createSpiFunc = FindSignAbility(&params);
    if (createSpiFunc == NULL) {
        LOGE("Can not find ability.");
        return HCF_NOT_SUPPORT;
    }

    HcfSignImpl *returnSign = (HcfSignImpl *)HcfMalloc(sizeof(HcfSignImpl), 0);
    if (returnSign == NULL) {
        LOGE("Failed to allocate returnSign memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnSign->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnSign);
        return HCF_INVALID_PARAMS;
    }
    HcfSignSpi *spiObj = NULL;
    HcfResult res = createSpiFunc(&params, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnSign);
        return res;
    }
    returnSign->base.base.destroy = DestroySign;
    returnSign->base.base.getClass = GetSignClass;
    returnSign->base.getAlgoName = GetSignAlgoName;
    returnSign->base.init = SignInit;
    returnSign->base.update = SignUpdate;
    returnSign->base.sign = SignDoFinal;
    returnSign->base.setSignSpecInt = SetSignSpecInt;
    returnSign->base.getSignSpecInt = GetSignSpecInt;
    returnSign->base.getSignSpecString = GetSignSpecString;
    returnSign->spiObj = spiObj;

    *returnObj = (HcfSign *)returnSign;
    LOGD("HcfSignCreate end");
    return HCF_SUCCESS;
}

HcfResult HcfVerifyCreate(const char *algoName, HcfVerify **returnObj)
{
    LOGD("HcfVerifyCreate start");
    if ((!IsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN)) || (returnObj == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    HcfSignatureParams params = {0};
    if (ParseAndSetParameter(algoName, &params, ParseSignatureParams) != HCF_SUCCESS) {
        LOGE("Failed to parser parmas!");
        return HCF_INVALID_PARAMS;
    }

    HcfVerifySpiCreateFunc createSpiFunc = FindVerifyAbility(&params);
    if (createSpiFunc == NULL) {
        return HCF_NOT_SUPPORT;
    }

    HcfVerifyImpl *returnVerify = (HcfVerifyImpl *)HcfMalloc(sizeof(HcfVerifyImpl), 0);
    if (returnVerify == NULL) {
        LOGE("Failed to allocate returnVerify memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnVerify->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnVerify);
        return HCF_INVALID_PARAMS;
    }
    HcfVerifySpi *spiObj = NULL;
    HcfResult res = createSpiFunc(&params, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnVerify);
        return res;
    }
    returnVerify->base.base.destroy = DestroyVerify;
    returnVerify->base.base.getClass = GetVerifyClass;
    returnVerify->base.getAlgoName = GetVerifyAlgoName;
    returnVerify->base.init = VerifyInit;
    returnVerify->base.update = VerifyUpdate;
    returnVerify->base.verify = VerifyDoFinal;
    returnVerify->base.setVerifySpecInt = SetVerifySpecInt;
    returnVerify->base.getVerifySpecInt = GetVerifySpecInt;
    returnVerify->base.getVerifySpecString = GetVerifySpecString;
    returnVerify->spiObj = spiObj;
    *returnObj = (HcfVerify *)returnVerify;
    LOGD("HcfVerifyCreate end");
    return HCF_SUCCESS;
}
