/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "jsi_api.h"
#include "jsi_api_common.h"
#include "jsi_api_errcode.h"
#include "jsi_utils.h"
#include "jsi_list.h"
#include <cstring>
#include "securec.h"
#include "log.h"
#include "memory.h"

#include "detailed_iv_params.h"
#include "detailed_aead_params.h"

namespace OHOS {
namespace ACELite {

static const char *GetIvParamsSpecType(void)
{
    return "IvParamsSpec";
}

static const char *GetAeadParamsSpecType(void)
{
    return "AeadParamsSpec";
}

static HcfResult ParseNamedPropertyToBlob(JSIValue obj, const char *name, HcfBlob *blob, bool optional)
{
    blob->data = nullptr;
    blob->len = 0;
    JSIValue value = JSI::GetNamedProperty(obj, name);
    JSIValue dataValue = value;
    bool isWrapped = JSI::ValueIsObject(value);
    if (isWrapped) {
        dataValue = JSI::GetNamedProperty(value, "data");
    }
    bool isTypedArr = JSI::ValueIsTypedArray(dataValue);
    if (optional && !isTypedArr) {
        JSI::ReleaseValue(dataValue);
        if (isWrapped) {
            JSI::ReleaseValue(value);
        }
        return HCF_SUCCESS;
    }
    if (!isTypedArr) {
        LOGE("named property %{public}s is not a typed array!", name);
        JSI::ReleaseValue(dataValue);
        if (isWrapped) {
            JSI::ReleaseValue(value);
        }
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = ParseUint8ArrayToBlob(dataValue, blob);
    JSI::ReleaseValue(dataValue);
    if (isWrapped) {
        JSI::ReleaseValue(value);
    }
    return ret;
}

static HcfResult BuildIvParamsSpec(JSIValue paramsObj, HcfParamsSpec **paramsSpec)
{
    HcfIvParamsSpec *ivSpec = (HcfIvParamsSpec *)HcfMalloc(sizeof(HcfIvParamsSpec), 0);
    if (ivSpec == nullptr) {
        LOGE("malloc ivSpec failed!");
        return HCF_ERR_MALLOC;
    }
    HcfResult ret = ParseNamedPropertyToBlob(paramsObj, "iv", &ivSpec->iv, false);
    if (ret != HCF_SUCCESS) {
        LOGE("parse iv failed!");
        HcfFree(ivSpec);
        return ret;
    }
    ivSpec->base.getType = GetIvParamsSpecType;
    *paramsSpec = (HcfParamsSpec *)ivSpec;
    return HCF_SUCCESS;
}

static HcfResult BuildAeadParamsSpec(JSIValue paramsObj, HcfParamsSpec **paramsSpec)
{
    HcfAeadParamsSpec *aeadSpec = (HcfAeadParamsSpec *)HcfMalloc(sizeof(HcfAeadParamsSpec), 0);
    if (aeadSpec == nullptr) {
        LOGE("malloc aeadSpec failed!");
        return HCF_ERR_MALLOC;
    }
    HcfResult ret = ParseNamedPropertyToBlob(paramsObj, "nonce", &aeadSpec->nonce, false);
    if (ret != HCF_SUCCESS) {
        LOGE("parse aead nonce failed!");
        HcfFree(aeadSpec);
        return ret;
    }
    ret = ParseNamedPropertyToBlob(paramsObj, "aad", &aeadSpec->aad, true);
    if (ret != HCF_SUCCESS) {
        LOGE("parse aead aad failed!");
        HcfBlobDataFree(&aeadSpec->nonce);
        HcfFree(aeadSpec);
        return ret;
    }
    JSIValue tagLenVal = JSI::GetNamedProperty(paramsObj, "tagLen");
    if (JSI::ValueIsNumber(tagLenVal)) {
        aeadSpec->tagLen = static_cast<int32_t>(JSI::ValueToNumber(tagLenVal));
    } else {
        aeadSpec->tagLen = 0;
    }
    JSI::ReleaseValue(tagLenVal);
    aeadSpec->base.getType = GetAeadParamsSpecType;
    *paramsSpec = (HcfParamsSpec *)aeadSpec;
    return HCF_SUCCESS;
}

static void FreeParamsSpec(HcfParamsSpec *paramsSpec)
{
    if (paramsSpec == nullptr) {
        return;
    }
    const char *typeName = (paramsSpec->getType == nullptr) ? nullptr : paramsSpec->getType();
    if ((typeName != nullptr) && (strcmp(typeName, "AeadParamsSpec") == 0)) {
        HcfAeadParamsSpec *aead = (HcfAeadParamsSpec *)paramsSpec;
        HcfBlobDataFree(&aead->nonce);
        HcfBlobDataFree(&aead->aad);
    } else if ((typeName != nullptr) && (strcmp(typeName, "IvParamsSpec") == 0)) {
        HcfIvParamsSpec *iv = (HcfIvParamsSpec *)paramsSpec;
        HcfBlobDataFree(&iv->iv);
    }
    HcfFree(paramsSpec);
}

static bool CheckCipherArgs(const JSIValue *args, uint8_t argsNum, char **transformation, JSIValue *errResult)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("CreateCipher args is err!");
        *errResult = JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "CreateCipher args is err!");
        return false;
    }
    *transformation = JSI::ValueToString(args[0]);
    if (*transformation == nullptr) {
        LOGE("CreateCipher transformation is null!");
        *errResult = JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS),
            "CreateCipher transformation is null!");
        return false;
    }
    return true;
}

JSIValue CryptoFrameworkLiteModule::CreateCipher(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    char *transformation = nullptr;
    JSIValue errResult;
    if (!CheckCipherArgs(args, argsNum, &transformation, &errResult)) {
        return errResult;
    }
    HcfCipher *cipher = nullptr;
    HcfResult res = HcfCipherCreate(transformation, &cipher);
    if (res != HCF_SUCCESS) {
        LOGE("CreateCipher HcfCipherCreate err res %d!", res);
        JSI::ReleaseString(transformation);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res), "CreateCipher HcfCipherCreate err!");
    }
    res = ListAddObjNode(JSI_ALG_CIPHER, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cipher)));
    if (res != HCF_SUCCESS) {
        LOGE("cipher add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(cipher));
        JSI::ReleaseString(transformation);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res), "cipher add node err!");
    }
    int32_t isGcm = (strstr(transformation, "GCM") != nullptr) ? 1 : 0;
    JSI::ReleaseString(transformation);
    JSIValue serviceObj = JSI::CreateObject();
    JSIValue initFn = JSI::CreateFunction(CipherInit);
    JSIValue initSyncFn = JSI::CreateFunction(CipherInitSync);
    JSIValue updateFn = JSI::CreateFunction(CipherUpdate);
    JSIValue doFinalFn = JSI::CreateFunction(CipherDoFinal);
    JSIValue updateSync = JSI::CreateFunction(CipherUpdateSync);
    JSIValue doFinalSync = JSI::CreateFunction(CipherDoFinalSync);
    JSI::SetNamedProperty(serviceObj, "init", initFn);
    JSI::SetNamedProperty(serviceObj, "initSync", initSyncFn);
    JSI::SetNamedProperty(serviceObj, "update", updateFn);
    JSI::SetNamedProperty(serviceObj, "doFinal", doFinalFn);
    JSI::SetNamedProperty(serviceObj, "updateSync", updateSync);
    JSI::SetNamedProperty(serviceObj, "doFinalSync", doFinalSync);
    const char *algo = cipher->getAlgorithm(cipher);
    if (algo != nullptr) {
        JSI::SetStringProperty(serviceObj, "algName", algo);
    }
    JSI::SetNumberProperty(serviceObj, "cipherObj",
        static_cast<double>(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cipher))));
    JSI::SetNumberProperty(serviceObj, "isGcm", static_cast<double>(isGcm));
    JSI::ReleaseValueList(initFn, initSyncFn, updateFn, doFinalFn, updateSync, doFinalSync, ARGS_END);
    return serviceObj;
}

static HcfSymKey *ExtractCipherKey(JSIValue keyArg)
{
    if (!JSI::ValueIsObject(keyArg)) {
        return nullptr;
    }
    return reinterpret_cast<HcfSymKey *>((uint32_t)JSI::GetNumberProperty(keyArg, "keyObj"));
}

static HcfResult BuildCipherParamsSpec(JSIValue paramsVal, bool isGcm, HcfParamsSpec **paramsSpec)
{
    if (!JSI::ValueIsObject(paramsVal)) {
        return HCF_SUCCESS;
    }
    if (isGcm) {
        return BuildAeadParamsSpec(paramsVal, paramsSpec);
    }
    return BuildIvParamsSpec(paramsVal, paramsSpec);
}

JSIValue CryptoFrameworkLiteModule::CipherInit(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_FOUR)) {
        LOGE("CipherInit args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "CipherInit args is err!");
    }
    if (args[ARRAY_INDEX_THREE] == nullptr) {
        LOGE("CipherInit promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "CipherInit promise is not supported.");
    }
    HcfCipher *cipher =
        reinterpret_cast<HcfCipher *>((uint32_t)JSI::GetNumberProperty(thisVal, "cipherObj"));
    if (cipher == nullptr) {
        LOGE("CipherInit cipher is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_THREE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    int32_t opMode = static_cast<int32_t>(JSI::ValueToNumber(args[ARRAY_INDEX_ZERO]));
    HcfSymKey *key = ExtractCipherKey(args[ARRAY_INDEX_ONE]);
    if (key == nullptr) {
        LOGE("CipherInit key is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_THREE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    HcfParamsSpec *paramsSpec = nullptr;
    bool isGcm = (JSI::GetNumberProperty(thisVal, "isGcm") != 0);
    HcfResult ret = BuildCipherParamsSpec(args[ARRAY_INDEX_TWO], isGcm, &paramsSpec);
    if (ret != HCF_SUCCESS) {
        LOGE("CipherInit build params failed %d!", ret);
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_THREE], ret, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    ret = cipher->init(cipher, static_cast<enum HcfCryptoMode>(opMode), (HcfKey *)key, paramsSpec);
    FreeParamsSpec(paramsSpec);
    if (ret != HCF_SUCCESS) {
        LOGE("CipherInit cipher init err %d!", ret);
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_THREE], ret, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_THREE], HCF_SUCCESS, JSI::CreateNull());
    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::CipherInitSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_THREE)) {
        LOGE("CipherInitSync args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "CipherInitSync args is err!");
    }
    HcfCipher *cipher =
        reinterpret_cast<HcfCipher *>((uint32_t)JSI::GetNumberProperty(thisVal, "cipherObj"));
    if (cipher == nullptr) {
        LOGE("CipherInitSync cipher is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "CipherInitSync cipher is null!");
    }
    int32_t opMode = static_cast<int32_t>(JSI::ValueToNumber(args[ARRAY_INDEX_ZERO]));
    HcfSymKey *key = ExtractCipherKey(args[ARRAY_INDEX_ONE]);
    if (key == nullptr) {
        LOGE("CipherInitSync key is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "CipherInitSync key is null!");
    }
    HcfParamsSpec *paramsSpec = nullptr;
    bool isGcm = (JSI::GetNumberProperty(thisVal, "isGcm") != 0);
    HcfResult ret = BuildCipherParamsSpec(args[ARRAY_INDEX_TWO], isGcm, &paramsSpec);
    if (ret != HCF_SUCCESS) {
        LOGE("CipherInitSync build params failed %d!", ret);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(ret), "CipherInitSync build params failed!");
    }
    ret = cipher->init(cipher, static_cast<enum HcfCryptoMode>(opMode), (HcfKey *)key, paramsSpec);
    FreeParamsSpec(paramsSpec);
    if (ret != HCF_SUCCESS) {
        LOGE("CipherInitSync cipher init err %d!", ret);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(ret), "CipherInitSync cipher init err!");
    }
    return ThrowErrorCodeResult(HCF_SUCCESS);
}

JSIValue CryptoFrameworkLiteModule::CipherUpdate(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_TWO)) {
        LOGE("CipherUpdate args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "CipherUpdate args is err!");
    }
    if (args[ARRAY_INDEX_ONE] == nullptr) {
        LOGE("CipherUpdate promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "CipherUpdate promise is not supported.");
    }
    HcfCipher *cipher =
        reinterpret_cast<HcfCipher *>((uint32_t)JSI::GetNumberProperty(thisVal, "cipherObj"));
    if (cipher == nullptr) {
        LOGE("CipherUpdate cipher is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inValue, &inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("CipherUpdate inBlob is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    errCode = cipher->update(cipher, &inBlob, &outBlob);
    HcfBlobDataClearAndFree(&inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("CipherUpdate update err %d!", errCode);
        HcfBlobDataClearAndFree(&outBlob);
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], errCode, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    JSIValue result = ConstructJSIReturnResult(&outBlob);
    HcfBlobDataClearAndFree(&outBlob);
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_SUCCESS, result);
    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::CipherUpdateSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("CipherUpdateSync args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "CipherUpdateSync args is err!");
    }
    HcfCipher *cipher =
        reinterpret_cast<HcfCipher *>((uint32_t)JSI::GetNumberProperty(thisVal, "cipherObj"));
    if (cipher == nullptr) {
        LOGE("CipherUpdateSync cipher is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS),
            "CipherUpdateSync cipher is null!");
    }
    JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inValue, &inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("CipherUpdateSync inBlob is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(errCode), "CipherUpdateSync inBlob is null!");
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    errCode = cipher->update(cipher, &inBlob, &outBlob);
    HcfBlobDataClearAndFree(&inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("CipherUpdateSync update err %d!", errCode);
        HcfBlobDataClearAndFree(&outBlob);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(errCode), "CipherUpdateSync update err!");
    }
    JSIValue result = ConstructJSIReturnResult(&outBlob);
    HcfBlobDataClearAndFree(&outBlob);
    return result;
}

JSIValue CryptoFrameworkLiteModule::CipherDoFinal(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_TWO)) {
        LOGE("CipherDoFinal args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "CipherDoFinal args is err!");
    }
    if (args[ARRAY_INDEX_ONE] == nullptr) {
        LOGE("CipherDoFinal promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "CipherDoFinal promise is not supported.");
    }
    HcfCipher *cipher =
        reinterpret_cast<HcfCipher *>((uint32_t)JSI::GetNumberProperty(thisVal, "cipherObj"));
    if (cipher == nullptr) {
        LOGE("CipherDoFinal cipher is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    if (JSI::ValueIsObject(args[ARRAY_INDEX_ZERO])) {
        JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
        if (JSI::ValueIsTypedArray(inValue)) {
            HcfResult errCode = ParseUint8ArrayToBlob(inValue, &inBlob);
            if (errCode != HCF_SUCCESS) {
                LOGE("CipherDoFinal inBlob parse failed!");
                JSI::ReleaseValue(inValue);
                CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], errCode, JSI::CreateNull());
                return JSI::CreateUndefined();
            }
        }
        JSI::ReleaseValue(inValue);
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult res = cipher->doFinal(cipher, &inBlob, &outBlob);
    HcfBlobDataClearAndFree(&inBlob);
    if (res != HCF_SUCCESS) {
        LOGE("CipherDoFinal doFinal err %d!", res);
        HcfBlobDataClearAndFree(&outBlob);
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], res, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    JSIValue result = ConstructJSIReturnResult(&outBlob);
    HcfBlobDataClearAndFree(&outBlob);
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_SUCCESS, result);
    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::CipherDoFinalSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    HcfCipher *cipher =
        reinterpret_cast<HcfCipher *>((uint32_t)JSI::GetNumberProperty(thisVal, "cipherObj"));
    if (cipher == nullptr) {
        LOGE("CipherDoFinalSync cipher is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS),
            "CipherDoFinalSync cipher is null!");
    }
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    if ((args != nullptr) && (argsNum >= ARGS_SIZE_ONE) && JSI::ValueIsObject(args[ARRAY_INDEX_ZERO])) {
        JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
        if (JSI::ValueIsTypedArray(inValue)) {
            HcfResult errCode = ParseUint8ArrayToBlob(inValue, &inBlob);
            if (errCode != HCF_SUCCESS) {
                LOGE("CipherDoFinalSync inBlob parse failed!");
                JSI::ReleaseValue(inValue);
                return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(errCode),
                    "CipherDoFinalSync inBlob parse failed!");
            }
        }
        JSI::ReleaseValue(inValue);
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult res = cipher->doFinal(cipher, &inBlob, &outBlob);
    HcfBlobDataClearAndFree(&inBlob);
    if (res != HCF_SUCCESS) {
        LOGE("CipherDoFinalSync doFinal err %d!", res);
        HcfBlobDataClearAndFree(&outBlob);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res), "CipherDoFinalSync doFinal err!");
    }
    JSIValue result = ConstructJSIReturnResult(&outBlob);
    HcfBlobDataClearAndFree(&outBlob);
    return result;
}

void CryptoFrameworkLiteModule::CipherDestroy(void)
{
    ListDestroy(JSI_ALG_CIPHER);
}

} // namespace ACELite
} // namespace OHOS
