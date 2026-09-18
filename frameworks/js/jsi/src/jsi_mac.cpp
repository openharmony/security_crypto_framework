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
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "mac.h"
#include "detailed_hmac_params.h"

namespace OHOS {
namespace ACELite {

static HcfResult BuildHmacParamsSpecFromObject(JSIValue specObj, HcfMacParamsSpec **paramsSpec)
{
    char *algName = JSI::ValueToString(JSI::GetNamedProperty(specObj, "algName"));
    if (algName == nullptr) {
        LOGE("get algName from spec failed!");
        return HCF_INVALID_PARAMS;
    }
    char *mdName = JSI::ValueToString(JSI::GetNamedProperty(specObj, "mdName"));
    if (mdName == nullptr) {
        LOGE("get mdName from spec failed!");
        JSI::ReleaseString(algName);
        return HCF_INVALID_PARAMS;
    }
    size_t mdLen = strlen(mdName);
    HcfHmacParamsSpec *tmp = (HcfHmacParamsSpec *)HcfMalloc(sizeof(HcfHmacParamsSpec), 0);
    if (tmp == nullptr) {
        LOGE("malloc hmac spec failed!");
        JSI::ReleaseString(algName);
        JSI::ReleaseString(mdName);
        return HCF_ERR_MALLOC;
    }
    char *mdNameCopy = static_cast<char *>(HcfMalloc(mdLen + 1, 0));
    if (mdNameCopy == nullptr) {
        LOGE("malloc mdName failed!");
        HcfFree(tmp);
        JSI::ReleaseString(algName);
        JSI::ReleaseString(mdName);
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(mdNameCopy, mdLen + 1, mdName, mdLen + 1) != EOK) {
        LOGE("copy mdName failed!");
        HcfFree(mdNameCopy);
        HcfFree(tmp);
        JSI::ReleaseString(algName);
        JSI::ReleaseString(mdName);
        return HCF_ERR_MALLOC;
    }
    tmp->base.algName = "HMAC";
    tmp->mdName = mdNameCopy;
    *paramsSpec = (HcfMacParamsSpec *)tmp;
    JSI::ReleaseString(algName);
    JSI::ReleaseString(mdName);
    return HCF_SUCCESS;
}

static void FreeMacParams(HcfMacParamsSpec *paramsSpec)
{
    if (paramsSpec == nullptr) {
        return;
    }
    HcfHmacParamsSpec *hmac = (HcfHmacParamsSpec *)paramsSpec;
    if (hmac->mdName != nullptr) {
        HcfFree(const_cast<void *>(static_cast<const void *>(hmac->mdName)));
        hmac->mdName = nullptr;
    }
    HcfFree(paramsSpec);
}

static bool CheckMacArgs(const JSIValue *args, uint8_t argsNum, JSIValue *errResult)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("CreateMac args is err!");
        *errResult = JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "CreateMac args is err!");
        return false;
    }
    if (!JSI::ValueIsObject(args[0])) {
        LOGE("CreateMac arg is not HmacSpec object!");
        *errResult = JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS),
            "CreateMac arg is not HmacSpec object!");
        return false;
    }
    return true;
}

JSIValue CryptoFrameworkLiteModule::CreateMac(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    JSIValue errResult;
    if (!CheckMacArgs(args, argsNum, &errResult)) {
        return errResult;
    }
    HcfMacParamsSpec *paramsSpec = nullptr;
    HcfResult res = BuildHmacParamsSpecFromObject(args[0], &paramsSpec);
    if (res != HCF_SUCCESS) {
        LOGE("CreateMac build params spec failed %d!", res);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res), "CreateMac build params spec failed!");
    }
    HcfMac *macObj = nullptr;
    res = HcfMacCreate(paramsSpec, &macObj);
    FreeMacParams(paramsSpec);
    if (res != HCF_SUCCESS) {
        LOGE("CreateMac is macObj err res %d!", res);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res), "CreateMac is macObj err!");
    }
    res = ListAddObjNode(JSI_ALG_MAC, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(macObj)));
    if (res != HCF_SUCCESS) {
        LOGE("mac add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(macObj));
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res), "mac add node err!");
    }
    JSIValue serviceObj = JSI::CreateObject();
    JSIValue macInit = JSI::CreateFunction(MacInit);
    JSIValue macInitSync = JSI::CreateFunction(MacInitSync);
    JSIValue macUpdate = JSI::CreateFunction(MacUpdate);
    JSIValue macUpdateSync = JSI::CreateFunction(MacUpdateSync);
    JSIValue macDoFinal = JSI::CreateFunction(MacDoFinal);
    JSIValue macDoFinalSync = JSI::CreateFunction(MacDoFinalSync);
    JSIValue getMacLength = JSI::CreateFunction(GetMacLength);
    JSI::SetNamedProperty(serviceObj, "init", macInit);
    JSI::SetNamedProperty(serviceObj, "initSync", macInitSync);
    JSI::SetNamedProperty(serviceObj, "update", macUpdate);
    JSI::SetNamedProperty(serviceObj, "updateSync", macUpdateSync);
    JSI::SetNamedProperty(serviceObj, "doFinal", macDoFinal);
    JSI::SetNamedProperty(serviceObj, "doFinalSync", macDoFinalSync);
    JSI::SetNamedProperty(serviceObj, "getMacLength", getMacLength);
    const char *algo = macObj->getAlgoName(macObj);
    if (algo != nullptr) {
        JSI::SetStringProperty(serviceObj, "algName", algo);
    }
    JSI::SetNumberProperty(serviceObj, "macObj",
        static_cast<double>(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(macObj))));
    JSI::ReleaseValueList(macInit, macInitSync, macUpdate, macUpdateSync, macDoFinal, macDoFinalSync,
        getMacLength, ARGS_END);
    return serviceObj;
}

JSIValue CryptoFrameworkLiteModule::MacInit(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_TWO)) {
        LOGE("MacInit args is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "MacInit args is null!");
    }
    if (args[ARRAY_INDEX_ONE] == nullptr) {
        LOGE("MacInit promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT), "MacInit promise is not supported.");
    }
    HcfMac *macObj = reinterpret_cast<HcfMac *>((uint32_t)JSI::GetNumberProperty(thisVal, "macObj"));
    if (macObj == nullptr) {
        LOGE("MacInit macObj is null!!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }

    HcfSymKey *symKey = nullptr;
    if (JSI::ValueIsObject(args[ARRAY_INDEX_ZERO])) {
        symKey = reinterpret_cast<HcfSymKey *>(
            (uint32_t)JSI::GetNumberProperty(args[ARRAY_INDEX_ZERO], "keyObj"));
    }
    if (symKey == nullptr) {
        LOGE("MacInit symKey is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }

    HcfResult errCode = macObj->init(macObj, symKey);
    if (errCode != HCF_SUCCESS) {
        LOGE("MacInit errCode not is success!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], errCode, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_SUCCESS, JSI::CreateNull());

    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::MacInitSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("MacInitSync args is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "MacInitSync args is null!");
    }
    HcfMac *macObj = reinterpret_cast<HcfMac *>((uint32_t)JSI::GetNumberProperty(thisVal, "macObj"));
    if (macObj == nullptr) {
        LOGE("MacInitSync macObj is null!!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "MacInitSync macObj is null!");
    }

    HcfSymKey *symKey = nullptr;
    if (JSI::ValueIsObject(args[ARRAY_INDEX_ZERO])) {
        symKey = reinterpret_cast<HcfSymKey *>(
            (uint32_t)JSI::GetNumberProperty(args[ARRAY_INDEX_ZERO], "keyObj"));
    }
    if (symKey == nullptr) {
        LOGE("MacInitSync symKey is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "MacInitSync symKey is null!");
    }

    HcfResult errCode = macObj->init(macObj, symKey);
    if (errCode != HCF_SUCCESS) {
        LOGE("MacInitSync init ret is error!");
    }

    return ThrowErrorCodeResult(errCode);
}

JSIValue CryptoFrameworkLiteModule::MacUpdate(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_TWO)) {
        LOGE("MacUpdate args is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "MacUpdate args is null!");
    }
    if (args[ARRAY_INDEX_ONE] == nullptr) {
        LOGE("MacUpdate promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "MacUpdate promise is not supported.");
    }
    HcfMac *macObj = reinterpret_cast<HcfMac *>((uint32_t)JSI::GetNumberProperty(thisVal, "macObj"));
    if (macObj == nullptr) {
        LOGE("MacUpdate macObj is null!!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }

    JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inValue, &inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("MacUpdate inBlob is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }

    errCode = macObj->update(macObj, &inBlob);
    HcfBlobDataClearAndFree(&inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("MacUpdate errCode not is success!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], errCode, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_SUCCESS, JSI::CreateNull());

    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::MacUpdateSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("MacUpdateSync args is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "MacUpdateSync args is null!");
    }
    HcfMac *macObj = reinterpret_cast<HcfMac *>((uint32_t)JSI::GetNumberProperty(thisVal, "macObj"));
    if (macObj == nullptr) {
        LOGE("MacUpdateSync macObj is null!!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "MacUpdateSync macObj is null!");
    }
    JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob inBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inValue, &inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("MacUpdateSync inBlob is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(errCode), "MacUpdateSync inBlob is null!");
    }

    errCode = macObj->update(macObj, &inBlob);
    HcfBlobDataClearAndFree(&inBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("MacUpdateSync update ret is error!");
    }

    return ThrowErrorCodeResult(errCode);
}

JSIValue CryptoFrameworkLiteModule::MacDoFinal(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("MacDoFinal args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "MacDoFinal args is err!");
    }
    if (args[ARRAY_INDEX_ZERO] == nullptr) {
        LOGE("MacDoFinal promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "MacDoFinal promise is not supported.");
    }
    HcfMac *macObj = reinterpret_cast<HcfMac *>((uint32_t)JSI::GetNumberProperty(thisVal, "macObj"));
    if (macObj == nullptr) {
        LOGE("MacDoFinal macObj is null!!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ZERO], HCF_INVALID_PARAMS, JSI::CreateUndefined());
        return JSI::CreateUndefined();
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = macObj->doFinal(macObj, &outBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("MacDoFinal errCode not is success!");
        HcfBlobDataClearAndFree(&outBlob);
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ZERO], errCode, JSI::CreateUndefined());
        return JSI::CreateUndefined();
    }
    JSIValue outValue = ConstructJSIReturnResult(&outBlob);
    CallbackErrorCodeOrDataResult(thisVal, args[0], errCode, outValue);
    HcfBlobDataClearAndFree(&outBlob);

    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::MacDoFinalSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)args;
    (void)argsNum;
    HcfMac *macObj = reinterpret_cast<HcfMac *>((uint32_t)JSI::GetNumberProperty(thisVal, "macObj"));
    if (macObj == nullptr) {
        LOGE("MacDoFinalSync macObj is null!!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "MacDoFinalSync macObj is null!");
    }

    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = macObj->doFinal(macObj, &outBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("MacDoFinalSync errCode not is success!");
        HcfBlobDataClearAndFree(&outBlob);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(errCode), "MacDoFinalSync errCode not is success!");
    }

    JSIValue macSyncData = ConstructJSIReturnResult(&outBlob);
    HcfBlobDataClearAndFree(&outBlob);

    return macSyncData;
}

JSIValue CryptoFrameworkLiteModule::GetMacLength(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    LOGE("GetMacLength is not supported.");
    return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT), "GetMacLength is not supported.");
}

void CryptoFrameworkLiteModule::MacDestroy(void)
{
    ListDestroy(JSI_ALG_MAC);
}

} // namespace ACELite
} // namespace OHOS
