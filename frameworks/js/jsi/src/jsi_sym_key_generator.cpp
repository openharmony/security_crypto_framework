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

namespace OHOS {
namespace ACELite {

static bool IsWearableSupportedAlgo(const char *alg)
{
    if (alg == nullptr) {
        return false;
    }
    if (strncmp(alg, "AES128", strlen("AES128")) == 0) {
        return true;
    }
    if (strncmp(alg, "HMAC", strlen("HMAC")) == 0) {
        return true;
    }
    return false;
}

static bool CheckSymKeyGeneratorArgs(const JSIValue *args, uint8_t argsNum, char **alg, JSIValue *errResult)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("CreateSymKeyGenerator args is err!");
        *errResult = JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS),
            "CreateSymKeyGenerator args is err!");
        return false;
    }
    *alg = JSI::ValueToString(args[0]);
    if (*alg == nullptr) {
        LOGE("CreateSymKeyGenerator alg is null!");
        *errResult = JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS),
            "CreateSymKeyGenerator alg is null!");
        return false;
    }
    if (!IsWearableSupportedAlgo(*alg)) {
        LOGE("CreateSymKeyGenerator algo not support! [Algo]: %{public}s", *alg);
        JSI::ReleaseString(*alg);
        *errResult = JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS),
            "CreateSymKeyGenerator algo not support!");
        return false;
    }
    return true;
}

JSIValue CryptoFrameworkLiteModule::CreateSymKeyGenerator(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    char *alg = nullptr;
    JSIValue errResult;
    if (!CheckSymKeyGeneratorArgs(args, argsNum, &alg, &errResult)) {
        return errResult;
    }
    HcfSymKeyGenerator *generator = nullptr;
    HcfResult res = HcfSymKeyGeneratorCreate(alg, &generator);
    if (res != HCF_SUCCESS) {
        LOGE("CreateSymKeyGenerator HcfSymKeyGeneratorCreate err res %d!", res);
        JSI::ReleaseString(alg);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res),
            "CreateSymKeyGenerator HcfSymKeyGeneratorCreate err!");
    }
    res = ListAddObjNode(JSI_ALG_SYM_KEY, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(generator)));
    if (res != HCF_SUCCESS) {
        LOGE("sym key generator add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(generator));
        JSI::ReleaseString(alg);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res), "sym key generator add node err!");
    }
    JSI::ReleaseString(alg);
    JSIValue serviceObj = JSI::CreateObject();
    JSIValue generateSymKey = JSI::CreateFunction(GenerateSymKey);
    JSIValue generateSymKeySync = JSI::CreateFunction(GenerateSymKeySync);
    JSIValue convertKey = JSI::CreateFunction(ConvertSymKey);
    JSIValue convertKeySync = JSI::CreateFunction(ConvertSymKeySync);
    JSI::SetNamedProperty(serviceObj, "generateSymKey", generateSymKey);
    JSI::SetNamedProperty(serviceObj, "generateSymKeySync", generateSymKeySync);
    JSI::SetNamedProperty(serviceObj, "convertKey", convertKey);
    JSI::SetNamedProperty(serviceObj, "convertKeySync", convertKeySync);
    const char *algo = generator->getAlgoName(generator);
    if (algo != nullptr) {
        JSI::SetStringProperty(serviceObj, "algName", algo);
    }
    JSI::SetNumberProperty(serviceObj, "genObj",
        static_cast<double>(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(generator))));
    JSI::ReleaseValueList(generateSymKey, generateSymKeySync, convertKey, convertKeySync, ARGS_END);
    return serviceObj;
}

JSIValue CryptoFrameworkLiteModule::GenerateSymKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    LOGE("GenerateSymKey is not supported on mini device.");
    return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
        "GenerateSymKey is not supported on mini device.");
}

JSIValue CryptoFrameworkLiteModule::GenerateSymKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    LOGE("GenerateSymKeySync is not supported on mini device.");
    return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
        "GenerateSymKeySync is not supported on mini device.");
}

JSIValue CryptoFrameworkLiteModule::ConvertSymKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_TWO)) {
        LOGE("ConvertSymKey args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "ConvertSymKey args is err!");
    }
    if (args[ARRAY_INDEX_ONE] == nullptr) {
        LOGE("ConvertSymKey promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "ConvertSymKey promise is not supported.");
    }
    HcfSymKeyGenerator *generator =
        reinterpret_cast<HcfSymKeyGenerator *>((uint32_t)JSI::GetNumberProperty(thisVal, "genObj"));
    if (generator == nullptr) {
        LOGE("ConvertSymKey generator is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob keyBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inValue, &keyBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("ConvertSymKey keyBlob is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    HcfSymKey *key = nullptr;
    HcfResult res = generator->convertSymKey(generator, &keyBlob, &key);
    HcfBlobDataClearAndFree(&keyBlob);
    if (res != HCF_SUCCESS) {
        LOGE("ConvertSymKey convertSymKey err %d!", res);
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], res, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    res = ListAddObjNode(JSI_ALG_SYM_KEY, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(key)));
    if (res != HCF_SUCCESS) {
        LOGE("sym key add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(key));
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], res, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    JSIValue keyObj = BuildSymKeyObject(key);
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_SUCCESS, keyObj);
    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::ConvertSymKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("ConvertSymKeySync args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "ConvertSymKeySync args is err!");
    }
    HcfSymKeyGenerator *generator =
        reinterpret_cast<HcfSymKeyGenerator *>((uint32_t)JSI::GetNumberProperty(thisVal, "genObj"));
    if (generator == nullptr) {
        LOGE("ConvertSymKeySync generator is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS),
            "ConvertSymKeySync generator is null!");
    }
    JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob keyBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inValue, &keyBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("ConvertSymKeySync keyBlob is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(errCode), "ConvertSymKeySync keyBlob is null!");
    }
    HcfSymKey *key = nullptr;
    HcfResult res = generator->convertSymKey(generator, &keyBlob, &key);
    HcfBlobDataClearAndFree(&keyBlob);
    if (res != HCF_SUCCESS) {
        LOGE("ConvertSymKeySync convertSymKey err %d!", res);
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res), "ConvertSymKeySync convertSymKey err!");
    }
    res = ListAddObjNode(JSI_ALG_SYM_KEY, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(key)));
    if (res != HCF_SUCCESS) {
        LOGE("sym key add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(key));
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(res), "sym key add node err!");
    }
    return BuildSymKeyObject(key);
}

} // namespace ACELite
} // namespace OHOS
