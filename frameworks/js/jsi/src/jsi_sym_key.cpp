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

JSIValue CryptoFrameworkLiteModule::BuildSymKeyObject(HcfSymKey *keyObj)
{
    JSIValue serviceObj = JSI::CreateObject();
    JSIValue getEncodedFn = JSI::CreateFunction(GetSymKeyDataSync);
    JSIValue getKeySizeFn = JSI::CreateFunction(GetSymKeySize);
    JSIValue clearMemFn = JSI::CreateFunction(ClearSymKeyMem);
    JSI::SetNamedProperty(serviceObj, "getEncoded", getEncodedFn);
    JSI::SetNamedProperty(serviceObj, "getKeySize", getKeySizeFn);
    JSI::SetNamedProperty(serviceObj, "clearMem", clearMemFn);
    const char *algo = keyObj->key.getAlgorithm((HcfKey *)keyObj);
    if (algo != nullptr) {
        JSI::SetStringProperty(serviceObj, "algName", algo);
    }
    const char *format = keyObj->key.getFormat((HcfKey *)keyObj);
    if (format != nullptr) {
        JSI::SetStringProperty(serviceObj, "format", format);
    }
    JSI::SetNumberProperty(serviceObj, "keyObj", (double)(uint32_t)(uintptr_t)keyObj);
    JSI::ReleaseValueList(getEncodedFn, getKeySizeFn, clearMemFn, ARGS_END);
    return serviceObj;
}

JSIValue CryptoFrameworkLiteModule::GetSymKeyDataSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::GetSymKeySize(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::ClearSymKeyMem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)args;
    (void)argsNum;
    HcfSymKey *key = reinterpret_cast<HcfSymKey *>((uint32_t)JSI::GetNumberProperty(thisVal, "keyObj"));
    if (key == nullptr) {
        LOGE("ClearSymKeyMem key is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "ClearSymKeyMem key is null!");
    }
    key->clearMem(key);
    return ThrowErrorCodeResult(HCF_SUCCESS);
}

void CryptoFrameworkLiteModule::SymKeyDestroy(void)
{
    ListDestroy(JSI_ALG_SYM_KEY);
}

} // namespace ACELite
} // namespace OHOS
