/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef HCF_NAPI_HCF_KEY_H
#define HCF_NAPI_HCF_KEY_H

#include <stdint.h>
#include "log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "key.h"

namespace OHOS {
namespace CryptoFramework {
class NapiKey {
public:
    NapiKey(HcfKey *symKey);
    ~NapiKey();
    HcfKey *GetHcfKey();

    static void DefineHcfKeyJSClass(napi_env env);
    static napi_value CreateHcfKey(napi_env env);
    static napi_value KeyConstructor(napi_env env, napi_callback_info info);

    static napi_value JsGetAlgorithm(napi_env env, napi_callback_info info);
    static napi_value JsGetEncoded(napi_env env, napi_callback_info info);
    static napi_value JsGetFormat(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;
private:
    HcfKey *hcfKey_;
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
