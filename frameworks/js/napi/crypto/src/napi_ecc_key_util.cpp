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

#include "napi_ecc_key_util.h"
#include "securec.h"
#include "detailed_ecc_key_params.h"
#include "log.h"

#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "napi_key_pair.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"

namespace OHOS {
namespace CryptoFramework {
NapiECCKeyUtil::NapiECCKeyUtil() {}

NapiECCKeyUtil::~NapiECCKeyUtil() {}

napi_value NapiECCKeyUtil::JsGenECCCommonParamsSpec(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != expectedArgc) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        LOGE("The input args num is invalid.");
        return nullptr;
    }

    std::string algName;
    if (!GetStringFromJSParams(env, argv[0], algName)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get algoName."));
        LOGE("failed to get algoName.");
        return NapiGetNull(env);
    }

    HcfEccCommParamsSpec *eccCommParamsSpec = nullptr;
    if (HcfEccKeyUtilCreate(algName.c_str(), &eccCommParamsSpec) != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "create c generator fail."));
        LOGE("create c generator fail.");
        return NapiGetNull(env);
    }
    napi_value instance = ConvertEccCommParamsSpecToNapiValue(env, eccCommParamsSpec);
    FreeEccCommParamsSpec(eccCommParamsSpec);
    return instance;
}

napi_value NapiECCKeyUtil::ECCKeyUtilConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiECCKeyUtil::GenECCCommonParamSpec(napi_env env)
{
    napi_value cons = nullptr;
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_STATIC_FUNCTION("genECCCommonParamsSpec", NapiECCKeyUtil::JsGenECCCommonParamsSpec),
    };
    NAPI_CALL(env, napi_define_class(env, "ECCKeyUtil", NAPI_AUTO_LENGTH, NapiECCKeyUtil::ECCKeyUtilConstructor,
        nullptr, sizeof(clzDes) / sizeof(clzDes[0]), clzDes, &cons));
    return cons;
}

void NapiECCKeyUtil::DefineNapiECCKeyUtilJSClass(napi_env env, napi_value exports)
{
    napi_set_named_property(env, exports, "ECCKeyUtil", NapiECCKeyUtil::GenECCCommonParamSpec(env));
}
} // CryptoFramework
} // OHOS
