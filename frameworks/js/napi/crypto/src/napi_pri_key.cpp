/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "napi_pri_key.h"

#include "log.h"
#include "memory.h"
#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "napi_pub_key.h"
#include "securec.h"
#include "key.h"

namespace OHOS {
namespace CryptoFramework {
thread_local napi_ref NapiPriKey::classRef_ = nullptr;

NapiPriKey::NapiPriKey(HcfPriKey *priKey) : NapiKey(reinterpret_cast<HcfKey *>(priKey)) {}

NapiPriKey::~NapiPriKey() {}

HcfPriKey *NapiPriKey::GetPriKey()
{
    return reinterpret_cast<HcfPriKey *>(NapiKey::GetHcfKey());
}

napi_value NapiPriKey::PriKeyConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

struct PriKeyCtx {
    napi_env env = nullptr;
    napi_ref priKeyRef = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    HcfPriKey *priKey = nullptr;
    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfPubKey *returnPubKey = nullptr;
};

static void FreePriKeyCtx(napi_env env, PriKeyCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }
    if (ctx->priKeyRef != nullptr) {
        napi_delete_reference(env, ctx->priKeyRef);
        ctx->priKeyRef = nullptr;
    }
    HcfFree(ctx);
}

static void FreeEncodeParamsSpec(HcfParamsSpec *paramsSpec)
{
    if (paramsSpec == nullptr) {
        return;
    }
    HcfKeyEncodingParamsSpec *spec = reinterpret_cast<HcfKeyEncodingParamsSpec *>(paramsSpec);
    if (spec->password != nullptr) {
        size_t pwdLen = strlen(spec->password);
        (void)memset_s((void*)spec->password, pwdLen, 0, pwdLen);
        HcfFree(static_cast<void *>(spec->password));
        spec->password = nullptr;
    }
    if (spec->cipher != nullptr) {
        HcfFree(static_cast<void *>(spec->cipher));
        spec->cipher = nullptr;
    }
    HcfFree(paramsSpec);
    paramsSpec = nullptr;
}

napi_value NapiPriKey::ConvertToJsPriKey(napi_env env)
{
    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    const char *algName = this->GetPriKey()->base.getAlgorithm(&(this->GetPriKey()->base));
    const char *format = this->GetPriKey()->base.getFormat(&(this->GetPriKey()->base));

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName, NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    napi_value napiFormat = nullptr;
    napi_create_string_utf8(env, format, NAPI_AUTO_LENGTH, &napiFormat);
    napi_set_named_property(env, instance, CRYPTO_TAG_FORMAT.c_str(), napiFormat);
    return instance;
}

napi_value NapiPriKey::JsGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiPriKey *napiPriKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPriKey obj!"));
        LOGE("failed to unwrap napiPriKey obj!");
        return nullptr;
    }

    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get priKey obj!"));
        LOGE("failed to get priKey obj!");
        return nullptr;
    }

    HcfBlob returnBlob;
    HcfResult res = priKey->base.getEncoded(&priKey->base, &returnBlob);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "c getEncoded fail."));
        LOGD("[error] c getEncoded fail.");
        return nullptr;
    }

    napi_value instance = ConvertBlobToNapiValue(env, &returnBlob);
    if (instance == nullptr) {
        HcfBlobDataFree(&returnBlob);
        napi_throw(env, GenerateBusinessError(env, res, "covert blob to napi value failed."));
        LOGE("covert blob to napi value failed.");
        return nullptr;
    }
    HcfBlobDataClearAndFree(&returnBlob);
    return instance;
}

static bool ValidateAndGetParams(napi_env env, napi_callback_info info, std::string &format,
    HcfParamsSpec **paramsSpec, NapiPriKey **napiPriKey)
{
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = expectedArgc;
    napi_value thisVar = nullptr;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != (expectedArgc - 1))) {
        LOGE("The input args num is invalid.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        return false;
    }

    if (!GetStringFromJSParams(env, argv[0], format)) {
        LOGE("failed to get formatStr.");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get formatStr."));
        return false;
    }

    if (argc == expectedArgc) {
        if (!GetEncodingParamsSpec(env, argv[1], paramsSpec)) {
            LOGE("get params failed!");
            napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "get napi paramsSpec failed!"));
            return false;
        }
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        LOGE("failed to unwrap napiPriKey obj!");
        FreeEncodeParamsSpec(*paramsSpec);
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPriKey obj!"));
        return false;
    }
    return true;
}

napi_value NapiPriKey::JsGetEncodedPem(napi_env env, napi_callback_info info)
{
    std::string format;
    HcfParamsSpec *paramsSpec = nullptr;
    NapiPriKey *napiPriKey = nullptr;
    if (!ValidateAndGetParams(env, info, format, &paramsSpec, &napiPriKey)) {
        return NapiGetNull(env);
    }

    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        FreeEncodeParamsSpec(paramsSpec);
        paramsSpec = nullptr;
        LOGE("failed to get priKey obj!");
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get priKey obj!"));
        return nullptr;
    }

    char *returnString = nullptr;
    HcfResult res = priKey->getEncodedPem(priKey, paramsSpec, format.c_str(), &returnString);
    if (res != HCF_SUCCESS) {
        FreeEncodeParamsSpec(paramsSpec);
        paramsSpec = nullptr;
        LOGE("getEncodedPem fail.");
        napi_throw(env, GenerateBusinessError(env, res, "getEncodedPem fail."));
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    returnString = nullptr;
    FreeEncodeParamsSpec(paramsSpec);
    paramsSpec = nullptr;
    return instance;
}

napi_value NapiPriKey::JsClearMem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiPriKey *napiPriKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPriKey obj!"));
        LOGE("failed to unwrap napiPriKey obj!");
        return nullptr;
    }

    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get priKey obj!"));
        LOGE("failed to get priKey obj!");
        return nullptr;
    }

    priKey->clearMem(priKey);
    return nullptr;
}

static napi_value GetAsyKeySpecBigInt(napi_env env, AsyKeySpecItem item, HcfPriKey *priKey)
{
    HcfBigInteger returnBigInteger = { 0 };
    HcfResult res = priKey->getAsyKeySpecBigInteger(priKey, item, &returnBigInteger);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getAsyKeySpecBigInteger failed."));
        LOGE("C getAsyKeySpecBigInteger failed.");
        return nullptr;
    }

    napi_value instance = ConvertBigIntToNapiValue(env, &returnBigInteger);
    (void)memset_s(returnBigInteger.data, returnBigInteger.len, 0, returnBigInteger.len);
    HcfFree(returnBigInteger.data);
    returnBigInteger.data = nullptr;
    if (instance == nullptr) {
        napi_throw(env, GenerateBusinessError(env, res, "covert bigInt to napi value failed."));
        LOGE("covert bigInt to napi value failed.");
        return nullptr;
    }
    return instance;
}

static napi_value GetAsyKeySpecNumber(napi_env env, AsyKeySpecItem item, HcfPriKey *priKey)
{
    int returnInt = 0;
    HcfResult res = priKey->getAsyKeySpecInt(priKey, item, &returnInt);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getAsyKeySpecInt failed."));
        LOGE("C getAsyKeySpecInt fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_int32(env, returnInt, &instance);
    return instance;
}

static napi_value GetAsyKeySpecString(napi_env env, AsyKeySpecItem item, HcfPriKey *priKey)
{
    char *returnString = nullptr;
    HcfResult res = priKey->getAsyKeySpecString(priKey, item, &returnString);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getAsyKeySpecString failed."));
        LOGE("c getAsyKeySpecString fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    returnString = nullptr;
    return instance;
}

napi_value NapiPriKey::JsGetAsyKeySpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiPriKey *napiPriKey = nullptr;
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "JsGetAsyKeySpec fail, wrong argument num."));
        LOGE("wrong argument num. require 1 arguments. [Argc]: %{public}zu!", argc);
        return nullptr;
    }

    AsyKeySpecItem item;
    if (napi_get_value_uint32(env, argv[0], reinterpret_cast<uint32_t *>(&item)) != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "JsGetAsyKeySpec failed!"));
        LOGE("JsGetAsyKeySpec failed!");
        return nullptr;
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiPriKey obj!"));
        LOGE("failed to unwrap napiPriKey obj!");
        return nullptr;
    }
    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get priKey obj!"));
        LOGE("failed to get priKey obj!");
        return nullptr;
    }
    LOGD("prepare priKey ok.");

    int32_t type = GetAsyKeySpecType(item);
    if (type == SPEC_ITEM_TYPE_BIG_INT) {
        return GetAsyKeySpecBigInt(env, item, priKey);
    } else if (type == SPEC_ITEM_TYPE_NUM) {
        return GetAsyKeySpecNumber(env, item, priKey);
    } else if (type == SPEC_ITEM_TYPE_STR) {
        return GetAsyKeySpecString(env, item, priKey);
    } else {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "AsyKeySpecItem not support!"));
        return nullptr;
    }
}

napi_value NapiPriKey::JsGetEncodedDer(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiPriKey *napiPriKey = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != ARGS_SIZE_ONE) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "wrong argument num."));
        LOGE("wrong argument num. require 1 arguments. [Argc]: %{public}zu!", argc);
        return nullptr;
    }
    std::string format;
    if (!GetStringFromJSParams(env, argv[0], format)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get format."));
        LOGE("get format fail.");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap private key obj!"));
        LOGE("failed to unwrap private key obj!");
        return nullptr;
    }
    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get private key obj!"));
        LOGE("failed to get private key obj!");
        return nullptr;
    }
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult res = priKey->getEncodedDer(priKey, format.c_str(), &returnBlob);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "get private key encodedDer fail."));
        LOGE("get private key encodeDer fail.");
        return nullptr;
    }

    napi_value instance = ConvertBlobToNapiValue(env, &returnBlob);
    HcfBlobDataClearAndFree(&returnBlob);
    return instance;
}

static void ReturnPromiseResult(napi_env env, PriKeyCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static HcfResult BuildPriKeyJsGetPubKeyCtx(napi_env env, napi_callback_info info, PriKeyCtx *context)
{
    napi_value thisVar = nullptr;
    NapiPriKey *napiPriKey = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        LOGE("failed to unwrap napiPriKey obj!");
        return HCF_ERR_NAPI;
    }

    context->priKey = napiPriKey->GetPriKey();

    if (napi_create_reference(env, thisVar, 1, &context->priKeyRef) != napi_ok) {
        LOGE("create priKey ref failed when do getPubKey!");
        return HCF_ERR_NAPI;
    }

    if (napi_create_promise(env, &context->deferred, &context->promise) != napi_ok) {
        LOGE("create promise failed when do getPubKey!");
        return HCF_ERR_NAPI;
    }
    return HCF_SUCCESS;
}

static void PriKeyJsGetPubKeyAsyncWorkProcess(napi_env env, void *data)
{
    PriKeyCtx *ctx = static_cast<PriKeyCtx *>(data);
    ctx->errCode = ctx->priKey->getPubKey(ctx->priKey, &(ctx->returnPubKey));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("get PubKey fail.");
        ctx->errMsg = "get PubKey fail.";
    }
}

static void PriKeyJsGetPubKeyAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    PriKeyCtx *ctx = static_cast<PriKeyCtx *>(data);
    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiPubKey *napiPubKey = new (std::nothrow) NapiPubKey(ctx->returnPubKey);
        if (napiPubKey == nullptr) {
            napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi pub key failed!"));
            LOGE("new napi pub key failed");
            HcfObjDestroy(ctx->returnPubKey);
            ctx->returnPubKey = nullptr;
            FreePriKeyCtx(env, ctx);
            return;
        }
        instance = napiPubKey->ConvertToJsPubKey(env);
        if (instance == nullptr) {
            napi_throw(env, GenerateBusinessError(env, HCF_ERR_NAPI, "convert to napi pub key failed!"));
            LOGE("convert to napi pub key failed");
            HcfObjDestroy(ctx->returnPubKey);
            ctx->returnPubKey = nullptr;
            delete napiPubKey;
            FreePriKeyCtx(env, ctx);
            return;
        }

        napi_status ret = napi_wrap(
            env, instance, napiPubKey,
            [](napi_env env, void *data, void *hint) {
                NapiPubKey *napiPubKey = static_cast<NapiPubKey *>(data);
                HcfObjDestroy(napiPubKey->GetPubKey());
                delete napiPubKey;
                return;
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiPubKey obj!");
            ctx->errCode = HCF_ERR_NAPI;
            ctx->errMsg = "failed to wrap napiPubKey obj!";
            HcfObjDestroy(napiPubKey->GetPubKey());
            delete napiPubKey;
        }
    }
    ReturnPromiseResult(env, ctx, instance);
    FreePriKeyCtx(env, ctx);
}

static napi_value NewPriKeyJsGetPubKeyAsyncWork(napi_env env, PriKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "getPubKey", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            PriKeyJsGetPubKeyAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            PriKeyJsGetPubKeyAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);
    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

napi_value NapiPriKey::JsGetPubKey(napi_env env, napi_callback_info info)
{
    PriKeyCtx *context = static_cast<PriKeyCtx *>(HcfMalloc(sizeof(PriKeyCtx), 0));
    if (context == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "malloc context failed"));
        LOGE("malloc context failed!");
        return nullptr;
    }

    HcfResult res = BuildPriKeyJsGetPubKeyCtx(env, info, context);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "build context failed."));
        LOGE("build context failed.");
        FreePriKeyCtx(env, context);
        return nullptr;
    }

    return NewPriKeyJsGetPubKeyAsyncWork(env, context);
}

napi_value NapiPriKey::JsGetPubKeySync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiPriKey *napiPriKey = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_NAPI, "failed to unwrap napiPriKey obj!"));
        LOGE("failed to unwrap napiPriKey obj!");
        return nullptr;
    }

    HcfPriKey *priKey = napiPriKey->GetPriKey();
    if (priKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_NAPI, "failed to get priKey obj!"));
        LOGE("failed to get priKey obj!");
        return nullptr;
    }

    HcfPubKey *returnPubKey = nullptr;
    HcfResult errCode = priKey->getPubKey(priKey, &(returnPubKey));
    if (errCode != HCF_SUCCESS) {
        LOGE("get PubKey fail.");
        napi_throw(env, GenerateBusinessError(env, errCode, "get PubKey fail."));
        return nullptr;
    }

    napi_value instance = nullptr;
    NapiPubKey *napiPubKey = new (std::nothrow) NapiPubKey(returnPubKey);
    if (napiPubKey == nullptr) {
        HcfObjDestroy(returnPubKey);
        returnPubKey = nullptr;
        LOGE("new napi pub key failed");
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "get napi pub key failed!"));
        return nullptr;
    }

    instance = napiPubKey->ConvertToJsPubKey(env);
    napi_status ret = napi_wrap(
        env, instance, napiPubKey,
        [](napi_env env, void *data, void *hint) {
            NapiPubKey *napiPubKey = static_cast<NapiPubKey *>(data);
            HcfObjDestroy(napiPubKey->GetPubKey());
            delete napiPubKey;
            return;
        }, nullptr, nullptr);
    if (ret != napi_ok) {
        LOGE("failed to wrap napiPubKey obj!");
        HcfObjDestroy(napiPubKey->GetPubKey());
        delete napiPubKey;
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_NAPI, "failed to wrap napiPubKey obj!"));
        return nullptr;
    }

    return instance;
}
void NapiPriKey::DefinePriKeyJSClass(napi_env env)
{
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("getEncoded", NapiPriKey::JsGetEncoded),
        DECLARE_NAPI_FUNCTION("getEncodedDer", NapiPriKey::JsGetEncodedDer),
        DECLARE_NAPI_FUNCTION("getEncodedPem", NapiPriKey::JsGetEncodedPem),
        DECLARE_NAPI_FUNCTION("clearMem", NapiPriKey::JsClearMem),
        DECLARE_NAPI_FUNCTION("getAsyKeySpec", NapiPriKey::JsGetAsyKeySpec),
        DECLARE_NAPI_FUNCTION("getPubKey", NapiPriKey::JsGetPubKey),
        DECLARE_NAPI_FUNCTION("getPubKeySync", NapiPriKey::JsGetPubKeySync),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "PriKey", NAPI_AUTO_LENGTH, NapiPriKey::PriKeyConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
