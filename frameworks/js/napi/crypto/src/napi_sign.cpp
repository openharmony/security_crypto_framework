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

#include "napi_sign.h"

#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_crypto_framework_defines.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "napi_utils.h"

namespace OHOS {
namespace CryptoFramework {
struct SignInitCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;

    HcfSign *sign = nullptr;
    HcfParamsSpec *params = nullptr;
    HcfPriKey *priKey = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
};

struct SignUpdateCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;

    HcfSign *sign;
    HcfBlob *data;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
};

struct SignDoFinalCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;

    HcfSign *sign;
    HcfBlob *data;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfBlob returnSignatureData;
};

thread_local napi_ref NapiSign::classRef_ = nullptr;

static void FreeSignInitCtx(napi_env env, SignInitCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
    }

    if (ctx->callback != nullptr) {
        napi_delete_reference(env, ctx->callback);
    }

    HcfFree(ctx);
}

static void FreeSignUpdateCtx(napi_env env, SignUpdateCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
    }

    if (ctx->callback != nullptr) {
        napi_delete_reference(env, ctx->callback);
    }

    HcfBlobDataFree(ctx->data);
    HcfFree(ctx->data);
    HcfFree(ctx);
}

static void FreeSignDoFinalCtx(napi_env env, SignDoFinalCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }

    if (ctx->callback != nullptr) {
        napi_delete_reference(env, ctx->callback);
        ctx->callback = nullptr;
    }

    if (ctx->returnSignatureData.data != nullptr) {
        HcfFree(ctx->returnSignatureData.data);
        ctx->returnSignatureData.data = nullptr;
        ctx->returnSignatureData.len = 0;
    }

    HcfBlobDataFree(ctx->data);
    HcfFree(ctx->data);
    HcfFree(ctx);
}

static bool BuildSignJsInitCtx(napi_env env, napi_callback_info info, SignInitCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr, nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require %zu or %zu arguments. [Argc]: %zu!", expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiSign *napiSign = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiSign));
    if (status != napi_ok || napiSign == nullptr) {
        LOGE("failed to unwrap napi sign obj.");
        return false;
    }

    size_t index = 0;
    NapiPriKey *napiPriKey = nullptr;
    status = napi_unwrap(env, argv[index], reinterpret_cast<void **>(&napiPriKey));
    if (status != napi_ok || napiPriKey == nullptr) {
        LOGE("failed to unwrap napi priKey obj.");
        return false;
    }

    ctx->sign = napiSign->GetSign();
    ctx->params = nullptr;
    ctx->priKey = napiPriKey->GetPriKey();

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool BuildSignJsUpdateCtx(napi_env env, napi_callback_info info, SignUpdateCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr, nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != expectedArgc - 1)) {
        LOGE("wrong argument num. require %zu or %zu arguments. [Argc]: %zu!", expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiSign *napiSign = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiSign));
    if (status != napi_ok || napiSign == nullptr) {
        LOGE("failed to unwrap napi sign obj.");
        return false;
    }

    size_t index = 0;
    HcfBlob *blob = GetBlobFromNapiValue(env, argv[index]);
    if (blob == nullptr) {
        LOGE("failed to get data.");
        return false;
    }

    ctx->sign = napiSign->GetSign();
    ctx->data = blob;

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool BuildSignJsDoFinalCtx(napi_env env, napi_callback_info info, SignDoFinalCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_TWO;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_TWO] = { nullptr, nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != expectedArgc - 1)) {
        LOGE("wrong argument num. require %zu or %zu arguments. [Argc]: %zu!", expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiSign *napiSign = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiSign));
    if (status != napi_ok || napiSign == nullptr) {
        LOGE("failed to unwrap napi sign obj.");
        return false;
    }

    size_t index = 0;
    napi_valuetype valueType;
    napi_typeof(env, argv[index], &valueType);
    HcfBlob *data = nullptr;
    if (valueType != napi_null) {
        data = GetBlobFromNapiValue(env, argv[index]);
        if (data == nullptr) {
            LOGE("failed to get data.");
            return false;
        }
    }

    ctx->sign = napiSign->GetSign();
    ctx->data = data;

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static void ReturnInitCallbackResult(napi_env env, SignInitCtx *ctx, napi_value result)
{
    napi_value businessError = nullptr;
    if (ctx->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, ctx->errCode, ctx->errMsg);
    }

    napi_value params[ARGS_SIZE_ONE] = { businessError };

    napi_value func = nullptr;
    napi_get_reference_value(env, ctx->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_ONE, params, &callFuncRet);
}

static void ReturnInitPromiseResult(napi_env env, SignInitCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred, GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnUpdateCallbackResult(napi_env env, SignUpdateCtx *ctx, napi_value result)
{
    napi_value businessError = nullptr;
    if (ctx->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, ctx->errCode, ctx->errMsg);
    }

    napi_value params[ARGS_SIZE_ONE] = { businessError };

    napi_value func = nullptr;
    napi_get_reference_value(env, ctx->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_ONE, params, &callFuncRet);
}

static void ReturnUpdatePromiseResult(napi_env env, SignUpdateCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred, GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnDoFinalCallbackResult(napi_env env, SignDoFinalCtx *ctx, napi_value result)
{
    napi_value businessError = nullptr;
    if (ctx->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, ctx->errCode, ctx->errMsg);
    }

    napi_value params[ARGS_SIZE_TWO] = { businessError, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, ctx->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_TWO, params, &callFuncRet);
}

static void ReturnDoFinalPromiseResult(napi_env env, SignDoFinalCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred, GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

void SignJsInitAsyncWorkProcess(napi_env env, void *data)
{
    SignInitCtx *ctx = static_cast<SignInitCtx *>(data);

    ctx->errCode = ctx->sign->init(ctx->sign, ctx->params, ctx->priKey);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("sign init fail.");
        ctx->errMsg = "sign init fail.";
    }
}

void SignJsInitAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    SignInitCtx *ctx = static_cast<SignInitCtx *>(data);

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnInitCallbackResult(env, ctx, NapiGetNull(env));
    } else {
        ReturnInitPromiseResult(env, ctx, NapiGetNull(env));
    }
    FreeSignInitCtx(env, ctx);
}

void SignJsUpdateAsyncWorkProcess(napi_env env, void *data)
{
    SignUpdateCtx *ctx = static_cast<SignUpdateCtx *>(data);

    ctx->errCode = ctx->sign->update(ctx->sign, ctx->data);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("sign update fail.");
        ctx->errMsg = "sign update fail.";
    }
}

void SignJsUpdateAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    SignUpdateCtx *ctx = static_cast<SignUpdateCtx *>(data);

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnUpdateCallbackResult(env, ctx, NapiGetNull(env));
    } else {
        ReturnUpdatePromiseResult(env, ctx, NapiGetNull(env));
    }
    FreeSignUpdateCtx(env, ctx);
}

void SignJsDoFinalAsyncWorkProcess(napi_env env, void *data)
{
    SignDoFinalCtx *ctx = static_cast<SignDoFinalCtx *>(data);

    ctx->errCode = ctx->sign->sign(ctx->sign, ctx->data, &ctx->returnSignatureData);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("sign doFinal fail.");
        ctx->errMsg = "sign doFinal fail.";
    }
}

void SignJsDoFinalAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    SignDoFinalCtx *ctx = static_cast<SignDoFinalCtx *>(data);

    napi_value dataBlob = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        dataBlob = ConvertBlobToNapiValue(env, &ctx->returnSignatureData);
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnDoFinalCallbackResult(env, ctx, dataBlob);
    } else {
        ReturnDoFinalPromiseResult(env, ctx, dataBlob);
    }
    FreeSignDoFinalCtx(env, ctx);
}

static napi_value NewSignJsInitAsyncWork(napi_env env, SignInitCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "init", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            SignJsInitAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            SignJsInitAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    if (ctx->asyncType == ASYNC_PROMISE) {
        return ctx->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value NewSignJsUpdateAsyncWork(napi_env env, SignUpdateCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "update", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            SignJsUpdateAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            SignJsUpdateAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    if (ctx->asyncType == ASYNC_PROMISE) {
        return ctx->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value NewSignJsDoFinalAsyncWork(napi_env env, SignDoFinalCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "sign", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            SignJsDoFinalAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            SignJsDoFinalAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    if (ctx->asyncType == ASYNC_PROMISE) {
        return ctx->promise;
    } else {
        return NapiGetNull(env);
    }
}

NapiSign::NapiSign(HcfSign *sign)
{
    this->sign_ = sign;
}

NapiSign::~NapiSign()
{
    HcfObjDestroy(this->sign_);
}

HcfSign *NapiSign::GetSign()
{
    return this->sign_;
}

napi_value NapiSign::JsInit(napi_env env, napi_callback_info info)
{
    SignInitCtx *ctx = static_cast<SignInitCtx *>(HcfMalloc(sizeof(SignInitCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create context fail."));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildSignJsInitCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeSignInitCtx(env, ctx);
        return nullptr;
    }

    return NewSignJsInitAsyncWork(env, ctx);
}

napi_value NapiSign::JsUpdate(napi_env env, napi_callback_info info)
{
    SignUpdateCtx *ctx = static_cast<SignUpdateCtx *>(HcfMalloc(sizeof(SignUpdateCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create context fail."));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildSignJsUpdateCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeSignUpdateCtx(env, ctx);
        return nullptr;
    }

    return NewSignJsUpdateAsyncWork(env, ctx);
}

napi_value NapiSign::JsSign(napi_env env, napi_callback_info info)
{
    SignDoFinalCtx *ctx = static_cast<SignDoFinalCtx *>(HcfMalloc(sizeof(SignDoFinalCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create context fail."));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildSignJsDoFinalCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeSignDoFinalCtx(env, ctx);
        return nullptr;
    }

    return NewSignJsDoFinalAsyncWork(env, ctx);
}

napi_value NapiSign::SignConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static napi_value NapiWrapSign(napi_env env, napi_value instance, NapiSign *napiSign)
{
    napi_status status = napi_wrap(
        env, instance, napiSign,
        [](napi_env env, void *data, void *hint) {
            NapiSign *napiSign = static_cast<NapiSign *>(data);
            delete napiSign;
            return;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("failed to wrap napiSign obj!");
        delete napiSign;
        napiSign = nullptr;
        return nullptr;
    }
    return instance;
}

napi_value NapiSign::CreateJsSign(napi_env env, napi_callback_info info)
{
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != expectedArgc) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        LOGE("The input args num is invalid.");
        return nullptr;
    }

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    std::string algName;
    if (!GetStringFromJSParams(env, argv[0], algName)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "get algName fail."));
        return nullptr;
    }

    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate(algName.c_str(), &sign);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "create c sign fail."));
        LOGE("create c sign fail.");
        return nullptr;
    }

    NapiSign *napiSign = new (std::nothrow) NapiSign(sign);
    if (napiSign == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi sign failed"));
        LOGE("new napi sign failed");
        HcfObjDestroy(sign);
        return nullptr;
    }

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName.c_str(), NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    return NapiWrapSign(env, instance, napiSign);
}

// sign setSignSpec(itemType :signSpecItem, itemValue : number)
napi_value NapiSign::JsSetSignSpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiSign *napiSign = nullptr;
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    // thisVar means the js this argument for the call (sign.() means this = sign)
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "init failed for wrong argument num."));
        LOGE("wrong argument num. require 2 arguments. [Argc]: %zu!", argc);
        return nullptr;
    }
    SignSpecItem item;
    if (napi_get_value_uint32(env, argv[0], reinterpret_cast<uint32_t *>(&item)) != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "get signSpecItem failed!"));
        LOGE("get signspecitem failed!");
        return nullptr;
    }
    int32_t saltLen;
    if (napi_get_value_int32(env, argv[1], &saltLen) != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "get signSpec saltLen failed!"));
        LOGE("get signSpec saltLen failed!");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiSign));
    if (status != napi_ok || napiSign == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiSign obj!"));
        LOGE("failed to unwrap napiSign obj!");
        return nullptr;
    }
    HcfSign *sign = napiSign->GetSign();
    HcfResult res = sign->setSignSpecInt(sign, item, saltLen);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "c setSignSpecNumber fail."));
        LOGE("c setSignSpecNumber fail.");
        return nullptr;
    }
    return thisVar;
}

static napi_value GetSignSpecString(napi_env env, SignSpecItem item, HcfSign *sign)
{
    char *returnString = nullptr;
    HcfResult res = sign->getSignSpecString(sign, item, &returnString);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getSignSpecString failed."));
        LOGE("c getSignSpecString fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    return instance;
}

static napi_value GetSignSpecNumber(napi_env env, SignSpecItem item, HcfSign *sign)
{
    int returnInt;
    HcfResult res = sign->getSignSpecInt(sign, item, &returnInt);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getSignSpecInt failed."));
        LOGE("c getSignSpecInt fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_int32(env, returnInt, &instance);
    return instance;
}

napi_value NapiSign::JsGetSignSpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiSign *napiSign = nullptr;
    size_t expectedArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "init failed for wrong argument num."));
        LOGE("wrong argument num. require 1 arguments. [Argc]: %zu!", argc);
        return nullptr;
    }
    SignSpecItem item;
    if (napi_get_value_uint32(env, argv[0], reinterpret_cast<uint32_t *>(&item)) != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "get getSignSpecString failed!"));
        LOGE("get getSignSpecString failed!");
        return nullptr;
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiSign));
    if (status != napi_ok || napiSign == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiSign obj!"));
        LOGE("failed to unwrap napiSign obj!");
        return nullptr;
    }
    HcfSign *sign = napiSign->GetSign();
    if (sign == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get sign obj!"));
        LOGE("failed to get sign obj!");
        return nullptr;
    }

    int32_t type = GetSignSpecType(item);
    if (type == SPEC_ITEM_TYPE_STR) {
        return GetSignSpecString(env, item, sign);
    } else if (type == SPEC_ITEM_TYPE_NUM) {
        return GetSignSpecNumber(env, item, sign);
    } else {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "SignSpecItem not support!"));
        return nullptr;
    }
}

void NapiSign::DefineSignJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createSign", NapiSign::CreateJsSign),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("init", NapiSign::JsInit),
        DECLARE_NAPI_FUNCTION("update", NapiSign::JsUpdate),
        DECLARE_NAPI_FUNCTION("sign", NapiSign::JsSign),
        DECLARE_NAPI_FUNCTION("setSignSpec", NapiSign::JsSetSignSpec),
        DECLARE_NAPI_FUNCTION("getSignSpec", NapiSign::JsGetSignSpec),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "Sign", NAPI_AUTO_LENGTH, NapiSign::SignConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
