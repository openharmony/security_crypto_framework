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

#include "napi_verify.h"

#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_crypto_framework_defines.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "napi_utils.h"

namespace OHOS {
namespace CryptoFramework {
struct VerifyInitCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;

    HcfVerify *verify = nullptr;
    HcfParamsSpec *params = nullptr;
    HcfPubKey *pubKey = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
};

struct VerifyUpdateCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;

    HcfVerify *verify = nullptr;
    HcfBlob *data = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
};

struct VerifyDoFinalCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;

    HcfVerify *verify = nullptr;
    HcfBlob *data = nullptr;
    HcfBlob *signatureData = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    bool isVerifySucc;
};

thread_local napi_ref NapiVerify::classRef_ = nullptr;

static void FreeVerifyInitCtx(napi_env env, VerifyInitCtx *ctx)
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

    HcfFree(ctx);
}

static void FreeVerifyUpdateCtx(napi_env env, VerifyUpdateCtx *ctx)
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

    HcfBlobDataFree(ctx->data);
    HcfFree(ctx->data);
    HcfFree(ctx);
}

static void FreeVerifyDoFinalCtx(napi_env env, VerifyDoFinalCtx *ctx)
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

    HcfBlobDataFree(ctx->data);
    HcfFree(ctx->data);
    HcfBlobDataFree(ctx->signatureData);
    HcfFree(ctx->signatureData);
    HcfFree(ctx);
}

static bool BuildVerifyJsInitCtx(napi_env env, napi_callback_info info, VerifyInitCtx *ctx)
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

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        LOGE("failed to unwrap napi verify obj.");
        return false;
    }

    size_t index = 0;
    NapiPubKey *napiPubKey = nullptr;
    status = napi_unwrap(env, argv[index], reinterpret_cast<void **>(&napiPubKey));
    if (status != napi_ok || napiPubKey == nullptr) {
        LOGE("failed to unwrap napi pubKey obj.");
        return false;
    }

    ctx->verify = napiVerify->GetVerify();
    ctx->params = nullptr;
    ctx->pubKey = napiPubKey->GetPubKey();

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool BuildVerifyJsUpdateCtx(napi_env env, napi_callback_info info, VerifyUpdateCtx *ctx)
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

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        LOGE("failed to unwrap napi verify obj.");
        return false;
    }

    size_t index = 0;
    HcfBlob *blob = GetBlobFromNapiValue(env, argv[index]);
    if (blob == nullptr) {
        return false;
    }

    ctx->verify = napiVerify->GetVerify();
    ctx->data = blob;

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool GetDataBlobAndSignatureFromInput(napi_env env, napi_value dataValue, napi_value signatureDataValue,
    HcfBlob **returnData, HcfBlob **returnSignatureData)
{
    napi_valuetype valueType;
    napi_typeof(env, dataValue, &valueType);
    HcfBlob *data = nullptr;
    if (valueType != napi_null) {
        data = GetBlobFromNapiValue(env, dataValue);
        if (data == nullptr) {
            LOGE("failed to get data.");
            return false;
        }
    }

    HcfBlob *signatureData = GetBlobFromNapiValue(env, signatureDataValue);
    if (signatureData == nullptr) {
        LOGE("failed to get signature.");
        HcfBlobDataFree(data);
        HcfFree(data);
        return false;
    }

    *returnData = data;
    *returnSignatureData = signatureData;
    return true;
}

static bool BuildVerifyJsDoFinalCtx(napi_env env, napi_callback_info info, VerifyDoFinalCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_THREE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_THREE] = { nullptr, nullptr, nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != expectedArgc - 1)) {
        LOGE("wrong argument num. require %zu or %zu arguments. [Argc]: %zu!", expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiVerify *napiVerify = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        LOGE("failed to unwrap napi verify obj.");
        return false;
    }

    HcfBlob *data = nullptr;
    HcfBlob *signatureData = nullptr;
    if (!GetDataBlobAndSignatureFromInput(env, argv[PARAM0], argv[PARAM1], &data, &signatureData)) {
        return false;
    }

    ctx->verify = napiVerify->GetVerify();
    ctx->data = data;
    ctx->signatureData = signatureData;

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static void ReturnInitCallbackResult(napi_env env, VerifyInitCtx *ctx, napi_value result)
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

static void ReturnInitPromiseResult(napi_env env, VerifyInitCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnUpdateCallbackResult(napi_env env, VerifyUpdateCtx *ctx, napi_value result)
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

static void ReturnUpdatePromiseResult(napi_env env, VerifyUpdateCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnDoFinalCallbackResult(napi_env env, VerifyDoFinalCtx *ctx, napi_value result)
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

static void ReturnDoFinalPromiseResult(napi_env env, VerifyDoFinalCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

void VerifyJsInitAsyncWorkProcess(napi_env env, void *data)
{
    VerifyInitCtx *ctx = static_cast<VerifyInitCtx *>(data);

    ctx->errCode = ctx->verify->init(ctx->verify, ctx->params, ctx->pubKey);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("verify init fail.");
        ctx->errMsg = "verify init fail.";
    }
}

void VerifyJsInitAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    VerifyInitCtx *ctx = static_cast<VerifyInitCtx *>(data);

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnInitCallbackResult(env, ctx, NapiGetNull(env));
    } else {
        ReturnInitPromiseResult(env, ctx, NapiGetNull(env));
    }
    FreeVerifyInitCtx(env, ctx);
}

void VerifyJsUpdateAsyncWorkProcess(napi_env env, void *data)
{
    VerifyUpdateCtx *ctx = static_cast<VerifyUpdateCtx *>(data);

    ctx->errCode = ctx->verify->update(ctx->verify, ctx->data);
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("verify update fail.");
        ctx->errMsg = "verify update fail.";
    }
}

void VerifyJsUpdateAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    VerifyUpdateCtx *ctx = static_cast<VerifyUpdateCtx *>(data);

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnUpdateCallbackResult(env, ctx, NapiGetNull(env));
    } else {
        ReturnUpdatePromiseResult(env, ctx, NapiGetNull(env));
    }
    FreeVerifyUpdateCtx(env, ctx);
}

void VerifyJsDoFinalAsyncWorkProcess(napi_env env, void *data)
{
    VerifyDoFinalCtx *ctx = static_cast<VerifyDoFinalCtx *>(data);

    ctx->isVerifySucc = ctx->verify->verify(ctx->verify, ctx->data, ctx->signatureData);
    ctx->errCode = HCF_SUCCESS;
    if (!ctx->isVerifySucc) {
        LOGE("verify doFinal fail.");
        return;
    }
}

void VerifyJsDoFinalAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    VerifyDoFinalCtx *ctx = static_cast<VerifyDoFinalCtx *>(data);

    napi_value result = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        napi_get_boolean(env, ctx->isVerifySucc, &result);
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnDoFinalCallbackResult(env, ctx, result);
    } else {
        ReturnDoFinalPromiseResult(env, ctx, result);
    }
    FreeVerifyDoFinalCtx(env, ctx);
}

static napi_value NewVerifyJsInitAsyncWork(napi_env env, VerifyInitCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "init", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            VerifyJsInitAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            VerifyJsInitAsyncWorkReturn(env, status, data);
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

static napi_value NewVerifyJsUpdateAsyncWork(napi_env env, VerifyUpdateCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "update", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            VerifyJsUpdateAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            VerifyJsUpdateAsyncWorkReturn(env, status, data);
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

static napi_value NewVerifyJsDoFinalAsyncWork(napi_env env, VerifyDoFinalCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "verify", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            VerifyJsDoFinalAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            VerifyJsDoFinalAsyncWorkReturn(env, status, data);
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

NapiVerify::NapiVerify(HcfVerify *verify)
{
    this->verify_ = verify;
}

NapiVerify::~NapiVerify()
{
    HcfObjDestroy(this->verify_);
}

HcfVerify *NapiVerify::GetVerify()
{
    return this->verify_;
}

napi_value NapiVerify::JsInit(napi_env env, napi_callback_info info)
{
    VerifyInitCtx *ctx = static_cast<VerifyInitCtx *>(HcfMalloc(sizeof(VerifyInitCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create context fail."));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildVerifyJsInitCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeVerifyInitCtx(env, ctx);
        return nullptr;
    }

    return NewVerifyJsInitAsyncWork(env, ctx);
}

napi_value NapiVerify::JsUpdate(napi_env env, napi_callback_info info)
{
    VerifyUpdateCtx *ctx = static_cast<VerifyUpdateCtx *>(HcfMalloc(sizeof(VerifyUpdateCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create context fail."));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildVerifyJsUpdateCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeVerifyUpdateCtx(env, ctx);
        return nullptr;
    }

    return NewVerifyJsUpdateAsyncWork(env, ctx);
}

napi_value NapiVerify::JsVerify(napi_env env, napi_callback_info info)
{
    VerifyDoFinalCtx *ctx = static_cast<VerifyDoFinalCtx *>(HcfMalloc(sizeof(VerifyDoFinalCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create context fail."));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildVerifyJsDoFinalCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeVerifyDoFinalCtx(env, ctx);
        return nullptr;
    }

    return NewVerifyJsDoFinalAsyncWork(env, ctx);
}

napi_value NapiVerify::VerifyConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static napi_value NapiWrapVerify(napi_env env, napi_value instance, NapiVerify *napiVerify)
{
    napi_status status = napi_wrap(
        env, instance, napiVerify,
        [](napi_env env, void *data, void *hint) {
            NapiVerify *napiVerify = static_cast<NapiVerify *>(data);
            delete napiVerify;
            return;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("failed to wrap napiVerify obj!");
        delete napiVerify;
        napiVerify = nullptr;
        return nullptr;
    }
    return instance;
}

napi_value NapiVerify::CreateJsVerify(napi_env env, napi_callback_info info)
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
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get algoName."));
        LOGE("failed to get algoName.");
        return nullptr;
    }

    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate(algName.c_str(), &verify);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "create c verify fail."));
        LOGE("create c verify fail.");
        return nullptr;
    }

    NapiVerify *napiVerify = new (std::nothrow) NapiVerify(verify);
    if (napiVerify == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi verify failed"));
        LOGE("new napi verify failed");
        HcfObjDestroy(verify);
        return nullptr;
    }

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName.c_str(), NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    return NapiWrapVerify(env, instance, napiVerify);
}

// verify setVerifySpec(itemType :VerifySpecItem, itemValue : number)
napi_value NapiVerify::JsSetVerifySpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiVerify *napiVerify = nullptr;
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
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
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "get VerifySpec saltLen failed!"));
        LOGE("get VerifySpec saltLen failed!");
        return nullptr;
    }
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiVerify obj!"));
        LOGE("failed to unwrap napiVerify obj!");
        return nullptr;
    }
    HcfVerify *verify = napiVerify->GetVerify();
    HcfResult res = verify->setVerifySpecInt(verify, item, saltLen);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "c setVerifySpecNumber fail."));
        LOGE("c setVerifySpecNumber fail.");
        return nullptr;
    }
    return thisVar;
}

static napi_value GetVerifySpecString(napi_env env, SignSpecItem item, HcfVerify *verify)
{
    char *returnString = nullptr;
    HcfResult res = verify->getVerifySpecString(verify, item, &returnString);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getVerifySpecString failed."));
        LOGE("c getVerifySpecString fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, NAPI_AUTO_LENGTH, &instance);
    HcfFree(returnString);
    return instance;
}

static napi_value GetVerifySpecNumber(napi_env env, SignSpecItem item, HcfVerify *verify)
{
    int returnInt;
    HcfResult res = verify->getVerifySpecInt(verify, item, &returnInt);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, res, "C getVerifySpecInt failed."));
        LOGE("c getVerifySpecInt fail.");
        return nullptr;
    }

    napi_value instance = nullptr;
    napi_create_int32(env, returnInt, &instance);
    return instance;
}

napi_value NapiVerify::JsGetVerifySpec(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiVerify *napiVerify = nullptr;
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
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "get getVerifySpecString failed!"));
        LOGE("get getVerifySpecString failed!");
        return nullptr;
    }

    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiVerify));
    if (status != napi_ok || napiVerify == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to unwrap napiVerify obj!"));
        LOGE("failed to unwrap napiVerify obj!");
        return nullptr;
    }
    HcfVerify *verify = napiVerify->GetVerify();
    if (verify == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get verify obj!"));
        LOGE("failed to get verfiy obj!");
        return nullptr;
    }

    int32_t type = GetSignSpecType(item);
    if (type == SPEC_ITEM_TYPE_STR) {
        return GetVerifySpecString(env, item, verify);
    } else if (type == SPEC_ITEM_TYPE_NUM) {
        return GetVerifySpecNumber(env, item, verify);
    } else {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "VerifySpecItem not support!"));
        return nullptr;
    }
}

void NapiVerify::DefineVerifyJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createVerify", NapiVerify::CreateJsVerify),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("init", NapiVerify::JsInit),
        DECLARE_NAPI_FUNCTION("update", NapiVerify::JsUpdate),
        DECLARE_NAPI_FUNCTION("verify", NapiVerify::JsVerify),
        DECLARE_NAPI_FUNCTION("setVerifySpec", NapiVerify::JsSetVerifySpec),
        DECLARE_NAPI_FUNCTION("getVerifySpec", NapiVerify::JsGetVerifySpec),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "Verify", NAPI_AUTO_LENGTH, NapiVerify::VerifyConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
