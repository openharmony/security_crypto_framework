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

#include "napi_asy_key_generator.h"

#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_crypto_framework_defines.h"
#include "napi_utils.h"
#include "napi_key_pair.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"

namespace OHOS {
namespace CryptoFramework {
struct GenKeyPairCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;

    HcfAsyKeyGenerator *generator = nullptr;
    HcfParamsSpec *params = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
};

struct ConvertKeyCtx {
    napi_env env = nullptr;

    AsyncType asyncType = ASYNC_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;

    HcfAsyKeyGenerator *generator = nullptr;
    HcfParamsSpec *params = nullptr;
    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;

    HcfResult errCode = HCF_SUCCESS;
    const char *errMsg = nullptr;
    HcfKeyPair *returnKeyPair = nullptr;
};

thread_local napi_ref NapiAsyKeyGenerator::classRef_ = nullptr;

static void FreeGenKeyPairCtx(napi_env env, GenKeyPairCtx *ctx)
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

static void FreeConvertKeyCtx(napi_env env, ConvertKeyCtx *ctx)
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

    HcfBlobDataFree(ctx->pubKey);
    HcfFree(ctx->pubKey);
    HcfBlobDataFree(ctx->priKey);
    HcfFree(ctx->priKey);
    HcfFree(ctx);
}

static bool BuildGenKeyPairCtx(napi_env env, napi_callback_info info, GenKeyPairCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require %zu or %zu arguments. [Argc]: %zu!", expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[0], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiAsyKeyGenerator *napiGenerator;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }

    ctx->generator = napiGenerator->GetAsyKeyGenerator();
    ctx->params = nullptr;

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static bool GetPkAndSkBlobFromNapiValueIfInput(napi_env env, napi_value pkValue, napi_value skValue,
    HcfBlob **returnPubKey, HcfBlob **returnPriKey)
{
    napi_valuetype valueType;
    napi_typeof(env, pkValue, &valueType);
    HcfBlob *pubKey = nullptr;
    if (valueType != napi_null) {
        pubKey = GetBlobFromNapiDataBlob(env, pkValue);
        if (pubKey == nullptr) {
            LOGE("failed to get pubKey.");
            return false;
        }
    }

    napi_typeof(env, skValue, &valueType);
    HcfBlob *priKey = nullptr;
    if (valueType != napi_null) {
        priKey = GetBlobFromNapiDataBlob(env, skValue);
        if (priKey == nullptr) {
            // if the prikey get func fails, the return pointer will not take the ownership of pubkey and not free it.
            HcfBlobDataFree(pubKey);
            HcfFree(pubKey);
            LOGE("failed to get priKey.");
            return false;
        }
    }

    *returnPubKey = pubKey;
    *returnPriKey = priKey;
    return true;
}

static bool BuildConvertKeyCtx(napi_env env, napi_callback_info info, ConvertKeyCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = PARAMS_NUM_THREE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc && argc != expectedArgc - 1) {
        LOGE("wrong argument num. require %zu or %zu arguments. [Argc]: %zu!", expectedArgc - 1, expectedArgc, argc);
        return false;
    }
    ctx->asyncType = isCallback(env, argv[expectedArgc - 1], argc, expectedArgc) ? ASYNC_CALLBACK : ASYNC_PROMISE;

    NapiAsyKeyGenerator *napiGenerator;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiGenerator));
    if (status != napi_ok || napiGenerator == nullptr) {
        LOGE("failed to unwrap napi asyKeyGenerator obj.");
        return false;
    }

    HcfBlob *pubKey = nullptr;
    HcfBlob *priKey = nullptr;
    if (!GetPkAndSkBlobFromNapiValueIfInput(env, argv[PARAM0], argv[PARAM1], &pubKey, &priKey)) {
        return false;
    }

    ctx->generator = napiGenerator->GetAsyKeyGenerator();
    ctx->params = nullptr;
    ctx->pubKey = pubKey;
    ctx->priKey = priKey;

    if (ctx->asyncType == ASYNC_PROMISE) {
        napi_create_promise(env, &ctx->deferred, &ctx->promise);
        return true;
    } else {
        return GetCallbackFromJSParams(env, argv[expectedArgc - 1], &ctx->callback);
    }
}

static void ReturnGenKeyPairCallbackResult(napi_env env, GenKeyPairCtx *ctx, napi_value result)
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

static void ReturnGenKeyPairPromiseResult(napi_env env, GenKeyPairCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ReturnConvertKeyCallbackResult(napi_env env, ConvertKeyCtx *ctx, napi_value result)
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

static void ReturnConvertKeyPromiseResult(napi_env env, ConvertKeyCtx *ctx, napi_value result)
{
    if (ctx->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            GenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void GenKeyPairAsyncWorkProcess(napi_env env, void *data)
{
    GenKeyPairCtx *ctx = static_cast<GenKeyPairCtx *>(data);

    ctx->errCode = ctx->generator->generateKeyPair(ctx->generator, ctx->params, &(ctx->returnKeyPair));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("generate key pair fail.");
        ctx->errMsg = "generate key pair fail.";
    }
}

static void GenKeyPairAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    GenKeyPairCtx *ctx = static_cast<GenKeyPairCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(ctx->returnKeyPair);
        if (napiKeyPair == nullptr) {
            napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi key pair failed!"));
            LOGE("new napi key pair failed");
            FreeGenKeyPairCtx(env, ctx);
            return;
        }
        instance = napiKeyPair->ConvertToJsKeyPair(env);

        napi_status ret = napi_wrap(
            env, instance, napiKeyPair,
            [](napi_env env, void *data, void *hint) {
                NapiKeyPair *keyPair = static_cast<NapiKeyPair *>(data);
                delete keyPair;
                return;
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiKeyPair obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiKeyPair obj!";
            delete napiKeyPair;
        }
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnGenKeyPairCallbackResult(env, ctx, instance);
    } else {
        ReturnGenKeyPairPromiseResult(env, ctx, instance);
    }
    FreeGenKeyPairCtx(env, ctx);
}

static void ConvertKeyAsyncWorkProcess(napi_env env, void *data)
{
    ConvertKeyCtx *ctx = static_cast<ConvertKeyCtx *>(data);

    ctx->errCode = ctx->generator->convertKey(ctx->generator, ctx->params,
        ctx->pubKey, ctx->priKey, &(ctx->returnKeyPair));
    if (ctx->errCode != HCF_SUCCESS) {
        LOGE("convert key fail.");
        ctx->errMsg = "convert key fail.";
    }
}

static void ConvertKeyAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    ConvertKeyCtx *ctx = static_cast<ConvertKeyCtx *>(data);

    napi_value instance = nullptr;
    if (ctx->errCode == HCF_SUCCESS) {
        NapiKeyPair *napiKeyPair = new (std::nothrow) NapiKeyPair(ctx->returnKeyPair);
        if (napiKeyPair == nullptr) {
            napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi key pair failed!"));
            LOGE("new napi key pair failed");
            FreeConvertKeyCtx(env, ctx);
            return;
        }
        instance = napiKeyPair->ConvertToJsKeyPair(env);

        napi_status ret = napi_wrap(
            env, instance, napiKeyPair,
            [](napi_env env, void *data, void *hint) {
                NapiKeyPair *keyPair = static_cast<NapiKeyPair *>(data);
                delete keyPair;
                return;
            }, nullptr, nullptr);
        if (ret != napi_ok) {
            LOGE("failed to wrap napiKeyPair obj!");
            ctx->errCode = HCF_INVALID_PARAMS;
            ctx->errMsg = "failed to wrap napiKeyPair obj!";
            delete napiKeyPair;
        }
    }

    if (ctx->asyncType == ASYNC_CALLBACK) {
        ReturnConvertKeyCallbackResult(env, ctx, instance);
    } else {
        ReturnConvertKeyPromiseResult(env, ctx, instance);
    }
    FreeConvertKeyCtx(env, ctx);
}

static napi_value NewGenKeyPairAsyncWork(napi_env env, GenKeyPairCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "generatorKeyPair", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            GenKeyPairAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            GenKeyPairAsyncWorkReturn(env, status, data);
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

static napi_value NewConvertKeyAsyncWork(napi_env env, ConvertKeyCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "convertKey", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            ConvertKeyAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            ConvertKeyAsyncWorkReturn(env, status, data);
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

NapiAsyKeyGenerator::NapiAsyKeyGenerator(HcfAsyKeyGenerator *generator)
{
    this->generator_ = generator;
}

NapiAsyKeyGenerator::~NapiAsyKeyGenerator()
{
    HcfObjDestroy(this->generator_);
}

HcfAsyKeyGenerator *NapiAsyKeyGenerator::GetAsyKeyGenerator()
{
    return this->generator_;
}

napi_value NapiAsyKeyGenerator::JsGenerateKeyPair(napi_env env, napi_callback_info info)
{
    GenKeyPairCtx *ctx = static_cast<GenKeyPairCtx *>(HcfMalloc(sizeof(GenKeyPairCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "malloc ctx fail."));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildGenKeyPairCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeGenKeyPairCtx(env, ctx);
        return nullptr;
    }

    return NewGenKeyPairAsyncWork(env, ctx);
}

napi_value NapiAsyKeyGenerator::JsConvertKey(napi_env env, napi_callback_info info)
{
    ConvertKeyCtx *ctx = static_cast<ConvertKeyCtx *>(HcfMalloc(sizeof(ConvertKeyCtx), 0));
    if (ctx == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "create context fail!"));
        LOGE("create context fail.");
        return nullptr;
    }

    if (!BuildConvertKeyCtx(env, info, ctx)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "build context fail."));
        LOGE("build context fail.");
        FreeConvertKeyCtx(env, ctx);
        return nullptr;
    }

    return NewConvertKeyAsyncWork(env, ctx);
}

napi_value NapiAsyKeyGenerator::AsyKeyGeneratorConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static napi_value NapiWrapAsyKeyGen(napi_env env, napi_value instance, NapiAsyKeyGenerator *napiAsyKeyGenerator)
{
    napi_status status = napi_wrap(
        env, instance, napiAsyKeyGenerator,
        [](napi_env env, void *data, void *hint) {
            NapiAsyKeyGenerator *napiAsyKeyGenerator = static_cast<NapiAsyKeyGenerator *>(data);
            delete napiAsyKeyGenerator;
            return;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to wrap napiAsyKeyGenerator obj!"));
        delete napiAsyKeyGenerator;
        napiAsyKeyGenerator = nullptr;
        LOGE("failed to wrap napiAsyKeyGenerator obj!");
        return nullptr;
    }
    return instance;
}

napi_value NapiAsyKeyGenerator::CreateJsAsyKeyGenerator(napi_env env, napi_callback_info info)
{
    LOGD("Enter CreateJsAsyKeyGenerator...");
    size_t expectedArgc = PARAMS_NUM_ONE;
    size_t argc = expectedArgc;
    napi_value argv[PARAMS_NUM_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc != expectedArgc) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "The input args num is invalid."));
        LOGE("The input args num is invalid.");
        return NapiGetNull(env);
    }

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    std::string algName;
    if (!GetStringFromJSParams(env, argv[0], algName)) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "failed to get algoName."));
        LOGE("failed to get algoName.");
        return NapiGetNull(env);
    }

    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "create c generator fail."));
        LOGE("create c generator fail.");
        return NapiGetNull(env);
    }

    NapiAsyKeyGenerator *napiAsyKeyGenerator = new (std::nothrow) NapiAsyKeyGenerator(generator);
    if (napiAsyKeyGenerator == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_ERR_MALLOC, "new napi asy key napi generator failed!"));
        LOGE("new napi asy key napi generator failed");
        HcfObjDestroy(generator);
        return NapiGetNull(env);
    }

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName.c_str(), NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    return NapiWrapAsyKeyGen(env, instance, napiAsyKeyGenerator);
}

void NapiAsyKeyGenerator::DefineAsyKeyGeneratorJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createAsyKeyGenerator", NapiAsyKeyGenerator::CreateJsAsyKeyGenerator),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("generateKeyPair", NapiAsyKeyGenerator::JsGenerateKeyPair),
        DECLARE_NAPI_FUNCTION("convertKey", NapiAsyKeyGenerator::JsConvertKey),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "AsyKeyGenerator", NAPI_AUTO_LENGTH, NapiAsyKeyGenerator::AsyKeyGeneratorConstructor,
        nullptr, sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CryptoFramework
} // OHOS
