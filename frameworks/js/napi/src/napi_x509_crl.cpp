/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_x509_crl.h"

#include "napi/native_node_api.h"
#include "napi/native_api.h"
#include "log.h"
#include "memory.h"
#include "utils.h"
#include "object_base.h"
#include "result.h"
#include "napi_crypto_framework_defines.h"
#include "napi_pub_key.h"
#include "napi_utils.h"
#include "napi_x509_certificate.h"
#include "napi_x509_crl_entry.h"

namespace OHOS {
namespace CryptoFramework {
napi_ref NapiX509Crl::classRef_ = nullptr;

struct CfCtx {
    CfAsyncType asyncType = ASYNC_TYPE_CALLBACK;
    napi_value promise = nullptr;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;

    HcfEncodingBlob *encodingBlob = nullptr;
    NapiX509Crl *crlClass = nullptr;
    HcfX509Certificate *certificate = nullptr;
    HcfPubKey *pubKey = nullptr;
    int32_t serialNumber = 0;

    HcfX509CrlEntry *crlEntry = nullptr;
    int32_t errCode = 0;
    const char *errMsg = nullptr;
    bool isRevoked = false;
    HcfX509Crl *crl;
    HcfEncodingBlob *encoded = nullptr;
    HcfBlob *blob = nullptr;
    HcfArray *array = nullptr;
};

static void FreeCryptoFwkCtx(napi_env env, CfCtx *context)
{
    if (context == nullptr) {
        return;
    }

    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
    }

    if (context->callback != nullptr) {
        napi_delete_reference(env, context->callback);
    }

    HcfEncodingBlobDataFree(context->encodingBlob);
    HcfFree(context->encodingBlob);
    context->encodingBlob = nullptr;

    HcfEncodingBlobDataFree(context->encoded);
    HcfFree(context->encoded);
    context->encoded = nullptr;

    HcfBlobDataFree(context->blob);
    HcfFree(context->blob);
    context->blob = nullptr;

    if (context->array != nullptr) {
        HcfFree(context->array->data);
        context->array->data = nullptr;
        HcfFree(context->array);
        context->array = nullptr;
    }

    HcfFree(context);
}

static void ReturnCallbackResult(napi_env env, CfCtx *context, napi_value result)
{
    napi_value businessError = nullptr;
    if (context->errCode != HCF_SUCCESS) {
        businessError = GenerateBusinessError(env, context->errCode, context->errMsg);
    }
    napi_value params[ARGS_SIZE_TWO] = { businessError, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, context->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_TWO, params, &callFuncRet);
}

static void ReturnPromiseResult(napi_env env, CfCtx *context, napi_value result)
{
    if (context->errCode == HCF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred, GenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

static void ReturnResult(napi_env env, CfCtx *context, napi_value result)
{
    if (context->asyncType == ASYNC_TYPE_CALLBACK) {
        ReturnCallbackResult(env, context, result);
    } else {
        ReturnPromiseResult(env, context, result);
    }
}

static bool CreateCallbackAndPromise(napi_env env, CfCtx *context, size_t argc,
    size_t maxCount, napi_value callbackValue)
{
    context->asyncType = (argc == maxCount) ? ASYNC_TYPE_CALLBACK : ASYNC_TYPE_PROMISE;
    if (context->asyncType == ASYNC_TYPE_CALLBACK) {
        if (!GetCallbackFromJSParams(env, callbackValue, &context->callback)) {
            LOGE("get callback failed!");
            return false;
        }
    } else {
        napi_create_promise(env, &context->deferred, &context->promise);
    }
    return true;
}

NapiX509Crl::NapiX509Crl(HcfX509Crl *x509Crl)
{
    this->x509Crl_ = x509Crl;
}

NapiX509Crl::~NapiX509Crl()
{
    HcfObjDestroy(this->x509Crl_);
}

void IsInvokedExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    context->isRevoked = x509Crl->base.isRevoked((HcfCrl *)x509Crl, (HcfCertificate *)context->certificate);
    context->errCode = HCF_SUCCESS;
}

void IsInvokedComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    napi_value result = nullptr;
    if (context->isRevoked) {
        napi_get_boolean(env, true, &result);
    } else {
        napi_get_boolean(env, false, &result);
    }
    ReturnResult(env, context, result);
    FreeCryptoFwkCtx(env, context);
}

static void GetEncodedExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    HcfEncodingBlob *encodingBlob = (HcfEncodingBlob *)HcfMalloc(sizeof(HcfEncodingBlob), 0);
    if (encodingBlob == nullptr) {
        LOGE("malloc encoding blob failed!");
        context->errCode = HCF_ERR_MALLOC;
        context->errMsg = "malloc encoding blob failed";
        return;
    }
    context->errCode = x509Crl->getEncoded(x509Crl, encodingBlob);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("get encoded failed!");
        context->errMsg = "get encoded failed";
    }
    context->encoded = encodingBlob;
}

static void GetEncodedComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != HCF_SUCCESS) {
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value returnEncodingBlob = ConvertEncodingBlobToNapiValue(env, context->encoded);
    ReturnResult(env, context, returnEncodingBlob);
    FreeCryptoFwkCtx(env, context);
}

static void VerifyExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    context->errCode = x509Crl->verify(x509Crl, context->pubKey);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("verify crl failed!");
        context->errMsg = "verify crl failed";
    }
}

static void VerifyComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    ReturnResult(env, context, NapiGetNull(env));
    FreeCryptoFwkCtx(env, context);
}

void GetRevokedCertificateExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    context->errCode = x509Crl->getRevokedCert(x509Crl, context->serialNumber, &context->crlEntry);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("get revoked cert failed!");
        context->errMsg = "get revoked cert failed";
    }
}

void GetRevokedCertificateComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != HCF_SUCCESS) {
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value instance = NapiX509CrlEntry::CreateX509CrlEntry(env);
    NapiX509CrlEntry *x509CrlEntryClass = new NapiX509CrlEntry(context->crlEntry);
    napi_wrap(
        env, instance, x509CrlEntryClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509CrlEntry *x509CrlEntryClass = (NapiX509CrlEntry *)data;
            delete x509CrlEntryClass;
            return;
        },
        nullptr, nullptr);
    ReturnResult(env, context, instance);
    FreeCryptoFwkCtx(env, context);
}

void GetRevokedCertificateWithCertExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    context->errCode = x509Crl->getRevokedCertWithCert(x509Crl, context->certificate, &context->crlEntry);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("get revoked cert with cert failed!");
        context->errMsg = "get revoked cert with cert failed";
    }
}

void GetRevokedCertificateWithCertComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != HCF_SUCCESS) {
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value instance = NapiX509CrlEntry::CreateX509CrlEntry(env);
    NapiX509CrlEntry *x509CrlEntryClass = new NapiX509CrlEntry(context->crlEntry);
    napi_wrap(
        env, instance, x509CrlEntryClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509CrlEntry *x509CrlEntryClass = (NapiX509CrlEntry *)data;
            delete x509CrlEntryClass;
            return;
        },
        nullptr, nullptr);
    ReturnResult(env, context, instance);
    FreeCryptoFwkCtx(env, context);
}

void GetRevokedCertificatesExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    HcfArray *array = (HcfArray *)HcfMalloc(sizeof(HcfArray), 0);
    if (array == nullptr) {
        LOGE("malloc array failed!");
        context->errCode = HCF_ERR_MALLOC;
        context->errMsg = "malloc array failed";
        return;
    }
    context->errCode = x509Crl->getRevokedCerts(x509Crl, array);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("get revoked certs failed!");
        context->errMsg = "get revoked certs failed";
    }
    context->array = array;
}

static napi_value GenerateCrlEntryArray(napi_env env, HcfArray *array)
{
    if (array == nullptr) {
        LOGE("crl entry array is null!");
        return nullptr;
    }
    if (array->count == 0) {
        LOGE("crl entry array count is 0!");
        return nullptr;
    }
    napi_value returnArray = nullptr;
    napi_create_array(env, &returnArray);
    for (uint32_t i = 0; i < array->count; i++) {
        HcfBlob *blob = (HcfBlob *)(array->data + i);
        HcfX509CrlEntry *entry = (HcfX509CrlEntry *)blob->data;
        napi_value instance = NapiX509CrlEntry::CreateX509CrlEntry(env);
        NapiX509CrlEntry *x509CrlEntryClass = new NapiX509CrlEntry(entry);
        napi_wrap(
            env, instance, x509CrlEntryClass,
            [](napi_env env, void *data, void *hint) {
                NapiX509CrlEntry *x509CrlEntryClass = (NapiX509CrlEntry *)data;
                delete x509CrlEntryClass;
                return;
            },
            nullptr, nullptr);
        napi_set_element(env, returnArray, i, instance);
    }
    return returnArray;
}

void GetRevokedCertificatesComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != HCF_SUCCESS) {
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value returnArray = GenerateCrlEntryArray(env, context->array);
    ReturnResult(env, context, returnArray);
    FreeCryptoFwkCtx(env, context);
}

void GetTBSCertListExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    HcfBlob *blob = (HcfBlob *)HcfMalloc(sizeof(HcfBlob), 0);
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        context->errCode = HCF_ERR_MALLOC;
        context->errMsg = "malloc blob failed";
        return;
    }
    context->errCode = x509Crl->getTbsInfo(x509Crl, blob);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("get tbs info failed!");
        context->errMsg = "get tbs info failed";
    }
    context->blob = blob;
}

void GetTBSCertListComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != HCF_SUCCESS) {
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value returnBlob = ConvertBlobToNapiValue(env, context->blob);
    ReturnResult(env, context, returnBlob);
    FreeCryptoFwkCtx(env, context);
}

napi_value NapiX509Crl::IsRevoked(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, argv[PARAM0], (void**)&x509Cert);
    if (x509Cert == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "x509 cert is null"));
        LOGE("x509Cert is null!");
        return nullptr;
    }
    CfCtx *context = static_cast<CfCtx *>(HcfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->certificate = x509Cert->GetX509Cert();
    context->crlClass = this;

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, GetResourceName(env, "IsRevoked"),
        IsInvokedExecute,
        IsInvokedComplete,
        (void *)context,
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

napi_value NapiX509Crl::GetType(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ZERO;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ZERO, true)) {
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    const char *type = x509Crl->base.getType((HcfCrl *)x509Crl);
    napi_value result = nullptr;
    napi_create_string_utf8(env, type, strlen(type), &result);
    return result;
}

napi_value NapiX509Crl::GetEncoded(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(HcfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->crlClass = this;

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_ONE, argv[PARAM0])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, GetResourceName(env, "GetEncoded"),
        GetEncodedExecute,
        GetEncodedComplete,
        (void *)context,
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

napi_value NapiX509Crl::Verify(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    NapiPubKey *pubKey = nullptr;
    napi_unwrap(env, argv[PARAM0], (void**)&pubKey);
    if (pubKey == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "public key is null"));
        LOGE("pubKey is null!");
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(HcfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->pubKey = pubKey->GetPubKey();
    context->crlClass = this;

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, GetResourceName(env, "Verify"),
        VerifyExecute,
        VerifyComplete,
        (void *)context,
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

napi_value NapiX509Crl::GetVersion(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ZERO;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ZERO, true)) {
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    int version = x509Crl->getVersion(x509Crl);
    napi_value result = nullptr;
    napi_create_int32(env, version, &result);
    return result;
}

napi_value NapiX509Crl::GetIssuerDN(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ZERO;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ZERO, true)) {
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    HcfBlob *blob = (HcfBlob *)HcfMalloc(sizeof(HcfBlob), 0);
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfResult ret = x509Crl->getIssuerName(x509Crl, blob);
    if (ret != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, ret, "get issuer name failed"));
        LOGE("getIssuerDN failed!");
        HcfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnBlob = ConvertBlobToNapiValue(env, blob);
    HcfBlobDataFree(blob);
    HcfFree(blob);
    blob = nullptr;
    return returnBlob;
}

napi_value NapiX509Crl::GetThisUpdate(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ZERO;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ZERO, true)) {
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    HcfBlob *blob = (HcfBlob *)HcfMalloc(sizeof(HcfBlob), 0);
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfResult ret = x509Crl->getLastUpdate(x509Crl, blob);
    if (ret != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, ret, "get last update failed"));
        LOGE("getLastUpdate failed!");
        HcfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_string_utf8(env, (char *)blob->data, blob->len, &result);
    HcfBlobDataFree(blob);
    HcfFree(blob);
    blob = nullptr;
    return result;
}

napi_value NapiX509Crl::GetNextUpdate(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ZERO;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ZERO, true)) {
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    HcfBlob *blob = (HcfBlob *)HcfMalloc(sizeof(HcfBlob), 0);
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfResult ret = x509Crl->getNextUpdate(x509Crl, blob);
    if (ret != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, ret, "get next update failed"));
        LOGE("getNextUpdate failed!");
        HcfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_string_utf8(env, (char *)blob->data, blob->len, &result);
    HcfBlobDataFree(blob);
    HcfFree(blob);
    blob = nullptr;
    return result;
}

napi_value NapiX509Crl::GetRevokedCertificate(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(HcfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->crlClass = this;

    if (!GetInt32FromJSParams(env, argv[PARAM0], context->serialNumber)) {
        LOGE("get serialNumber failed!");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, GetResourceName(env, "GetRevokedCertificate"),
        GetRevokedCertificateExecute,
        GetRevokedCertificateComplete,
        (void *)context,
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

napi_value NapiX509Crl::GetRevokedCertificateWithCert(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, argv[PARAM0], (void**)&x509Cert);
    if (x509Cert == nullptr) {
        napi_throw(env, GenerateBusinessError(env, HCF_INVALID_PARAMS, "x509 cert is null"));
        LOGE("x509Cert is null!");
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(HcfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->certificate = x509Cert->GetX509Cert();
    context->crlClass = this;

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, GetResourceName(env, "GetRevokedCertificateWithCert"),
        GetRevokedCertificateWithCertExecute,
        GetRevokedCertificateWithCertComplete,
        (void *)context,
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

napi_value NapiX509Crl::GetRevokedCertificates(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(HcfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->crlClass = this;

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_ONE, argv[PARAM0])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, GetResourceName(env, "GetRevokedCertificates"),
        GetRevokedCertificatesExecute,
        GetRevokedCertificatesComplete,
        (void *)context,
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

napi_value NapiX509Crl::GetTBSCertList(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(HcfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->crlClass = this;

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_ONE, argv[PARAM0])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, GetResourceName(env, "GetTBSCertList"),
        GetTBSCertListExecute,
        GetTBSCertListComplete,
        (void *)context,
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

napi_value NapiX509Crl::GetSignature(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ZERO;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ZERO, true)) {
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    HcfBlob *blob = (HcfBlob *)HcfMalloc(sizeof(HcfBlob), 0);
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfResult result = x509Crl->getSignature(x509Crl, blob);
    if (result != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, result, "get signature failed"));
        LOGE("getSignature failed!");
        HcfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnBlob = ConvertBlobToNapiValue(env, blob);
    HcfBlobDataFree(blob);
    HcfFree(blob);
    blob = nullptr;
    return returnBlob;
}

napi_value NapiX509Crl::GetSigAlgName(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ZERO;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ZERO, true)) {
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    HcfBlob *blob = (HcfBlob *)HcfMalloc(sizeof(HcfBlob), 0);
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfResult ret = x509Crl->getSignatureAlgName(x509Crl, blob);
    if (ret != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, ret, "get signature alg name failed"));
        LOGE("getSigAlgName failed!");
        HcfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_string_utf8(env, (char *)blob->data, blob->len, &result);
    HcfBlobDataFree(blob);
    HcfFree(blob);
    blob = nullptr;
    return result;
}

napi_value NapiX509Crl::GetSigAlgOID(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ZERO;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ZERO, true)) {
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    HcfBlob *blob = (HcfBlob *)HcfMalloc(sizeof(HcfBlob), 0);
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfResult ret = x509Crl->getSignatureAlgOid(x509Crl, blob);
    if (ret != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, ret, "get signature alg oid failed"));
        LOGE("getSigAlgOID failed!");
        HcfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value result = nullptr;
    napi_create_string_utf8(env, (char *)blob->data, blob->len, &result);
    HcfBlobDataFree(blob);
    HcfFree(blob);
    blob = nullptr;
    return result;
}

napi_value NapiX509Crl::GetSigAlgParams(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ZERO;
    napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_ZERO, true)) {
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    HcfBlob *blob = (HcfBlob *)HcfMalloc(sizeof(HcfBlob), 0);
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfResult result = x509Crl->getSignatureAlgParams(x509Crl, blob);
    if (result != HCF_SUCCESS) {
        napi_throw(env, GenerateBusinessError(env, result, "get signature alg params failed"));
        LOGE("getSigAlgParams failed!");
        HcfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnBlob = ConvertBlobToNapiValue(env, blob);
    HcfBlobDataFree(blob);
    HcfFree(blob);
    blob = nullptr;
    return returnBlob;
}

static napi_value NapiIsRevoked(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->IsRevoked(env, info);
}

static napi_value NapiGetType(napi_env env, napi_callback_info info)
{
    LOGI("napi get crl type called.");
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    LOGI("unwrap x509 crl class success.");
    return x509Crl->GetType(env, info);
}

static napi_value NapiGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetEncoded(env, info);
}

static napi_value NapiVerify(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->Verify(env, info);
}

static napi_value NapiGetVersion(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetVersion(env, info);
}

static napi_value NapiGetIssuerDN(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetIssuerDN(env, info);
}

static napi_value NapiGetThisUpdate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetThisUpdate(env, info);
}

static napi_value NapiGetNextUpdate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetNextUpdate(env, info);
}

static napi_value NapiGetRevokedCertificate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetRevokedCertificate(env, info);
}

static napi_value NapiGetRevokedCertificateWithCert(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetRevokedCertificateWithCert(env, info);
}

static napi_value NapiGetRevokedCertificates(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetRevokedCertificates(env, info);
}

static napi_value NapiGetTBSCertList(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetTBSCertList(env, info);
}

static napi_value NapiGetSignature(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetSignature(env, info);
}

static napi_value NapiGetSigAlgName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetSigAlgName(env, info);
}

static napi_value NapiGetSigAlgOID(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetSigAlgOID(env, info);
}

static napi_value NapiGetSigAlgParams(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetSigAlgParams(env, info);
}

void NapiX509Crl::CreateX509CrlExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    context->errCode = HcfX509CrlCreate(context->encodingBlob, &context->crl);
    if (context->errCode != HCF_SUCCESS) {
        context->errMsg = "create X509Crl failed";
    }
}

void NapiX509Crl::CreateX509CrlComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != HCF_SUCCESS) {
        LOGE("call create X509Crl failed!");
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value instance = CreateX509Crl(env);
    NapiX509Crl *x509CrlClass = new NapiX509Crl(context->crl);
    napi_wrap(
        env, instance, x509CrlClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509Crl *crlClass = (NapiX509Crl *)data;
            delete crlClass;
            return;
        },
        nullptr, nullptr);
    ReturnResult(env, context, instance);
    FreeCryptoFwkCtx(env, context);
}

napi_value NapiX509Crl::NapiCreateX509Crl(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(HcfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    if (!GetEncodingBlobFromValue(env, argv[PARAM0], &context->encodingBlob)) {
        LOGE("get encoding blob from data failed!");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, GetResourceName(env, "createX509Crl"),
        CreateX509CrlExecute,
        CreateX509CrlComplete,
        (void *)context,
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value X509CrlConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

void NapiX509Crl::DefineX509CrlJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createX509Crl", NapiCreateX509Crl),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor x509CrlDesc[] = {
        DECLARE_NAPI_FUNCTION("isRevoked", NapiIsRevoked),
        DECLARE_NAPI_FUNCTION("getType", NapiGetType),
        DECLARE_NAPI_FUNCTION("getEncoded", NapiGetEncoded),
        DECLARE_NAPI_FUNCTION("verify", NapiVerify),
        DECLARE_NAPI_FUNCTION("getVersion", NapiGetVersion),
        DECLARE_NAPI_FUNCTION("getIssuerName", NapiGetIssuerDN),
        DECLARE_NAPI_FUNCTION("getLastUpdate", NapiGetThisUpdate),
        DECLARE_NAPI_FUNCTION("getNextUpdate", NapiGetNextUpdate),
        DECLARE_NAPI_FUNCTION("getRevokedCert", NapiGetRevokedCertificate),
        DECLARE_NAPI_FUNCTION("getRevokedCertWithCert", NapiGetRevokedCertificateWithCert),
        DECLARE_NAPI_FUNCTION("getRevokedCerts", NapiGetRevokedCertificates),
        DECLARE_NAPI_FUNCTION("getTbsInfo", NapiGetTBSCertList),
        DECLARE_NAPI_FUNCTION("getSignature", NapiGetSignature),
        DECLARE_NAPI_FUNCTION("getSignatureAlgName", NapiGetSigAlgName),
        DECLARE_NAPI_FUNCTION("getSignatureAlgOid", NapiGetSigAlgOID),
        DECLARE_NAPI_FUNCTION("getSignatureAlgParams", NapiGetSigAlgParams),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "X509Crl", NAPI_AUTO_LENGTH, X509CrlConstructor, nullptr,
        sizeof(x509CrlDesc) / sizeof(x509CrlDesc[0]), x509CrlDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}

napi_value NapiX509Crl::CreateX509Crl(napi_env env)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    return instance;
}
} // namespace CryptoFramework
} // namespace OHOS
