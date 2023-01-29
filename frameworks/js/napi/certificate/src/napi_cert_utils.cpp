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

#include "napi_cert_utils.h"

#include "log.h"
#include "memory.h"
#include "securec.h"
#include "cipher.h"
#include "napi_cert_defines.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"

namespace OHOS {
namespace CertFramework {
using namespace std;
napi_value CertNapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value ConvertArrayToNapiValue(napi_env env, HcfArray *array)
{
    if (array == nullptr) {
        LOGE("array is null!");
        return nullptr;
    }
    if (array->count == 0) {
        LOGE("array count is 0!");
        return nullptr;
    }
    napi_value returnArray = nullptr;
    napi_create_array(env, &returnArray);
    if (returnArray == nullptr) {
        LOGE("create return array failed!");
        return nullptr;
    }
    for (uint32_t i = 0; i < array->count; i++) {
        HcfBlob *blob = reinterpret_cast<HcfBlob *>(array->data + i);
        napi_value outBuffer = GenerateArrayBuffer(env, blob->data, blob->len);
        if (outBuffer == nullptr) {
            LOGE("generate array buffer failed!");
            return nullptr;
        }
        napi_value element = nullptr;
        napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &element);
        napi_set_element(env, returnArray, i, element);
    }
    napi_value returnValue = nullptr;
    napi_create_object(env, &returnValue);
    napi_set_named_property(env, returnValue, CERT_TAG_DATA.c_str(), returnArray);
    return returnValue;
}

napi_value GenerateArrayBuffer(napi_env env, uint8_t *data, uint32_t size)
{
    uint8_t *buffer = static_cast<uint8_t *>(HcfMalloc(size, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return nullptr;
    }

    if (memcpy_s(buffer, size, data, size) != EOK) {
        LOGE("memcpy_s data to buffer failed!");
        HcfFree(buffer);
        return nullptr;
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, size, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create uint8 array buffer failed!");
        HcfFree(buffer);
        return nullptr;
    }
    buffer = nullptr;
    return outBuffer;
}

static bool GetDataOfEncodingBlob(napi_env env, napi_value data, HcfEncodingBlob *encodingBlob)
{
    napi_typedarray_type arrayType;
    napi_value arrayBuffer = nullptr;
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;

    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &length,
        reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "get array data failed"));
        LOGE("failed to get array data!");
        return false;
    }
    if (arrayType != napi_uint8_array) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "array type is not uint8 array"));
        LOGE("array is not uint8 array!");
        return false;
    }

    if (length == 0) {
        LOGE("input data length is 0");
        return false;
    }
    encodingBlob->data = static_cast<uint8_t *>(HcfMalloc(length, 0));
    if (encodingBlob->data == nullptr) {
        LOGE("malloc encoding blob data failed!");
        return false;
    }
    if (memcpy_s(encodingBlob->data, length, rawData, length) != EOK) {
        LOGE("memcpy_s encoding blob data failed!");
        HcfFree(encodingBlob->data);
        encodingBlob->data = nullptr;
        return false;
    }
    encodingBlob->len = length;
    return true;
}

bool GetEncodingBlobFromValue(napi_env env, napi_value obj, HcfEncodingBlob **encodingBlob)
{
    *encodingBlob = static_cast<HcfEncodingBlob *>(HcfMalloc(sizeof(HcfEncodingBlob), 0));
    if (*encodingBlob == nullptr) {
        LOGE("malloc encoding blob failed!");
        return false;
    }
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_TAG_DATA.c_str(), &data);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "get encoding blob data failed"));
        LOGE("failed to get encoding blob data!");
        HcfFree(*encodingBlob);
        *encodingBlob = nullptr;
        return false;
    }
    if (!GetDataOfEncodingBlob(env, data, *encodingBlob)) {
        HcfFree(*encodingBlob);
        *encodingBlob = nullptr;
        return false;
    }
    napi_value format = nullptr;
    status = napi_get_named_property(env, obj, CERT_TAG_ENCODING_FORMAT.c_str(), &format);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "get encoding blob format failed"));
        LOGE("failed to get encoding blob format!");
        HcfFree((*encodingBlob)->data);
        (*encodingBlob)->data = nullptr;
        HcfFree(*encodingBlob);
        *encodingBlob = nullptr;
        return false;
    }
    napi_get_value_uint32(env, format, reinterpret_cast<uint32_t *>(&(*encodingBlob)->encodingFormat));
    return true;
}

napi_value ConvertEncodingBlobToNapiValue(napi_env env, HcfEncodingBlob *encodingBlob)
{
    napi_value outBuffer = GenerateArrayBuffer(env, encodingBlob->data, encodingBlob->len);
    if (outBuffer == nullptr) {
        LOGE("generate array buffer failed!");
        return nullptr;
    }
    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, encodingBlob->len, outBuffer, 0, &outData);
    napi_value encoding = nullptr;
    napi_create_uint32(env, encodingBlob->encodingFormat, &encoding);
    napi_value returnEncodingBlob = nullptr;
    napi_create_object(env, &returnEncodingBlob);
    napi_set_named_property(env, returnEncodingBlob, CERT_TAG_DATA.c_str(), outData);
    napi_set_named_property(env, returnEncodingBlob, CERT_TAG_ENCODING_FORMAT.c_str(), encoding);
    return returnEncodingBlob;
}

HcfBlob *CertGetBlobFromNapiValue(napi_env env, napi_value arg)
{
    if ((env == nullptr) || (arg == nullptr)) {
        LOGE("Invalid parmas!");
        return nullptr;
    }
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, arg, CERT_TAG_DATA.c_str(), &data);
    if ((status != napi_ok) || (data == nullptr)) {
        LOGE("failed to get valid data property!");
        return nullptr;
    }

    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;
    napi_value arrayBuffer = nullptr;
    napi_typedarray_type arrayType;
    // Warning: Do not release the rawData returned by this interface because the rawData is managed by VM.
    status = napi_get_typedarray_info(env, data, &arrayType, &length,
        reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
    if ((status != napi_ok) || (length == 0) || (rawData == nullptr)) {
        LOGE("failed to get valid rawData.");
        return nullptr;
    }
    if (arrayType != napi_uint8_array) {
        LOGE("input data is not uint8 array.");
        return nullptr;
    }

    HcfBlob *newBlob = reinterpret_cast<HcfBlob *>(HcfMalloc(sizeof(HcfBlob), 0));
    if (newBlob == nullptr) {
        LOGE("Failed to allocate newBlob memory!");
        return nullptr;
    }
    newBlob->len = length;
    newBlob->data = static_cast<uint8_t *>(HcfMalloc(length, 0));
    if (newBlob->data == nullptr) {
        LOGE("malloc blob data failed!");
        HcfFree(newBlob);
        return nullptr;
    }
    if (memcpy_s(newBlob->data, length, rawData, length) != EOK) {
        LOGE("memcpy_s blob data failed!");
        HcfFree(newBlob->data);
        HcfFree(newBlob);
        return nullptr;
    }

    return newBlob;
}

napi_value CertConvertBlobToNapiValue(napi_env env, HcfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->len == 0) {
        LOGE("Invalid blob!");
        return nullptr;
    }
    uint8_t *buffer = static_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return nullptr;
    }

    if (memcpy_s(buffer, blob->len, blob->data, blob->len) != EOK) {
        LOGE("memcpy_s data to buffer failed!");
        HcfFree(buffer);
        return nullptr;
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->len, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create uint8 array buffer failed!");
        HcfFree(buffer);
        return nullptr;
    }
    buffer = nullptr;

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &outData);
    napi_value dataBlob = nullptr;
    napi_create_object(env, &dataBlob);
    napi_set_named_property(env, dataBlob, CERT_TAG_DATA.c_str(), outData);

    return dataBlob;
}

static bool GetDataOfCertChain(napi_env env, napi_value data, HcfCertChainData *certChain)
{
    napi_typedarray_type arrayType;
    napi_value arrayBuffer = nullptr;
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;

    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &length,
        reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "get array data failed"));
        LOGE("failed to get array data!");
        return false;
    }
    if (arrayType != napi_uint8_array) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "array type is not uint8 array"));
        LOGE("array is not uint8 array!");
        return false;
    }

    if (length == 0) {
        LOGE("input data length is 0");
        return false;
    }
    certChain->data = static_cast<uint8_t *>(HcfMalloc(length, 0));
    if (certChain->data == nullptr) {
        LOGE("malloc cert chain data failed!");
        return false;
    }
    if (memcpy_s(certChain->data, length, rawData, length) != EOK) {
        LOGE("memcpy_s cert chain data failed!");
        HcfFree(certChain->data);
        certChain->data = nullptr;
        return false;
    }
    certChain->dataLen = length;
    return true;
}

bool GetCertChainFromValue(napi_env env, napi_value obj, HcfCertChainData **certChainData)
{
    *certChainData = static_cast<HcfCertChainData *>(HcfMalloc(sizeof(HcfCertChainData), 0));
    if (*certChainData == nullptr) {
        LOGE("malloc certChainData failed!");
        return false;
    }
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_TAG_DATA.c_str(), &data);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "get cert chain data failed"));
        LOGE("failed to get cert chain data!");
        HcfFree(*certChainData);
        *certChainData = nullptr;
        return false;
    }
    if (!GetDataOfCertChain(env, data, *certChainData)) {
        HcfFree(*certChainData);
        *certChainData = nullptr;
        return false;
    }

    napi_value certCount = nullptr;
    status = napi_get_named_property(env, obj, CERT_TAG_COUNT.c_str(), &certCount);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "get cert chain count failed"));
        LOGE("failed to get cert count!");
        HcfFree((*certChainData)->data);
        (*certChainData)->data = nullptr;
        HcfFree(*certChainData);
        *certChainData = nullptr;
        return false;
    }
    napi_get_value_uint32(env, certCount, reinterpret_cast<uint32_t *>(&(*certChainData)->count));

    napi_value format = nullptr;
    status = napi_get_named_property(env, obj, CERT_TAG_ENCODING_FORMAT.c_str(), &format);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "get cert chain format failed"));
        LOGE("failed to get cert chain format!");
        HcfFree((*certChainData)->data);
        (*certChainData)->data = nullptr;
        HcfFree(*certChainData);
        *certChainData = nullptr;
        return false;
    }
    napi_get_value_uint32(env, format, reinterpret_cast<uint32_t *>(&(*certChainData)->format));
    return true;
}

bool CertGetStringFromJSParams(napi_env env, napi_value arg, string &returnStr)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_string) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "param type is not string"));
        LOGE("wrong argument type. expect string type. [Type]: %d", valueType);
        return false;
    }

    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok) {
        LOGE("can not get string length");
        return false;
    }
    returnStr.reserve(length + 1);
    returnStr.resize(length);
    if (napi_get_value_string_utf8(env, arg, returnStr.data(), (length + 1), &length) != napi_ok) {
        LOGE("can not get string value");
        return false;
    }
    return true;
}

bool CertGetInt32FromJSParams(napi_env env, napi_value arg, int32_t &returnInt)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_number) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "param type is not number"));
        LOGE("wrong argument type. expect int type. [Type]: %d", valueType);
        return false;
    }

    if (napi_get_value_int32(env, arg, &returnInt) != napi_ok) {
        LOGE("can not get int value");
        return false;
    }
    return true;
}

bool CertGetCallbackFromJSParams(napi_env env, napi_value arg, napi_ref *returnCb)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_function) {
        napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "param type is not function"));
        LOGE("wrong argument type. expect callback type. [Type]: %d", valueType);
        return false;
    }

    napi_create_reference(env, arg, 1, returnCb);
    return true;
}

static uint32_t GetCertErrValueByErrCode(int32_t errCode)
{
    switch (errCode) {
        case HCF_INVALID_PARAMS:
            return JS_ERR_CERT_INVALID_PARAMS;
        case HCF_NOT_SUPPORT:
            return JS_ERR_CERT_NOT_SUPPORT;
        case HCF_ERR_MALLOC:
            return JS_ERR_CERT_OUT_OF_MEMORY;
        case HCF_ERR_COPY:
            return JS_ERR_CERT_RUNTIME_ERROR;
        case HCF_ERR_CRYPTO_OPERATION:
            return JS_ERR_CERT_CRYPTO_OPERATION;
        case HCF_ERR_CERT_SIGNATURE_FAILURE:
            return JS_ERR_CERT_SIGNATURE_FAILURE;
        case HCF_ERR_CERT_NOT_YET_VALID:
            return JS_ERR_CERT_NOT_YET_VALID;
        case HCF_ERR_CERT_HAS_EXPIRED:
            return JS_ERR_CERT_HAS_EXPIRED;
        case HCF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            return JS_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
        case HCF_ERR_KEYUSAGE_NO_CERTSIGN:
            return JS_ERR_KEYUSAGE_NO_CERTSIGN;
        case HCF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
            return JS_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE;
        default:
            return JS_ERR_DEFAULT_ERR;
    }
}

napi_value CertGenerateBusinessError(napi_env env, int32_t errCode, const char *errMsg)
{
    napi_value businessError = nullptr;

    napi_value code = nullptr;
    napi_create_uint32(env, GetCertErrValueByErrCode(errCode), &code);

    napi_value msg = nullptr;
    napi_create_string_utf8(env, errMsg, NAPI_AUTO_LENGTH, &msg);

    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, CERT_TAG_ERR_CODE.c_str(), code);

    return businessError;
}

bool CertCheckArgsCount(napi_env env, size_t argc, size_t expectedCount, bool isSync)
{
    if (isSync) {
        if (argc != expectedCount) {
            napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "invalid params count"));
            LOGE("invalid params count!");
            return false;
        }
    } else {
        if ((argc != expectedCount) && (argc != (expectedCount - ARGS_SIZE_ONE))) {
            napi_throw(env, CertGenerateBusinessError(env, HCF_INVALID_PARAMS, "invalid params count"));
            LOGE("invalid params count!");
            return false;
        }
    }
    return true;
}

napi_value CertGetResourceName(napi_env env, const char *name)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resourceName);
    return resourceName;
}

napi_value ConvertBlobToNapiValue(napi_env env, HcfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->len == 0) {
        LOGE("Invalid blob!");
        return nullptr;
    }
    uint8_t *buffer = static_cast<uint8_t *>(HcfMalloc(blob->len, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return nullptr;
    }

    if (memcpy_s(buffer, blob->len, blob->data, blob->len) != EOK) {
        LOGE("memcpy_s data to buffer failed!");
        HcfFree(buffer);
        return nullptr;
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->len, [](napi_env env, void *data, void *hint) { HcfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create uint8 array buffer failed!");
        HcfFree(buffer);
        return nullptr;
    }
    buffer = nullptr;

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->len, outBuffer, 0, &outData);
    napi_value dataBlob = nullptr;
    napi_create_object(env, &dataBlob);
    napi_set_named_property(env, dataBlob, CERT_TAG_DATA.c_str(), outData);

    return dataBlob;
}
}  // namespace CertFramework
}  // namespace OHOS
