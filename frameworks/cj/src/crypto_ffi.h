/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef CRYPTO_FFI_H
#define CRYPTO_FFI_H

#include "cj_common_ffi.h"
#include "blob.h"
#include "cipher.h"
#include "algorithm_parameter.h"

extern "C" {
    typedef struct {
        HcfBlob iv;
        HcfBlob add;
        HcfBlob authTag;
    } CParamsSpec;

    // random
    FFI_EXPORT int64_t FfiOHOSCreateRandom(int32_t* errCode);
    FFI_EXPORT const char *FfiOHOSRandomGetAlgName(int64_t id, int32_t* errCode);
    FFI_EXPORT HcfBlob FfiOHOSGenerateRandom(int64_t id, int32_t numBytes, int32_t* errCode);
    FFI_EXPORT void FfiOHOSSetSeed(int64_t id, HcfBlob *seed, int32_t* errCode);

    // md
    FFI_EXPORT int64_t FfiOHOSCreateMd(char* algName, int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSMdUpdate(int64_t id, HcfBlob *input);
    FFI_EXPORT HcfBlob FfiOHOSDigest(int64_t id, int32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSGetMdLength(int64_t id, int32_t* errCode);

    // symkeygenerator
    FFI_EXPORT int64_t FfiOHOSCreateSymKeyGenerator(char* algName, int32_t* errCode);
    FFI_EXPORT const char *FfiOHOSSymKeyGeneratorGetAlgName(int64_t id, int32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSGenerateSymKey(int64_t id, int32_t* errCode);
    FFI_EXPORT int64_t FfiOHOSConvertKey(int64_t id, HcfBlob *key, int32_t* errCode);

    // symkey
    FFI_EXPORT const char *FfiOHOSSymKeyGetAlgName(int64_t id, int32_t* errCode);
    FFI_EXPORT const char *FfiOHOSSymKeyGetFormat(int64_t id, int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSSymKeyGetEncoded(int64_t id, HcfBlob *returnBlob);
    FFI_EXPORT void FfiOHOSClearMem(int64_t id);
    FFI_EXPORT void* FfiOHOSSymKeyGetHcfKey(int64_t id);

    // cipher
    FFI_EXPORT int64_t FfiOHOSCreateCipher(char* transformation, int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSCipherInitByIv(int64_t id, int32_t opMode, void* key, HcfBlob blob1);
    FFI_EXPORT int32_t FfiOHOSCipherInitByGcm(int64_t id, int32_t opMode, void* key, CParamsSpec spec);
    FFI_EXPORT int32_t FfiOHOSCipherInitByCcm(int64_t id, int32_t opMode, void* key, CParamsSpec spec);
    FFI_EXPORT int32_t FfiOHOSCipherInitWithOutParams(int64_t id, int32_t opMode, void* key);
    FFI_EXPORT int32_t FfiOHOSCipherUpdate(int64_t id, HcfBlob *input, HcfBlob *output);
    FFI_EXPORT int32_t FfiOHOSCipherDoFinal(int64_t id, HcfBlob *input, HcfBlob *output);
    FFI_EXPORT int32_t FfiOHOSSetCipherSpec(int64_t id, int32_t item, HcfBlob pSource);
    FFI_EXPORT int32_t FfiOHOSGetCipherSpecString(int64_t id, int32_t item, char **returnString);
    FFI_EXPORT int32_t FfiOHOSGetCipherSpecUint8Array(int64_t id, int32_t item, HcfBlob *returnUint8Array);
    FFI_EXPORT const char *FfiOHOSCipherGetAlgName(int64_t id, int32_t* errCode);

    // mac
    FFI_EXPORT int64_t FFiOHOSCryptoMacConstructor(char* algName, int32_t* errCode);
    FFI_EXPORT int32_t FfiOHOSCryptoMacInit(int64_t id, int64_t symKeyId);
    FFI_EXPORT int32_t FfiOHOSCryptoMacUpdate(int64_t id, HcfBlob *input);
    FFI_EXPORT HcfBlob FfiOHOSCryptoMacDoFinal(int64_t id, int32_t* errCode);
    FFI_EXPORT uint32_t FfiOHOSGCryptoGetMacLength(int64_t id);

    // sign
    FFI_EXPORT int64_t FFiOHOSCryptoSignConstructor(char* algName, int32_t* errCode);
}

#endif
