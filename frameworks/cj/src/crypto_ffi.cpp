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
#include "crypto_ffi.h"
#include "random_impl.h"
#include "mac_impl.h"
#include "md_impl.h"
#include "log.h"
#include "sign_impl.h"
#include "symkey_generator_impl.h"
#include "symkey_impl.h"
#include "cipher_impl.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "securec.h"

#define MAX_MEMORY_SIZE (5 * 1024 * 1024)

using namespace OHOS::FFI;

namespace OHOS {
    namespace CryptoFramework {
        extern "C" {
            //-------------------random
            int64_t FfiOHOSCreateRandom(int32_t* errCode)
            {
                LOGD("[Random] CreateRandom start");
                HcfRand *randObj = nullptr;
                HcfResult res = HcfRandCreate(&randObj);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create c randObj failed.");
                    return 0;
                }
                auto native = FFIData::Create<RandomImpl>(randObj);
                LOGD("[Randome] CreateRandom success");
                return native->GetID();
            }

            const char *FfiOHOSRandomGetAlgName(int64_t id, int32_t* errCode)
            {
                LOGD("[Random] GetAlgName start");
                auto instance = FFIData::GetData<RandomImpl>(id);
                if (!instance) {
                    LOGE("[Random] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetAlgName(errCode);
                LOGD("[Randome] GetAlgName success");
                return res;
            }

            HcfBlob FfiOHOSGenerateRandom(int64_t id, int32_t numBytes, int32_t* errCode)
            {
                LOGD("[Random] GenerateRandom start");
                HcfBlob randBlob;
                auto instance = FFIData::GetData<RandomImpl>(id);
                if (!instance) {
                    LOGE("[Random] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return randBlob;
                }
                randBlob = instance->GenerateRandom(numBytes, errCode);
                LOGD("[Randome] GenerateRandom success");
                return randBlob;
            }

            void FfiOHOSSetSeed(int64_t id, HcfBlob *seed, int32_t* errCode)
            {
                LOGD("[Random] SetSeed start");
                auto instance = FFIData::GetData<RandomImpl>(id);
                if (!instance) {
                    LOGE("[Random] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return;
                }
                instance->SetSeed(seed, errCode);
                LOGD("[Randome] SetSeed success");
            }

            //--------------------- md
            int64_t FfiOHOSCreateMd(char* algName, int32_t* errCode)
            {
                LOGD("[Md] CreateMd start");
                HcfMd *mdObj = nullptr;
                HcfResult res = HcfMdCreate(algName, &mdObj);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create c mdObj failed.");
                    return 0;
                }
                auto native = FFIData::Create<MdImpl>(mdObj);
                if (native == nullptr) {
                    LOGE("[Md] CreateMd failed");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[Md] CreateMd success");
                return native->GetID();
            }

            int32_t FfiOHOSMdUpdate(int64_t id, HcfBlob *input)
            {
                LOGD("[Md] FfiOHOSMdUpdate start");
                HcfResult res = HCF_ERR_MALLOC;
                auto instance = FFIData::GetData<MdImpl>(id);
                if (!instance) {
                    LOGE("[Md] instance not exist.");
                    return res;
                }
                res = instance->MdUpdate(input);
                LOGD("[Md] FfiOHOSMdUpdate success");
                return res;
            }

            HcfBlob FfiOHOSDigest(int64_t id, int32_t* errCode)
            {
                LOGD("[Md] FfiOHOSDigest start");
                auto instance = FFIData::GetData<MdImpl>(id);
                HcfBlob blob = { .data = nullptr, .len = 0};
                if (!instance) {
                    LOGE("[Md] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return blob;
                }
                HcfResult res = instance->MdDoFinal(&blob);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("doFinal failed!");
                    return blob;
                }
                LOGD("[Md] FfiOHOSDigest success");
                return blob;
            }

            uint32_t FfiOHOSGetMdLength(int64_t id, int32_t* errCode)
            {
                LOGD("[Md] FfiOHOSGetMdLength start");
                auto instance = FFIData::GetData<MdImpl>(id);
                uint32_t res = 0;
                if (!instance) {
                    LOGE("[Md] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return res;
                }
                res = instance->GetMdLength(errCode);
                LOGD("[Md] FfiOHOSGetMdLength success");
                return res;
            }

            //-------------------symkeygenerator
            int64_t FfiOHOSCreateSymKeyGenerator(char* algName, int32_t* errCode)
            {
                LOGD("[SymKeyGenerator] CreateSymKeyGenerator start");
                HcfSymKeyGenerator *generator = nullptr;
                HcfResult res = HcfSymKeyGeneratorCreate(algName, &generator);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create C generator fail.");
                    return 0;
                }
                auto native = FFIData::Create<SymKeyGeneratorImpl>(generator);
                if (native == nullptr) {
                    LOGE("[SymKeyGenerator] CreateSymKeyGenerator failed");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[SymKeyGenerator] CreateSymKeyGenerator success");
                return native->GetID();
            }

            const char* FfiOHOSSymKeyGeneratorGetAlgName(int64_t id, int32_t* errCode)
            {
                LOGD("[SymKeyGenerator] GetAlgName start");
                auto instance = FFIData::GetData<SymKeyGeneratorImpl>(id);
                if (!instance) {
                    LOGE("[SymKeyGenerator] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetAlgName(errCode);
                LOGD("[SymKeyGenerator] GetAlgName success");
                return res;
            }

            int64_t FfiOHOSGenerateSymKey(int64_t id, int32_t* errCode)
            {
                LOGD("[SymKeyGenerator] GenerateSymKey start");
                auto instance = FFIData::GetData<SymKeyGeneratorImpl>(id);
                if (!instance) {
                    LOGE("[SymKeyGenerator] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                HcfSymKey *key = nullptr;
                HcfResult res = instance->GenerateSymKey(&key);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("generate sym key failed.");
                    return 0;
                }
                auto native = FFIData::Create<SymKeyImpl>(key);
                if (native == nullptr) {
                    LOGE("[SymKeyGenerator] GenerateSymKey failed");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[SymKeyGenerator] GenerateSymKey success");
                return native->GetID();
            }

            int64_t FfiOHOSConvertKey(int64_t id, HcfBlob *key, int32_t* errCode)
            {
                LOGD("[SymKeyGenerator] ConvertKey start");
                auto instance = FFIData::GetData<SymKeyGeneratorImpl>(id);
                if (!instance) {
                    LOGE("[SymKeyGenerator] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                HcfSymKey *symkey = nullptr;
                HcfResult res = instance->ConvertKey(*key, &symkey);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("generate sym key failed.");
                    return 0;
                }
                auto native = FFIData::Create<SymKeyImpl>(symkey);
                if (native == nullptr) {
                    LOGE("[SymKeyGenerator] ConvertKey failed");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[SymKeyGenerator] ConvertKey success");
                return native->GetID();
            }

            //-------------------symkey
            const char *FfiOHOSSymKeyGetAlgName(int64_t id, int32_t* errCode)
            {
                LOGD("[SymKey] GetAlgName start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetAlgorithm(errCode);
                LOGD("[SymKey] GetAlgName success");
                return res;
            }

            const char *FfiOHOSSymKeyGetFormat(int64_t id, int32_t* errCode)
            {
                LOGD("[SymKey] GetFormat start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetFormat(errCode);
                LOGD("[SymKey] GetFormat success");
                return res;
            }

            int32_t FfiOHOSSymKeyGetEncoded(int64_t id, HcfBlob *returnBlob)
            {
                LOGD("[SymKey] GetEncoded start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfResult res = instance->GetEncoded(returnBlob);
                LOGD("[SymKey] GetEncoded success");
                return res;
            }

            void FfiOHOSClearMem(int64_t id)
            {
                LOGD("[SymKey] ClearMem start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    return;
                }
                instance->ClearMem();
                LOGD("[SymKey] ClearMem success");
            }

            void* FfiOHOSSymKeyGetHcfKey(int64_t id)
            {
                LOGD("[SymKey] GetHcfKey start");
                auto instance = FFIData::GetData<SymKeyImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    return nullptr;
                }
                HcfKey *key =  instance->GetHcfKey();
                LOGD("[SymKey] GetHcfKey success");
                return key;
            }

            // cipher
            const std::string IV_PARAMS_SPEC = "IvParamsSpec";
            const std::string GCM_PARAMS_SPEC = "GcmParamsSpec";
            const std::string CCM_PARAMS_SPEC = "CcmParamsSpec";
            const size_t GCM_AUTH_TAG_LEN = 16;
            const size_t CCM_AUTH_TAG_LEN = 12;
            static const char *GetIvParamsSpecType()
            {
                return IV_PARAMS_SPEC.c_str();
            }
            static const char *GetGcmParamsSpecType()
            {
                return GCM_PARAMS_SPEC.c_str();
            }

            static const char *GetCcmParamsSpecType()
            {
                return CCM_PARAMS_SPEC.c_str();
            }

            void *HcfMalloc(uint32_t size, char val)
            {
                if ((size == 0) || (size > MAX_MEMORY_SIZE)) {
                    LOGE("malloc size is invalid");
                    return nullptr;
                }
                void *addr = malloc(size);
                if (addr != nullptr) {
                    (void)memset_s(addr, size, val, size);
                }
                return addr;
            }

            void HcfFree(void *addr)
            {
                if (addr != nullptr) {
                    free(addr);
                }
            }

            int64_t FfiOHOSCreateCipher(char* transformation, int32_t* errCode)
            {
                LOGD("[Cipher] CreateCipher start");
                HcfCipher *cipher = nullptr;
                HcfResult res = HcfCipherCreate(transformation, &cipher);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create C cipher fail!");
                    return 0;
                }
                auto native = FFIData::Create<CipherImpl>(cipher);
                if (native == nullptr) {
                    LOGE("[Cipher] CreateCipher failed");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[Cipher] CreateCipher success");
                return native->GetID();
            }

            int32_t FfiOHOSCipherInitByIv(int64_t id, int32_t opMode, void* key, HcfBlob blob1)
            {
                LOGD("[Cipher] CipherInit start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfIvParamsSpec *ivParamsSpec = reinterpret_cast<HcfIvParamsSpec *>(
                        HcfMalloc(sizeof(HcfIvParamsSpec), 0));
                if (ivParamsSpec == nullptr) {
                    LOGE("ivParamsSpec malloc failed!");
                    return HCF_ERR_MALLOC;
                }
                ivParamsSpec->base.getType = GetIvParamsSpecType;
                ivParamsSpec->iv = blob1;
                HcfCryptoMode mode = HcfCryptoMode(opMode);
                HcfParamsSpec *paramsSpec = reinterpret_cast<HcfParamsSpec *>(ivParamsSpec);
                ivParamsSpec = nullptr;
                HcfResult res = instance->CipherInit(mode, (HcfKey*)key, paramsSpec);
                HcfFree(paramsSpec);
                paramsSpec = nullptr;
                LOGD("[Cipher] CipherInit success");
                return res;
            }

            int32_t FfiOHOSCipherInitByGcm(int64_t id, int32_t opMode, void* key, CParamsSpec spec)
            {
                LOGD("[Cipher] CipherInit start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfGcmParamsSpec *gcmParamsSpec = reinterpret_cast<HcfGcmParamsSpec *>(
                                                    HcfMalloc(sizeof(HcfGcmParamsSpec), 0));
                if (gcmParamsSpec == nullptr) {
                    LOGE("gcmParamsSpec malloc failed!");
                    return HCF_ERR_MALLOC;
                }
                gcmParamsSpec->base.getType = GetGcmParamsSpecType;
                gcmParamsSpec->iv = spec.iv;
                gcmParamsSpec->aad = spec.add;
                HcfCryptoMode mode = HcfCryptoMode(opMode);
                if (mode == DECRYPT_MODE) {
                    gcmParamsSpec->tag = spec.authTag;
                } else if (mode == ENCRYPT_MODE) {
                    HcfBlob authTag = {};
                    authTag.data = static_cast<uint8_t *>(HcfMalloc(GCM_AUTH_TAG_LEN, 0));
                    authTag.len = GCM_AUTH_TAG_LEN;
                    gcmParamsSpec->tag = authTag;
                }
                HcfParamsSpec *paramsSpec = reinterpret_cast<HcfParamsSpec *>(gcmParamsSpec);
                gcmParamsSpec = nullptr;
                HcfResult res = instance->CipherInit(mode, (HcfKey*)key, paramsSpec);
                HcfFree(paramsSpec);
                paramsSpec = nullptr;
                LOGD("[Cipher] CipherInit success");
                return res;
            }

            int32_t FfiOHOSCipherInitByCcm(int64_t id, int32_t opMode, void* key, CParamsSpec spec)
            {
                LOGD("[Cipher] CipherInit start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfCcmParamsSpec *ccmParamsSpec = reinterpret_cast<HcfCcmParamsSpec *>(
                                                    HcfMalloc(sizeof(HcfCcmParamsSpec), 0));
                if (ccmParamsSpec == nullptr) {
                    LOGE("ccmParamsSpec malloc failed!");
                    return HCF_ERR_MALLOC;
                }
                ccmParamsSpec->base.getType = GetCcmParamsSpecType;
                ccmParamsSpec->iv = spec.iv;
                ccmParamsSpec->aad = spec.add;
                HcfCryptoMode mode = HcfCryptoMode(opMode);
                if (mode == DECRYPT_MODE) {
                    ccmParamsSpec->tag = spec.authTag;
                } else if (mode == ENCRYPT_MODE) {
                    HcfBlob authTag = {};
                    authTag.data = static_cast<uint8_t *>(HcfMalloc(CCM_AUTH_TAG_LEN, 0));
                    authTag.len = CCM_AUTH_TAG_LEN;
                    ccmParamsSpec->tag = authTag;
                }
                HcfParamsSpec *paramsSpec = reinterpret_cast<HcfParamsSpec *>(ccmParamsSpec);
                ccmParamsSpec = nullptr;
                HcfResult res = instance->CipherInit(mode, (HcfKey*)key, paramsSpec);
                HcfFree(paramsSpec);
                paramsSpec = nullptr;
                LOGD("[Cipher] CipherInit success");
                return res;
            }

            int32_t FfiOHOSCipherInitWithOutParams(int64_t id, int32_t opMode, void* key)
            {
                LOGD("[Cipher] CipherInit start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfParamsSpec *paramsSpec = nullptr;
                HcfCryptoMode mode = HcfCryptoMode(opMode);
                HcfResult res = instance->CipherInit(mode, (HcfKey*)key, paramsSpec);
                LOGD("[Cipher] CipherInit success");
                return res;
            }

            int32_t FfiOHOSCipherUpdate(int64_t id, HcfBlob *input, HcfBlob *output)
            {
                LOGD("[Cipher] CipherUpdate start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfResult res = instance->CipherUpdate(input, output);
                LOGD("[Cipher] CipherUpdate success");
                return res;
            }

            int32_t FfiOHOSCipherDoFinal(int64_t id, HcfBlob *input, HcfBlob *output)
            {
                LOGD("[Cipher] CipherDoFinal start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                HcfResult res = instance->CipherDoFinal(input, output);
                LOGD("[Cipher] CipherDoFinal success %{public}d", res);
                return res;
            }

            int32_t FfiOHOSSetCipherSpec(int64_t id, int32_t item, HcfBlob pSource)
            {
                LOGD("[Cipher] SetCipherSpec start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                CipherSpecItem csi = CipherSpecItem(item);
                HcfResult res = instance->SetCipherSpec(csi, pSource);
                LOGD("[Cipher] SetCipherSpec success");
                return res;
            }

            int32_t FfiOHOSGetCipherSpecString(int64_t id, int32_t item, char **returnString)
            {
                LOGD("[Cipher] GetCipherSpecString start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                CipherSpecItem csi = CipherSpecItem(item);
                HcfResult res = instance->GetCipherSpecString(csi, returnString);
                LOGD("[Cipher] GetCipherSpecString success");
                return res;
            }

            int32_t FfiOHOSGetCipherSpecUint8Array(int64_t id, int32_t item, HcfBlob *returnUint8Array)
            {
                LOGD("[Cipher] GetCipherSpecUint8Array start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[Cipher] instance not exist.");
                    return HCF_ERR_MALLOC;
                }
                CipherSpecItem csi = CipherSpecItem(item);
                HcfResult res = instance->GetCipherSpecUint8Array(csi, returnUint8Array);
                LOGD("[Cipher] GetCipherSpecUint8Array success");
                return res;
            }

            const char *FfiOHOSCipherGetAlgName(int64_t id, int32_t* errCode)
            {
                LOGD("[Cipher] GetAlgName start");
                auto instance = FFIData::GetData<CipherImpl>(id);
                if (!instance) {
                    LOGE("[SymKey] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return nullptr;
                }
                const char* res = instance->GetAlgorithm(errCode);
                LOGD("[Cipher] GetAlgName success");
                return res;
            }

            //--------------------- mac
            int64_t FFiOHOSCryptoMacConstructor(char* algName, int32_t* errCode)
            {
                LOGD("[Mac] CreateMac start");
                HcfMac *macObj = nullptr;
                HcfResult res = HcfMacCreate(algName, &macObj);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create c macObj failed.");
                    return 0;
                }
                auto native = FFIData::Create<MacImpl>(macObj);
                if (native == nullptr) {
                    LOGE("[Mac] CreateMac failed");
                    return 0;
                }
                LOGD("[Mac] CreateMac success");
                return native->GetID();
            }

            int32_t FfiOHOSCryptoMacInit(int64_t id, int64_t symKeyId)
            {
                LOGD("[MAC] FfiOHOSCryptoMacInit start");
                auto instance = FFIData::GetData<MacImpl>(id);
                if (!instance) {
                    LOGE("[MAC] MacImpl instance not exist.");
                    return HCF_ERR_MALLOC;
                }

                auto keyInstance = FFIData::GetData<SymKeyImpl>(symKeyId);
                if (!instance) {
                    LOGE("[MAC] SymKeyImpl instance not exist.");
                    return HCF_ERR_MALLOC;
                }

                HcfResult res = instance->MacInit(keyInstance->GetSymKey());
                if (res != HCF_SUCCESS) {
                    LOGE("[MAC] MacInit error %{public}d", res);
                } else {
                    LOGD("[MAC] FfiOHOSCryptoMacInit success");
                }

                return res;
            }

            int32_t FfiOHOSCryptoMacUpdate(int64_t id, HcfBlob *input)
            {
                LOGD("[Mac] FfiOHOSCryptoMacUpdate start");
                HcfResult res = HCF_ERR_MALLOC;
                auto instance = FFIData::GetData<MacImpl>(id);
                if (!instance) {
                    LOGE("[Mac] instance not exist.");
                    return res;
                }
                res = instance->MacUpdate(input);
                LOGD("[Mac] FfiOHOSCryptoMacUpdate success");
                return res;
            }

            HcfBlob FfiOHOSCryptoMacDoFinal(int64_t id, int32_t* errCode)
            {
                LOGD("[Mac] FfiOHOSCryptoMacDoFinal start");
                auto instance = FFIData::GetData<MacImpl>(id);
                HcfBlob blob = { .data = nullptr, .len = 0};
                if (!instance) {
                    LOGE("[Mac] instance not exist.");
                    *errCode = HCF_ERR_MALLOC;
                    return blob;
                }
                HcfResult res = instance->MacDoFinal(&blob);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("doFinal failed!");
                    return blob;
                }
                LOGD("[Mac] FfiOHOSCryptoMacDoFinal success");
                return blob;
            }

            uint32_t FfiOHOSGCryptoGetMacLength(int64_t id)
            {
                LOGD("[Mac] FfiOHOSGCryptoGetMacLength start");
                auto instance = FFIData::GetData<MacImpl>(id);
                uint32_t res = 0;
                if (!instance) {
                    LOGE("[Mac] instance not exist.");
                    return res;
                }
                res = instance->GetMacLength();
                LOGD("[Mac] FfiOHOSGCryptoGetMacLength success");
                return res;
            }

            //--------------------- sign
            int64_t FFiOHOSCryptoSignConstructor(char* algName, int32_t* errCode)
            {
                LOGD("[Sign] CreateSign start");
                HcfSign *signObj = nullptr;
                HcfResult res = HcfSignCreate(algName, &signObj);
                *errCode = static_cast<int32_t>(res);
                if (res != HCF_SUCCESS) {
                    LOGE("create c signObj failed.");
                    return 0;
                }
                auto native = FFIData::Create<SignImpl>(signObj);
                if (native == nullptr) {
                    LOGE("[Sign] CreateSign failed");
                    *errCode = HCF_ERR_MALLOC;
                    return 0;
                }
                LOGD("[Sign] CreateSign success");
                return native->GetID();
            }
        }
    } // namespace CryptoFramework
} // namespace OHOS